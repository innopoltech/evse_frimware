
import asyncio
import logging
from abc import ABC, abstractmethod
from asyncio.streams import StreamReader, StreamWriter
from typing import List, Optional, Tuple, Type, Union

from pydantic import ValidationError
from typing_extensions import TYPE_CHECKING

from ..shared.exceptions import (
    EXIDecodingError,
    FaultyStateImplementationError,
    InvalidV2GTPMessageError,
    MessageProcessingError,
    V2GMessageValidationError,
)
from ..shared.exi_codec import EXI
from ..shared.messages.app_protocol import (
    SupportedAppProtocolReq,
)
from ..shared.messages.datatypes import SelectedService as SelectedServiceV2_DIN
# from ..shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from ..shared.messages.enums import (
    DINPayloadTypes,
    ISOV2PayloadTypes,
    Namespace,
    Protocol,
    SessionStopAction,
)
from ..shared.messages.iso15118_2.datatypes import EnergyTransferModeEnum
from ..shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2

from ..shared.messages.v2gtp import V2GTPMessage
from ..shared.notifications import StopNotification
from ..shared.states import Pause, State, Terminate
from ..shared.utils import wait_for_tasks

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    # Для случая когда 2 файла ссылаются друг на друга, необходимо
    # избежать ошибки циклического импорта. Для этого используется TYPE_CHECKING
    # - эта переменная во время выполнения =False, а во время проверки типов =True.
    # Что позволяет использовать кросс типы в разных файла.
    # https://stackoverflow.com/questions/61545580/how-does-mypy-use-typing-type-checking-to-resolve-the-circular-import-annotation
    # https://docs.python.org/3/library/typing.html#typing.TYPE_CHECKING
    from comm_session_handler import SECCCommunicationSession

class SessionStateMachine(ABC):
    """
    Каждый новый сеанс связи TCP инициализирует новую машину состояний,
    для поддержания общения по ISO 15118.
    Это самый базовый класс сессии.
    """

    def __init__(
        self,
        start_state: Type[State],
        comm_session: "SECCCommunicationSession",
    ):
        """
        Начальное состояние для SECC -  ожидание сообщения
        SupportedAppProtocolReq от EVCC.
        """
        self.start_state    = start_state
        self.comm_session   = comm_session
        self.current_state  = start_state(comm_session)
    def get_exi_ns(
        self,
        payload_type: Union[DINPayloadTypes, ISOV2PayloadTypes],
    ) -> str:
        """
        Возвращает правильное пространство имен для выбранного протокола
        """
        if self.comm_session.protocol == Protocol.UNKNOWN:
            return Namespace.SAP
        elif self.comm_session.protocol == Protocol.ISO_15118_2:
            return Namespace.ISO_V2_MSG_DEF
        # elif self.comm_session.protocol == Protocol.DIN_SPEC_70121:
        #     return Namespace.DIN_MSG_DEF
        else:
            raise Exception("Only ISO_15118_2 protocol supported!")
            # return Namespace.ISO_V20_COMMON_MSG

    async def process_message(self, message: bytes):
        """
        Для каждого входящего сообщения, машина состояний должна выполнить следующую 
        последовательность действий:

        1. Попытаться создать V2GTP (V2G Transfer Protocol) сообщение из байтового массива.
        2. Попытка EXI декодирования сообщения. 
        3. Передача раскодированного сообщения в функции process_message(). 
           Эта функция уникальна для каждого состояния FSM. 
           Состояния FSM представлены классами.
           process_message() генерирует ответ на сообщение и определяет следующее состояние FSM.

        """
        # Шаг 1
        try:
            v2gtp_msg = V2GTPMessage.from_bytes(self.comm_session.protocol, message)
        except InvalidV2GTPMessageError as exc:
            logger.exception("Incoming TCPPacket is not a valid V2GTPMessage")
            raise exc

        # Шаг 2
        decoded_message: Union[
            SupportedAppProtocolReq,
            V2GMessageV2,
            None,
            # V2GMessageDINSPEC,
        ] = None
        try:
            decoded_message = EXI().from_exi(
                v2gtp_msg.payload, self.get_exi_ns(v2gtp_msg.payload_type)
            )
        except V2GMessageValidationError as exc:
            self.comm_session.current_state.stop_state_machine(
                exc.reason,
                None,
                exc.response_code,
                exc.message,
                self.get_exi_ns(v2gtp_msg.payload_type),
            )
            return
        except EXIDecodingError as exc:
            logger.exception(f"{exc}")
            raise exc

        # Не должно исполняться при штатной работе
        if not decoded_message:
            logger.error(
                "Unusual error situation: decoded_message is None"
                "although no EXIDecodingError was raised"
            )
            return

        # Шаг 3
        try:
            logger.info(f"{str(decoded_message)} received")
            await self.current_state.process_message(decoded_message, v2gtp_msg.payload)
        except MessageProcessingError as exc:
            logger.exception(
                f"{exc.__class__.__name__} while processing " f"{exc.message_name}"
            )
            raise exc
        except FaultyStateImplementationError as exc:
            logger.exception(f"{exc.__class__.__name__}: {exc}")
            raise exc
        except ValidationError as exc:
            logger.exception(f"{exc.__class__.__name__}: {exc}")
            raise exc
        except AttributeError as exc:
            logger.exception(f"{exc}")
            raise exc

        if (
            self.current_state.next_v2gtp_msg is None
            and not self.current_state.next_state in [Terminate, Pause]
        ):
            raise FaultyStateImplementationError(
                "Field 'next_v2gtp_msg' is "
                "None but must be set because "
                "next state is not Terminate"
            )

    def go_to_next_state(self):
        """
        Переход в следующее состояние будет осуществлен только
        при корректной обработке текущего состояния
        """
        if self.current_state.next_state:
            self.current_state.next_state(self.comm_session)

    def resume(self):
        logger.debug("Trying to resume communication session")
        self.current_state = self.start_state(self.comm_session)


class V2GCommunicationSession(SessionStateMachine):
    """
    Класс машины состояний. Тут происходит вся обработка приема сообщений.
    """

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        transport: Tuple[StreamReader, StreamWriter],
        start_state: Type["State"],
        session_handler_queue: asyncio.Queue,
        comm_session: "SECCCommunicationSession",
    ):
        self.protocol: Protocol = Protocol.UNKNOWN
        self.reader, self.writer = transport
        # Общая очередь для таймаута, пауз и завершения сессии
        self.session_handler_queue = session_handler_queue
        self.peer_name = self.writer.get_extra_info("peername")
        self.session_id: str = ""
        # Взаимно согласованный протокол общения
        self.chosen_protocol: str = ""
        # Дополнительные сервисы выбранные EVCC (ISO 15118-2)
        self.selected_services: List[SelectedServiceV2_DIN] = []
        # Режим зарядки EVCC(ISO 15118-2)
        self.selected_energy_mode: Optional[EnergyTransferModeEnum] = None
        # Режим зарядки связан с переменным током
        self.selected_charging_type_is_ac: bool = True
        # SAScheduleTuple который выбрал EVCC (по ID)
        self.selected_schedule: Optional[int] = None
        # Информация о завершении сеанса
        self.stop_reason: Optional[StopNotification] = None
        self.last_message_sent: Optional[V2GTPMessage] = None
        self._started: bool = True

        logger.info("Starting a new communication session")
        SessionStateMachine.__init__(self, start_state, comm_session)

    async def start(self, timeout: float):
        """
        Запускает rcv_loop(), ожидающий сообщение в течении таймаута.
        """
        tasks = [self.rcv_loop(timeout)]

        try:
            self._started = True
            await wait_for_tasks(tasks)
        finally:
            self._started = False

    @abstractmethod
    def save_session_info(self):
        raise NotImplementedError

    async def stop(self, reason: str):
        """
        Закрывает TCP соединение и  data link
        """
        # if self.current_state.next_state == Pause:
        #     self.save_session_info()
        #     terminate_or_pause = SessionStopAction.PAUSE      # Пауза не поддерживается
        # else:
        terminate_or_pause = SessionStopAction.TERMINATE

        logger.info(
            f"The data link will {terminate_or_pause} in 2 seconds and "
            "the TCP connection will close in 5 seconds. "
        )
        logger.info(f"Reason: {reason}")

        await asyncio.sleep(2)
        if hasattr(self.comm_session, "evse_controller"):
            await self.comm_session.evse_controller.update_data_link(terminate_or_pause)
        logger.info(f"{terminate_or_pause}d the data link")
        await asyncio.sleep(3)
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except ConnectionResetError as exc:
            logger.info(str(exc))
        logger.info("TCP connection closed to peer with address " f"{self.peer_name}")

    async def send(self, message: V2GTPMessage):
        """
        Отправляет V2GTPMessage через TCP сокет и сохраняет последнее переданное сообщение
        """
        logger.info(f"Sending {str(self.current_state.message)}")
        self.writer.write(message.to_bytes())
        await self.writer.drain()
        self.last_message_sent = message

    async def rcv_loop(self, timeout: float):
        """
        Постоянный цикл обработки входящих TCP сообщений.
        """
        while True:
            try:
                # Максимальный размер сообщения (TCertificate Installation Response) - около 5-6 кбайт
                message = await asyncio.wait_for(self.reader.read(7000), timeout)

                if message == b"" and self.reader.at_eof():     # Если не было ничего получено
                    stop_reason: str = "TCP peer closed connection"
                    await self.stop(reason=stop_reason)
                    self.session_handler_queue.put_nowait(
                        StopNotification(
                            False,
                            stop_reason,
                            self.peer_name,
                        )
                    )
                    return
            except (asyncio.TimeoutError, ConnectionResetError) as exc:
                if type(exc) == asyncio.TimeoutError:
                    if self.last_message_sent:
                        error_msg = (
                            f"{exc.__class__.__name__} occurred. Waited "
                            f"for {timeout} s after sending last message: "
                            f"{str(self.last_message_sent)}"
                        )
                    else:
                        error_msg = (
                            f"{exc.__class__.__name__} occurred. Waited "
                            f"for {timeout} s. No V2GTP message was "
                            "previously sent. This is probably a timeout "
                            f"while waiting for SupportedAppProtocolReq"
                        )
                else:
                    error_msg = f"{exc.__class__.__name__} occurred. {str(exc)}"

                self.stop_reason = StopNotification(False, error_msg, self.peer_name)

                await self.stop(reason=error_msg)
                self.session_handler_queue.put_nowait(self.stop_reason)
                return

            try:
                # Обработка сообщения
                await self.process_message(message)
                if hasattr(self.comm_session, "evse_controller"):
                    await self.comm_session.evse_controller.set_present_protocol_state(
                        str(self.current_state)
                    )
                if self.current_state.next_v2gtp_msg:
                        # next_v2gtp_msg не будет установлен, только если нужна пауза или завершение сессии
                    await self.send(self.current_state.next_v2gtp_msg)

                if self.current_state.next_state in (Terminate, Pause):
                    await self.stop(reason=self.comm_session.stop_reason.reason)
                    self.comm_session.session_handler_queue.put_nowait(
                        self.comm_session.stop_reason
                    )
                    return

                timeout = self.current_state.next_msg_timeout
                self.go_to_next_state()
            except (
                MessageProcessingError,
                FaultyStateImplementationError,
                EXIDecodingError,
                InvalidV2GTPMessageError,
            ) as exc:
                message_name = ""
                additional_info = ""
                if isinstance(exc, MessageProcessingError):
                    message_name = exc.message_name
                if isinstance(exc, FaultyStateImplementationError):
                    additional_info = f": {exc}"
                if isinstance(exc, EXIDecodingError):
                    additional_info = f": {exc}"
                if isinstance(exc, InvalidV2GTPMessageError):
                    additional_info = f": {exc}"

                stop_reason: str = (
                    f"{exc.__class__.__name__} occurred while processing message "
                    f"{message_name} in state {str(self.current_state)}"
                    f":{additional_info}"
                )

                self.stop_reason = StopNotification(
                    False,
                    stop_reason,
                    self.peer_name,
                )

                await self.stop(stop_reason)
                self.session_handler_queue.put_nowait(self.stop_reason)
                return
            except (AttributeError, ValueError) as exc:
                stop_reason: str = (
                    f"{exc.__class__.__name__} occurred while processing message in "
                    f"state {str(self.current_state)}: {exc}"
                )
                self.stop_reason = StopNotification(
                    False,
                    stop_reason,
                    self.peer_name,
                )

                await self.stop(stop_reason)
                self.session_handler_queue.put_nowait(self.stop_reason)
                return