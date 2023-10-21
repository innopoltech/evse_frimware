import base64
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Type, Union

from pydantic import ValidationError

from ..shared.exceptions import (
    EXIEncodingError,
    InvalidPayloadTypeError,
    InvalidProtocolError,
)
from ..shared.exi_codec import EXI
from ..shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
# from ..shared.messages.din_spec.body import Body as BodyDINSPEC
# from ..shared.messages.din_spec.body import BodyBase as BodyBaseDINSPEC
# from ..shared.messages.din_spec.datatypes import FaultCode as FaultCodeDINSPEC
# from ..shared.messages.din_spec.datatypes import (
#     Notification as NotificationDINSPEC,
# )
# from ..shared.messages.din_spec.header import (
#     MessageHeader as MessageHeaderDINSPEC,
# )
# from ..shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from ..shared.messages.enums import (
    # DINPayloadTypes,
    ISOV2PayloadTypes,
    Namespace,
)
from ..shared.messages.iso15118_2.body import Body, BodyBase
from ..shared.messages.iso15118_2.datatypes import FaultCode, Notification
from ..shared.messages.iso15118_2.header import MessageHeader as MessageHeaderV2
from ..shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2

from ..shared.messages.v2gtp import V2GTPMessage
from ..shared.messages.xmldsig import Signature

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    # Для случая когда 2 файла ссылаются друг на друга, необходимо
    # избежать ошибки циклического импорта. Для этого используется TYPE_CHECKING
    # - эта переменная во время выполнения =False, а во время проверки типов =True.
    # Что позволяет использовать кросс типы в разных файла.
    # https://stackoverflow.com/questions/61545580/how-does-mypy-use-typing-type-checking-to-resolve-the-circular-import-annotation
    # https://docs.python.org/3/library/typing.html#typing.TYPE_CHECKING
    from comm_session_handler import SECCCommunicationSession


class Base64:
    def __init__(self, message: str, message_name: str, namespace: Namespace):
        """
        Вспомогательный класс для сообщения CertificateInstallationRes.
        self.message = нагрузка закодированная в base64
        self.message_type = тип сообщения (строка)
        self.namespace = пространство имен
        """
        self.message = message
        self.message_name = message_name
        self.namespace = namespace

    def __str__(self):
        return self.message_name


class State(ABC):
    """
    Базовый класс состояния для FSM
    
    В каждом состоянии SECC должен обработать входящий запрос EVCC
    """
    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        comm_session: "SECCCommunicationSession",
        timeout: Union[float, int] = 0,
    ):
        """
        Каждое состояние, наследуемое от State, должно реализовать __init__ 
        и вызывать super().__init__() с соответствующим состоянию таймаутом.
        """
        self.comm_session: "SECCCommunicationSession" = comm_session
        self.comm_session.current_state = self
        # Таймаут ожидания входящего сообщения
        self.timeout: Union[float, int] = 0
        # Следующее состояние в которое должен быть совершен переход
        self.next_state: Optional[Type["State"]] = None
        # Опционально: подпись заголовка
        self.next_msg_signature: Optional[Signature] = None
        # Тип следующего сообщения
        self.message: Union[

            SupportedAppProtocolRes,
            V2GMessageV2,
            Base64,
            None,
            # V2GMessageDINSPEC,
        ] = None
        # Каждое сообщение  V2GMessage кодируется в EXI
        # и помещается в нагрузку сообщения V2GTP
        self.next_v2gtp_msg: Optional[V2GTPMessage] = None
        # Таймаут ожидания следующего сообщения, после отправки текущего
        self.next_msg_timeout: Union[float, int] = 0

        logger.info(f"Entered state {str(self)}")

        if timeout > 0:
            self.timeout = timeout
            logger.debug(f"Waiting for up to {timeout} s")

    @abstractmethod
    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        """
        Каждое состояние должно реализовывать эту функцию.

        Каждое состояние в первую очередь должно проверить сообщение в check_msg()
        Если произошла ошибка обработки сообщения, необходимо вызвать stop_state_machine()
        """
        raise NotImplementedError

    def create_next_message(
        self,
        next_state: Optional[Type["State"]],
        next_msg: Union[
            SupportedAppProtocolRes,
            BodyBase,
            Base64,
            # BodyBaseDINSPEC,
        ],
        next_msg_timeout: Union[float, int],
        namespace: Namespace,
        # next_msg_payload_type: Union[
        #     DINPayloadTypes, ISOV2PayloadTypes
        # ] = ISOV2PayloadTypes.EXI_ENCODED,
        next_msg_payload_type: ISOV2PayloadTypes = ISOV2PayloadTypes.EXI_ENCODED,
        signature: Signature = None,
    ):
        """
        Вызывается если после обработки сообщения необходимо отправить ответ.
        Создает сообщение V2GTP и отправляет его.

        Шаги:
        1. Установить следующее состояние и новый таймаут ожидания.
        2. Создать  V2GMessage сообщение.
        3. Закодировать в EXI
        4. Создать V2GTP сообщение с нагрузкой в виде EXI данных
        """
        # Шаг 1
        self.next_state         = next_state
        self.next_msg_timeout   = next_msg_timeout
        exi_payload: bytes      = bytes(0)

        # Шаг 2
        if not next_msg:
            logger.error("Parameter 'message' of create_next_message() is " "None")
            return
        to_be_exi_encoded: Union[
            SupportedAppProtocolRes,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ] = None
        if isinstance(next_msg, BodyBase):
            note: Union[Notification, None] = None
            if (                                    # Если это сообщение о закрытии сессии
                self.comm_session.stop_reason
                and not self.comm_session.stop_reason.successful
            ):
                # Не должно быть длиннее 64 символов
                if len(self.comm_session.stop_reason.reason) > 64:
                    fault_msg = self.comm_session.stop_reason.reason[:62] + ".."
                else:
                    fault_msg = self.comm_session.stop_reason.reason
                note = Notification(
                    fault_code=FaultCode.PARSING_ERROR, fault_msg=fault_msg
                )
            
            header = MessageHeaderV2(
                session_id=self.comm_session.session_id,
                signature=signature,
                notification=note,
            )
            body = Body.model_validate({str(next_msg): next_msg.model_dump()})
            try:
                to_be_exi_encoded = V2GMessageV2(header=header, body=body)
            except ValidationError as exc:
                logger.exception(exc)
                raise exc
            self.message = to_be_exi_encoded
        elif isinstance(next_msg, Base64):
            self.message = next_msg
            exi_payload = base64.b64decode(next_msg.message)
            if exi_payload:
                logger.info(
                    f"Already EXI encoded. Content: "
                    f"{EXI().get_exi_codec().decode(exi_payload,next_msg.namespace)}"
                )
        # elif isinstance(next_msg, BodyBaseDINSPEC):
        #     note: Union[NotificationDINSPEC, None] = None
        #     if (
        #         self.comm_session.stop_reason
        #         and not self.comm_session.stop_reason.successful
        #     ):
        #         # The fault message must not be bigger than 64 characters according to
        #         # the XSD data type description
        #         if len(self.comm_session.stop_reason.reason) > 64:
        #             fault_msg = self.comm_session.stop_reason.reason[:62] + ".."
        #         else:
        #             fault_msg = self.comm_session.stop_reason.reason
        #         note = NotificationDINSPEC(
        #             fault_code=FaultCodeDINSPEC.PARSING_ERROR, fault_msg=fault_msg
        #         )
        #     header = MessageHeaderDINSPEC(
        #         session_id=self.comm_session.session_id,
        #         signature=signature,
        #         notification=note,
        #     )
        #     body = BodyDINSPEC.parse_obj({str(next_msg): next_msg.dict()})
        #     try:
        #         to_be_exi_encoded = V2GMessageDINSPEC(header=header, body=body)
        #     except ValidationError as exc:
        #         logger.exception(exc)
        #         raise exc
        #     self.message = to_be_exi_encoded
        else:
            to_be_exi_encoded = next_msg
            self.message = to_be_exi_encoded

        # Если to_be_exi_encoded = None то возможно сообщение уже было закодировано ранее 
        # (например CertificateInstallationRes).
        if to_be_exi_encoded and next_msg_payload_type:
            # Шаг 3
            try:
                exi_payload = EXI().to_exi(to_be_exi_encoded, namespace)
            except EXIEncodingError as exc:
                logger.error(f"{exc}")
                self.next_state = Terminate
                raise

        # Шаг 4
        try:
            self.next_v2gtp_msg = V2GTPMessage(
                self.comm_session.protocol, next_msg_payload_type, exi_payload
            )
        except (InvalidProtocolError, InvalidPayloadTypeError) as exc:
            logger.exception(
                f"{exc.__class__.__name__} occurred while "
                f"creating a V2GTPMessage. {exc}"
            )

    def __repr__(self):
        """
        Представление класса в виде строки
        """
        return self.__str__()

    def __str__(self):
        """
        Название состояния
        """
        return self.__class__.__name__


class Terminate(State):
    """ Класс заглушка, для остановки сессии"""
    def __init__(
        self,
        comm_session: "SECCCommunicationSession"
    ):
        super().__init__(comm_session)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            # V2GMessageDINSPEC,
            Base64,
        ],
        message_exi: bytes = None,
    ):
        pass


class Pause(State):
    """ Класс заглушка, для установки паузы"""
    def __init__(
        self,
        comm_session: "SECCCommunicationSession"
    ):
        super().__init__(comm_session)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            Base64,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        pass
