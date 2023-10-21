import asyncio
import logging
from asyncio.streams import StreamReader, StreamWriter
from typing import Dict, List, Optional, Tuple, Union

from iso15118_l.controller.interface import (
    EVSEControllerInterface,
)
from failed_responses import  init_failed_responses_iso_v2

import secc_settings
from secc_settings import Config
from iso15118_l.transport.tcp_server import TCPServer
from iso15118_l.shared.comm_session import V2GCommunicationSession
from iso15118_l.shared.exi_codec import EXI
from iso15118_l.shared.iexi_codec import IEXICodec
from iso15118_l.shared.messages.enums import (
    AuthEnum,
    SessionStopAction,
)
from iso15118_l.shared.messages.iso15118_2.datatypes import (
    CertificateChain as CertificateChainV2,
)
from iso15118_l.shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from iso15118_l.shared.messages.iso15118_2.datatypes import (
    SAScheduleTuple,
    ServiceDetails,
    eMAID,
)
from iso15118_l.shared.messages.timeouts import Timeouts
from iso15118_l.shared.notifications import (
    StopNotification,
    TCPClientNotification,
)
from iso15118_l.shared.utils import cancel_task

logger = logging.getLogger(__name__)


class SECCCommunicationSession(V2GCommunicationSession):
    """
    Класс - хранилище переменных для сессии связи, также реализует механизм паузы
    """

    def __init__(
        self,
        transport: Tuple[StreamReader, StreamWriter],
        session_handler_queue: asyncio.Queue,
        config: Config,
        evse_controller: EVSEControllerInterface,
        evse_id: str,
    ):
        # Необходимо импортировать здесь, для избежания ошибки рекурсивного импорта
        # pylint: disable=import-outside-toplevel
        from iso15118_l.states.sap_states import SupportedAppProtocol

        V2GCommunicationSession.__init__(               #Инициализация базового класса сессии
            self, transport, SupportedAppProtocol, session_handler_queue, self
        )

        self.config = config
        # EVSE контроллер, реализующий интерфейс EVSEControllerInterface
        self.evse_controller = evse_controller
        # EVSE ID привязанный к конкретной сессии
        self.evse_id = evse_id
        # Список возможных вариантов авторизации для ServiceDiscoveryRes 
        # (ISO 15118-2) и AuthorizationSetupRes (ISO 15118-20)
        self.offered_auth_options: Optional[List[AuthEnum]] = []
        # Список дополнительных услуг ServiceDiscoveryRes
        self.offered_services: List[ServiceDetails] = []
        # Варианты авторизации (PaymentOption в ISO 15118-2) для сообщения
        # PaymentServiceSelectionReq
        self.selected_auth_option: Optional[AuthEnum] = None
        # Копия запроса PaymentDetailsRes хранится для сообщения 
        # AuthorizationReq (только для  Plug & Charge)
        self.gen_challenge: Optional[bytes] = None
        # Для ISO 15118-2,  EVCCID MAC адрес в байтах.
        # Для ISO 15118-20, the EVCCID VIN номер, в виде строки.
        self.evcc_id: Union[bytes, str, None] = None
        # Список предлагаемых SECC графиков зарядки в ChargeParameterDiscoveryRes (ISO 15118-2)
        self.offered_schedules: List[SAScheduleTuple] = []
        # Получил ли SECC сообщение PowerDeliveryReq с
        # ChargeProgress = 'Start'
        self.charge_progress_started: bool = False
        # Контрактный сертификат или сертификат sub-CA, которые EVCC прислал в
        # PaymentDetailsReq. Нужно сохранить, для проверки подписи в AuthorizationReq
        self.contract_cert_chain: Optional[CertificateChainV2] = None
        # eMAID используемый в PnC режиме
        self.emaid: Optional[eMAID] = None
        # Генерация негативных ответов заранее, для оптимизация скорости в V2G цикле связи
        self.failed_responses_isov2     = init_failed_responses_iso_v2()
        # Значение MeterInfo, которе EVCC отправило в ChargingStatusRes или
        # CurrentDemandRes.  SECC должен послать копию в сообщении MeteringReceiptReq
        self.sent_meter_info: Optional[MeterInfoV2] = None
        self.ev_session_context = secc_settings.save_ev_session_context
        self.is_tls = self._is_tls(transport)

        # # Initialise the failed possible responses per request message for a
        # # faster lookup later when needed
        # self.failed_responses_din_spec  = init_failed_responses_din_spec_70121()

    def save_session_info(self):
        secc_settings.save_ev_session_context = self.ev_session_context

    def _is_tls(self, transport: Tuple[StreamReader, StreamWriter]) -> bool:
        """
        Позволяет узнать используется ли TLS в конкретном транспорте
        """
        _, writer = transport
        return True if writer.get_extra_info("sslcontext") else False

    async def stop(self, reason: str):
        await self.evse_controller.stop_charger()
        await super().stop(reason)


class CommunicationSessionHandler:
    """
    Класс отвечающий за управление всей сессией связи.
    """

    # pylint: disable=too-many-instance-attributes
    def __init__(
        self, config: Config, codec: IEXICodec, evse_controller: EVSEControllerInterface
    ):

        self.list_of_tasks      = []
        self.tcp_server         = None
        self.tcp_server_handler = None
        self.config             = config
        self.evse_controller    = evse_controller

        # Установка выбранного варианта реализации EXI-кодека
        EXI().set_exi_codec(codec)

        # Очередь событий TCP и событий сессии (пауза, завершение)
        self._rcv_queue = asyncio.Queue()

        # Список активных сессий:
        # ключ - IPv6 адрес EV.
        # данные - кортеж из хранилища сессии и связанной с ней задачи
        self.comm_sessions: Dict[str, (SECCCommunicationSession, asyncio.Task)] = {}

    async def start_session_handler(self, iface: str):
        """
        Запуск менеджера сессий
        """
        logger.info("Communication session handler started")

        self.tcp_server = TCPServer(self._rcv_queue, iface, self.config)
        self.start_tcp_server(False)

        await self.get_from_rcv_queue(self._rcv_queue)


    async def get_from_rcv_queue(self, queue: asyncio.Queue):
        """
        Ожидает входящего сообщения TCP или события сеанса связи, 
        (пауза или завершение сеанса)
        """
        while True:
            try:
                notification = queue.get_nowait()       # Ожидание пакета
            except asyncio.QueueEmpty:
                notification = await queue.get()

            try:
                if isinstance(notification, TCPClientNotification):     # Подключился новый клиент
                    logger.info(
                        "TCP client connected, client address is "
                        f"{notification.ip_address}."
                    )

                    try: 
                        comm_session, task = self.comm_sessions[notification.ip_address]    
                        comm_session.resume()    # Если этот клиент сейчас на паузе, пробуем продолжить сессию                                
                    except (KeyError, ConnectionResetError) as e:
                        if isinstance(e, ConnectionResetError): # Если произошла ошибка возобновления сессии, перезапустим
                            logger.info("Can't resume session. End and start new one.")
                            await self.end_current_session(
                                notification.ip_address,
                                SessionStopAction.TERMINATE,
                            )
                        comm_session = SECCCommunicationSession(    # Создаем новую сессию
                            notification.transport,
                            self._rcv_queue,
                            self.config,
                            self.evse_controller,
                            self.config.evse_id,
                        )

                    if( len(self.comm_sessions) == 0):  # Допускается только одна сессия
                        task = asyncio.create_task(
                            comm_session.start(
                                Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT   # Запускаем отдельный поток для сессии
                            )
                        )
                        self.comm_sessions[notification.ip_address] = (comm_session, task)  #  Добавляем в список сессий

                elif isinstance(notification, StopNotification):
                    try:
                        await self.end_current_session( # Останавливаем выбранную сессию
                            notification.peer_ip_address,
                            notification.stop_action,
                        )
                    except KeyError:
                        pass
                else:                           # Неизвестный тип события
                    logger.warning(
                        f"Communication session handler "
                        f"received an unknown message or "
                        f"notification: {notification}"
                    )
            finally:
                queue.task_done()


    async def end_current_session(self, peer_ip_address: str, session_stop_action: SessionStopAction):
        """Завершаем сессию, в том числе закрываем TCP сервер"""
        try:
            await cancel_task(self.comm_sessions[peer_ip_address][1])
            await cancel_task(self.tcp_server_handler)
        except Exception as e:
            logger.warning(f"Unexpected error ending current session: {e}")
        finally:
            if session_stop_action == SessionStopAction.TERMINATE:  # Если команда на полное закрытие, то удаляем контекст
                del self.comm_sessions[peer_ip_address]
            else:
                logger.debug(
                    f"Preserved session state: {self.comm_sessions[peer_ip_address][0].ev_session_context}"
                )

        self.tcp_server_handler = None

        self.start_tcp_server(False)    # Авто-восстановление TCP сервера


    def start_tcp_server(self, with_tls: bool):

        if self.tcp_server_handler is not None: # Если сервер уже создан, то ничего не делать
            return
        
        self.tcp_server_handler = asyncio.create_task(
            self.tcp_server.server_factory(False)           # Создание сервера
        )
