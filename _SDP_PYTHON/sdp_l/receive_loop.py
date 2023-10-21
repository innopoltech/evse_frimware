
import asyncio
import logging
import socket

from .udp_server import UDPServer
from .v2gtp import V2GTPMessage

from sdp_l.exception_and_enums import (
    InvalidSDPRequestError,
    InvalidV2GTPMessageError,
    ISOV2PayloadTypes,
    Protocol,
)

from .sdp import SDPRequest, create_sdp_response


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("receive_loop")                                    # Настройка логера


class ReceiveLoop():                                        # Обработка сообщений UDP сервера
    def __init__(self, network_interface, secc_addr, secc_port) -> None:
        self.iface = network_interface
        self.port_no_tls        = secc_port
        self.is_tls_enabled     = 0
        self.ipv6_address_host  = secc_addr
        
    async def run(self):    
        """
        Запуск UDP сервера в цикле событий asyncio. Все принятые сообщения приходят в очередь rcv_queue 
        и обрабатываются в process_incoming_udp_packet().
        """
        self.rcv_queue = asyncio.Queue()                         # Общая очередь приема сообщений
        self.udp_server = UDPServer(self.rcv_queue, self.iface)

        await self.udp_server.start()                                  # Запускаем udp сервер

        logger.info("Communication session handler started")

        try:
            await self.process_incoming_udp_packet()
        except Exception as e:
            pass

        self.udp_server.close()         # Останавливаем сервер


    async def process_incoming_udp_packet(self):
        """
        Ожидаем получение SDP запроса от UDP клиента.
        """
        while(True):

            if(self.udp_server.started == False):       # В случае ошибок восстанавливаем сокет 
                self.udp_server.start()

            try:
                message = self.rcv_queue.get_nowait()   # Ожидание пакета
            except asyncio.QueueEmpty:
                message = await self.rcv_queue.get()
        
            try:
                v2gtp_msg = V2GTPMessage.from_bytes(Protocol.UNKNOWN, message[0]) # Попытка извлечь данные V2G
            except InvalidV2GTPMessageError as exc:
                logger.exception(exc)
                continue

            if v2gtp_msg.payload_type == ISOV2PayloadTypes.SDP_REQUEST: # Если это запрос
                try:
                    sdp_request = SDPRequest.from_payload(v2gtp_msg.payload)     # Попытка извлечь данные SDP
                    logger.info(f"SDPRequest received: {sdp_request}")

                    port = self.port_no_tls

                                        # Конвертирование IPv6 адреса из строкового представления в двоичный формат
                    ipv6_bytes = socket.inet_pton(socket.AF_INET6, self.ipv6_address_host )
                                                                                        # Создание SDP ответа
                    sdp_response = create_sdp_response(sdp_request, ipv6_bytes, port, self.is_tls_enabled) 
                except InvalidSDPRequestError as exc:
                    logger.exception(
                        f"Invalid SDPRequest! \n"
                        f"{exc.__class__.__name__}, received bytes: "
                        f"{v2gtp_msg.payload.hex()}"
                    )
                    continue
            else:                                                   # Не корректный запрос или битый пакет
                logger.error(
                    f"Incoming datagram of {len(message[0])} "
                    f"bytes is no valid SDP request message"
                )
                continue

            v2gtp_msg = V2GTPMessage(                       # Создание V2G пакета для SDP ответа
                Protocol.ISO_15118_2,
                ISOV2PayloadTypes.SDP_RESPONSE,
                sdp_response.to_payload(),
            )
            logger.info(f"Sending SDPResponse: {sdp_response}")

            self.udp_server.send(v2gtp_msg, message[1])     # Отправка ответа