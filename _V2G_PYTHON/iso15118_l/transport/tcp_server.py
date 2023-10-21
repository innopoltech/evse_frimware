import asyncio
import logging
import socket
from typing import Tuple
from sys import platform

from secc_settings import Config
from ..shared.network import get_link_local_full_addr
from ..shared.notifications import TCPClientNotification

logger = logging.getLogger(__name__)


class TCPServer(asyncio.Protocol):
    # pylint: disable=too-many-instance-attributes
    """ TCP Сервер для V2G цикла связи """

    # Кортеж содржащий данные IPv6 сервера (host, port, flowinfo, scope_id)
    # Например: ('fe80::1', 64473, 0, 1)
    full_ipv6_address: Tuple[str, int, int, int]
    # 'host' составляющая кортежа
    ipv6_address_host: str

    def __init__(self, session_handler_queue: asyncio.Queue, iface: str, config: Config) -> None:
        self._session_handler_queue = session_handler_queue
        self.config = config
        self.port_no_tls = config.port
        self.port_tls    = config.port         # TLS не поддерживается
        self.iface = iface
        self.server = None
        self.is_tls_enabled = False
        self.ciphersuites = config.ciphersuites

    async def _create_socket(self, port: int, iface: str) -> "socket":
        """
        Создание нативного сокета 
        """
        if platform.startswith("linux"):

            # Инициализаия IPv6 сокета с транспортом TCP 
            sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)

            # Разрешить переиспользование
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Создание полного набора информации IPv6 о сервере 
            self.full_ipv6_address = await get_link_local_full_addr(port, iface)
            self.ipv6_address_host = self.full_ipv6_address[0]

            # Привязка сокета к IP-адресу и порту
            sock.bind(self.full_ipv6_address)

            return sock
        else:       # Для Windows версии (!) Внимание, сетевой интерфейс должен быть активен, и не иметь VPN (!)

            # Инициализаия IPv6 сокета с транспортом TCP 
            sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_STREAM)

            # Разрешить переиспользование
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            
            server_address = (self.config.addr,port)
            
            # self.full_ipv6_address = await get_link_local_full_addr(port, iface)
            self.ipv6_address_host = self.config.addr

            # Привязка сокета к IP-адресу и порту
            sock.bind(server_address)
            return sock



    async def server_factory(self, tls: bool) -> None:
        """
        Создание TCP | TLS сервера
        После создания сервер сразу готов принимать подключения. 

        Справка по `asyncio.start_server`:
        https://docs.python.org/3/library/asyncio-stream.html#asyncio.start_server

        """
        port = self.port_no_tls
        ssl_context = None
        server_type = "TCP"
        self.is_tls_enabled = False
        # if tls:                                       # TLS не поддерживается
        #     port = self.port_tls
        #     ssl_context = get_ssl_context(True, self.ciphersuites)
        #     if ssl_context is not None:
        #         server_type = "TLS"
        #         self.is_tls_enabled = True
        #     else:
        #         logger.warning(
        #             "SSL context not created. Falling back to TCP connection."
        #         )

        # Создаем IPv6 TCP сокет
        sock = await self._create_socket(self.port_no_tls, self.iface)

        self.server = await asyncio.start_server(
            # Callback для каждого нового подключения клиента, также передает StreamReader and StreamWriter
            client_connected_cb=self,       
            sock=sock,
            reuse_address=True,
            ssl=ssl_context,
        )

        logger.info(
            f"{server_type} server started at "
            f"address {self.ipv6_address_host}%{self.iface} and "
            f"port {port}"
        )

        try:
            await asyncio.shield(self.server.wait_closed())
        except asyncio.CancelledError:
            logger.warning("Closing TCP server")
            self.server.close()
            await self.server.wait_closed()

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Callback при подключении нового клиента.
        """
        new_client = TCPClientNotification(reader, writer)

        self._session_handler_queue.put_nowait(new_client)