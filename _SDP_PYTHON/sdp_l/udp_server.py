import asyncio
import logging
import socket
import struct
from sys import platform
from asyncio import DatagramTransport

logger = logging.getLogger("udp_server")

SDP_MULTICAST_GROUP = "FF02::1"
SDP_MULTICAST_GROUP_FULL = "FF02:0:0:0:0:0:0:1"
SDP_SERVER_PORT = 15118


class UDPServer(asyncio.DatagramProtocol):                      # Класс UDP сервера
    """
    UDPServer использует asyncio и его реализацию транспортов.
        
    Для UDP используется asyncio.DatagramTransport, подробнее:
    https://docs.python.org/3/library/asyncio-protocol.html
    """

    def __init__(self, session_handler_queue: asyncio.Queue, iface: str):
        self.iface = iface
        self.session_handler_queue: asyncio.Queue = session_handler_queue
        self.transport      : DatagramTransport = None
        self.started        : bool = False
        self.pause_server   : bool = False

    async def _create_socket(self, iface: str) -> "socket":
        """
        Создание нативного сокета 
        """
        if platform.startswith("linux"):
            # Сокет должен быть UDP-IPv6
            sock = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)

            # Блокировка комбинации сокет+интерфейс, подробнее:
            # https://www.man7.org/linux/man-pages/man7/socket.7.html
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Привязка сокета к указанному порту
            if not hasattr(socket, "SO_BINDTODEVICE"):
                socket.SO_BINDTODEVICE = 25

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_BINDTODEVICE,
                (iface + "\0").encode("ascii"),
            )
            sock.bind(("", SDP_SERVER_PORT))

            # Конвертирование IPv6 адреса из строкового представления в двоичный формат
            multicast_group_bin = socket.inet_pton(socket.AF_INET6, SDP_MULTICAST_GROUP)

            # Получение индекса сетевого интерфейса в системе
            interface_idx = socket.if_nametoindex(iface)

            # Создание массива: адрес + индекс интерфейса
            join_multicast_group_req = multicast_group_bin + struct.pack("@I", interface_idx) 

            # После привязки сокета к порту, необходимо добавить их в группу multicast. 
            # Для этого используется IPV6_JOIN_GROUP опция, в которой нужно передать 16 байтный массив
            # с адресом группы multicast и индексом сетевого интерфейса.
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, join_multicast_group_req)
            
            return sock
        else:       # Для Windows версии (!) Внимание, сетевой интерфейс должен быть активен, и не иметь VPN (!)
            # Извлечение информации об адресе, указывается полный IPv6 адрес
            addrinfo = socket.getaddrinfo(SDP_MULTICAST_GROUP_FULL, None)[0]

            # Создание сокета
            s = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

            # Привязка сокета к указанному порту
            s.bind(('', SDP_SERVER_PORT))

            # Блокировка комбинации сокет+интерфейс
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Конвертирование IPv6 адреса из строкового представления в двоичный формат
            group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
            
            # Присоединение к группе
            mreq = group_bin + struct.pack('@I', 0)
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

            return s


    async def start(self):
        """Запуск UDP сервера"""
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self,                                           # Callback-ки находятся в этом классе
            sock = await self._create_socket(self.iface),
        )

        logger.info(
            "UDP server started at address "
            f"{SDP_MULTICAST_GROUP}%{self.iface} "
            f"and port {SDP_SERVER_PORT}"
        )

    async def stop(self):
        self.transport.close()
        try:
            await self.transport.wait_closed()
        except Exception:
            pass


    def send(self, message, addr):
        """
        Отправка сообщения в UDP сокет
        """
        if(self.started == True and self.pause_server == False):
            self.transport.sendto(message.to_bytes(), addr)
        else:
            raise ConnectionError("UDP server not ready!")

    def pause_udp_server(self):
        """
        Блокировка UDP сервера
        """
        logger.info("UDP server has been paused.")
        self.pause_server = True

    def resume_udp_server(self):
        """
        Возобновление работы UDP сервера
        """
        logger.info("UDP server has been resumed.")
        self.pause_server = False

                                            # Callback-ки UDP сервера 
    def connection_made(self, transport):
        """
        Callback - сокет успешно запущен и подключен к порту
        """
        logger.info("UDP server socket ready")
        self.started = True

    def datagram_received(self, data: bytes, addr):
        """
        Callback - был принят пакет данных
        """
        if self.pause_server:           # Если сервер в паузе, то игнорируем запрос
            return

        logger.debug(f"Message received from {addr}: {data.hex()}")
        try:
            self.session_handler_queue.put_nowait((data, addr))       # Передача пакета в очередь        
        except asyncio.QueueFull:   
            logger.error(f"Dropped packet size {len(data)} from {addr}")

    def error_received(self, exc):
        """
        Callback - произошла ошибка приема
        """
        logger.exception(f"Server received an error: {exc}")

    def connection_lost(self, exc):
        """
        Callback - потерянно соединение сокета с портом
        """
        reason = f". Reason: {exc}" if exc else ""
        logger.exception(f"UDP server closed. {reason}")
        self.started = False
