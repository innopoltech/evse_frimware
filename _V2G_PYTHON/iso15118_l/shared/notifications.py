from asyncio.streams import StreamReader, StreamWriter
from typing import Tuple

from ..shared.messages.enums import SessionStopAction


class Notification:
    """
    Базовый класс для всех уведомлений
    """


class TCPClientNotification(Notification):
    def __init__(self, reader: StreamReader, writer: StreamWriter):
        self.transport = (reader, writer)
        self.ip_address = writer.get_extra_info("peername")


class UDPPacketNotification(Notification):
    """
    Уведомления UDP
    """

    def __init__(self, data: bytes, addr: Tuple[str, int]):
        self.data = data
        self.addr = addr

    def __len__(self):
        return len(self.data)


class ReceiveTimeoutNotification(Notification):
    """
    Превышено время ожидания следующего пакета
    """


class StopNotification(Notification):
    """
    Необходимо остановить сессию
    """

    def __init__(
            self,
            successful: bool,
            reason: str,
            peer_ip_address: str = None,
            stop_action: SessionStopAction = SessionStopAction.TERMINATE,
    ):
        self.successful = successful
        self.reason = reason
        self.peer_ip_address = peer_ip_address
        self.stop_action = stop_action
