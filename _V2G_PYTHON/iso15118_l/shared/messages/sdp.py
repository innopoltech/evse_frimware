import logging
from enum import IntEnum
from ipaddress import IPv6Address
from typing import Union

from ...shared.exceptions import InvalidSDPRequestError, InvalidSDPResponseError

logger = logging.getLogger(__name__)

MIN_TCP_PORT = 49152
MAX_TCP_PORT = 65535

class Security(IntEnum):
    """
    Возможные варианты заполнения поля 'security' в SDP запросе и ответе по ISO 15118-2 и ISO 15118-20.
    """
    TLS     = 0x00
    NO_TLS  = 0x10

    @classmethod
    def options(cls) -> list:
        return list(cls)

    @classmethod
    def from_byte(cls, byte: bytes) -> "Security":
        if int.from_bytes(byte, "big") == Security.TLS:
            return Security.TLS
        if int.from_bytes(byte, "big") == Security.NO_TLS:
            return Security.NO_TLS

        logger.error(f"Invalid byte value for Security enum: {byte.hex()}")
        raise ValueError


class Transport(IntEnum):
    """
    Возможные варианты заполнения поля 'transport' в SDP запросе и ответе по ISO 15118-2 и ISO 15118-20.
    
    UDP не допускается к использованию. 
    """

    TCP = 0x00
    UDP = 0x10

    @classmethod
    def options(cls) -> list:
        return list(cls)

    @classmethod
    def from_byte(cls, byte: bytes) -> "Transport":
        if int.from_bytes(byte, "big") == Transport.TCP:
            return Transport.TCP
        if int.from_bytes(byte, "big") == Transport.UDP:
            return Transport.UDP

        logger.error(f"Invalid byte value for Transport enum: {byte.hex()}")
        raise ValueError


class SDPRequest:
    """
    Сообщение SECC Discovery Protocol Request.
    Запрос от EVCC, для получения IP-адреса и порта SECC, а так же,
    для получения типа транспорта TLS или TCP.
    """
    def __init__(self, security: Security, transport_protocol: Transport):

        if security not in Security.options():      # Проверка существования типа защищенности транспорта
            logger.error(
                f"'{security}' is not a valid value for "
                f"the field 'security'."
                f"Allowed: {Security.options()} "
            )
            raise InvalidSDPRequestError("Invalid input parameters - security")
            

        if transport_protocol not in Transport.options():   # Проверка существования типа транспорта
            logger.error(
                f"'{transport_protocol}' is not a valid value for the "
                f"field 'transport_protocol'."
                f"Allowed: {Transport.options()} "
            )
            raise InvalidSDPRequestError("Invalid input parameters - transport_protocol")

        self.security           = security
        self.transport_protocol = transport_protocol
        self.payload_type       = 0x9000  # SDP запрос одинаков для -2 и -20

    def to_payload(self) -> bytes:
        message = self.security.to_bytes(1, "big") + self.transport_protocol.to_bytes(1, "big")
        return bytes(message)

    @staticmethod
    def from_payload(payload: bytes) -> "SDPRequest":
        if len(payload) != 2:
            logger.error(
                "Payload must be of 2 bytes length. "
                f"Provided: {len(payload)} bytes ({payload.hex()})"
            )
            raise InvalidSDPRequestError

        try:                                    # Создание SDP запроса из массива байт
            security    = Security.from_byte(payload[:1])
            transport   = Transport.from_byte(payload[1:2])

            return SDPRequest(security, transport)
        except ValueError as exc:
            raise InvalidSDPRequestError from exc

    def __len__(self):
        return 2

    def __repr__(self):
        return ("[ "f"Security: {self.security.name}" f", Protocol: {self.transport_protocol.name}" "]")


class SDPResponse:
    """
    Сообщение SECC Discovery Protocol Request.
    Ответ от SECC о типе подключения, а так же, об IP адресе и порте.
    """

    def __init__(
        self,
        ip_address: bytes,
        port: int,
        security: Security,
        transport_protocol: Transport,
    ):
        if len(ip_address) != 16:                           # Проверка длинны IPv6 адреса
            logger.error(
                f"Please provide a valid IPv6 address with 16 bytes. "
                f"Provided: {len(ip_address)} bytes "
                f"({ip_address.hex()})"
            )
            raise InvalidSDPResponseError("Invalid input parameters - ip_address")

        if port < MIN_TCP_PORT or port > MAX_TCP_PORT:      # Проверка валидности порта
            logger.error(
                f"The port {port} does not match the mandatory "
                f"UDP server port 15118."
            )
            raise InvalidSDPResponseError("Invalid input parameters - port")

        if security not in Security.options():          # Проверка существования типа защищенности транспорта
            logger.error(
                f"'{security}' is not a valid value for the "
                f"field 'security'."
                f"Allowed: {Security.options()} "
            )
            raise InvalidSDPResponseError("Invalid input parameters - security")

        if transport_protocol not in Transport.options():           # Проверка существования типа транспорта
            logger.error(
                f"'{transport_protocol}' is not a valid value for "
                f"the field 'transport_protocol'."
                f"Allowed: {Transport.options()} "
            )
            raise InvalidSDPResponseError("Invalid input parameters - transport_protocol")

        self.ip_address         = ip_address
        self.port               = port
        self.security           = security
        self.transport_protocol = transport_protocol
        self.payload_type       = 0x9001        # SDP ответ одинаков для -2 и -20

    def to_payload(self) -> bytes:
        payload = (
            self.ip_address
            + self.port.to_bytes(2, "big")
            + self.security.value.to_bytes(1, "big")
            + self.transport_protocol.to_bytes(1, "big")
        )
        return payload

    @staticmethod
    def from_payload(payload) -> "SDPResponse":
        if len(payload) != 20:
            raise InvalidSDPResponseError(
                f"Payload must be of 20 bytes length. "
                f"Provided: {len(payload)} bytes ({payload})"
            )

        return SDPResponse(
            payload[:16],                                       # IPv6 адрес
            int.from_bytes(payload[16:18], "big"),              # Порт
            Security(int.from_bytes(payload[18:19], "big")),    # Защищенность
            Transport(int.from_bytes(payload[19:20], "big")),   # Транспорт
        )

    def __len__(self):
        return 20

    def __repr__(self):
        ip_address: str = IPv6Address(int.from_bytes(self.ip_address, "big")).compressed
        return (
            f"[ IP address: {ip_address}"
            f", Port: {str(self.port)} "
            f", Security: {self.security.name} "
            f", Transport: {self.transport_protocol.name} ]"
        )


class SDPRequestWireless(SDPRequest):
    pass


class SDPResponseWireless(SDPResponse):
    pass


def create_sdp_response(
    sdp_request: Union[SDPRequest, SDPRequestWireless],
    ip_address: bytes,
    port: int,
    tls_enabled: bool,
) -> Union[SDPResponse, SDPResponseWireless]:
    """
    Создание SDP ответа на основе SDP запроса
    """
    sdp_response = None

    if tls_enabled:
        security = Security.TLS
    else:
        security = Security.NO_TLS

    if isinstance(sdp_request, SDPRequest):
        sdp_response = SDPResponse(ip_address, port, security, Transport.TCP)
    elif isinstance(sdp_request, SDPRequestWireless):
        raise NotImplementedError("SDPRequestWireless is not yet implemented")
    else:
        logger.error("Invalid SDP request, will ignore")

    return sdp_response
