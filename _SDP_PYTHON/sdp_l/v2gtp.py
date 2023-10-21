import logging
from typing import Union
from .exception_and_enums import (
    InvalidPayloadTypeError,
    InvalidProtocolError,
    InvalidV2GTPMessageError,
    UINT_32_MAX,
    DINPayloadTypes,
    ISOV2PayloadTypes,
    ISOV20PayloadTypes,
    Namespace,
    Protocol,
    V2GTPVersion,
)

logger = logging.getLogger(__name__)

class V2GTPMessage:
    def __init__(
        self,
        protocol: Protocol,
        payload_type: Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes],
        payload: bytes,
    ):
        """
        Пакет V2G состоит из заголовка и полезной нагрузки

                |  Header |         Payload        |
                | 8 Bytes |   0 - 4294967296 Bytes |

        Полезная нагрузка содержит данные верхних уровней (представления или прикладного).
        Заголовок содержит информацию о типе и размере полезных данных.
        Размер заголовка 8 байт:

        -     0     -        1         -      2-3    -      4-5-6-7      -
         ____________ __________________ _____________ __________________
        |  Protocol |      Inverse     |    Payload  |      Payload     |
        |  Version  | Protocol Version |     Type    |      Length      |
         ____________ __________________ _____________ _________________
        |  1 Byte   |     1 Byte       |    2 Bytes  |    4 Bytes      |

        protocol_version            = 0x01      : Идентификатор версии V2GTP сообщения
        inverse_protocol_version    = 0xFE      : Идентификатор версии V2GTP сообщения, инвертированный побитово
        payload_type                = X         : Тип предоставляемых данных
        payload_length              = X         : Длина V2GTP сообщения в байтах
        """
        if protocol not in Protocol.options():      # Проверка на существование выбранного протокола
            raise InvalidProtocolError(
                f"'{protocol.name}' is not a "
                "valid protocol. Allowed: "
                f"{Protocol.allowed_protocols()}"
            )

        if not self.is_payload_type_valid(protocol, payload_type):  # Проверка на существование типа данных в протоколе
            raise InvalidPayloadTypeError(
                f"Protocol {protocol} doesn't support" f" payload type {payload_type}"
            )

        self.protocol               = protocol
        self.protocol_version       = V2GTPVersion.PROTOCOL_VERSION
        self.inv_protocol_version   = V2GTPVersion.INV_PROTOCOL_VERSION
        self.payload_type           = payload_type
        self.payload_length         = len(payload)
        self.payload                = payload

    @staticmethod
    def get_payload_type(header: bytes) -> int:
        if len(header) == 8:                    # Возвращение типа полезной нагрузки только при валидной длине заголовка
            return int.from_bytes(header[2:4], "big")   
        return -1

    @staticmethod
    def get_payload_length(header: bytes) -> int:
        if len(header) == 8:                    # Возвращение длинны полезной нагрузки только при валидной длине заголовка
            return int.from_bytes(header[4:], "big")
        return -1

    @classmethod
    def is_payload_type_valid(cls, protocol: Protocol, payload_type: int) -> bool:  # Проверка типа данных для протокола
        is_valid = True

        if (protocol in [Protocol.ISO_15118_2, Protocol.UNKNOWN] and 
            payload_type not in ISOV2PayloadTypes.options()):          
            is_valid = False

        if (protocol.ns.startswith(Namespace.ISO_V20_BASE) and  # Для всех видов ISO_V20
            payload_type not in ISOV20PayloadTypes.options()):
            is_valid = False

        if(is_valid == True):
            return is_valid
        
        logger.error(f"{str(protocol)} does not support payload type " f"{payload_type}")
        return is_valid

    @classmethod
    def is_header_valid(cls, protocol: Protocol, header: bytes) -> bool:
        """
        Проверка валидности заголовка по 15118 (15118-2, глава 7.8.3.2)
        """
        is_valid: bool = True

        if len(header) != 8:                    # Проверка длинны заголовка
            logger.error(
                f"No proper V2GTP message, header is "
                f"{len(header)} bytes long. Expected: 8 bytes"
            )
            is_valid = False

        if protocol not in Protocol.options(): # Проверка существования протокола 
            logger.error(
                f"Unable to identify protocol version. " f"Received: {protocol}"
            )
            is_valid = False

        protocol_version = header[0]
        if protocol_version != V2GTPVersion.PROTOCOL_VERSION:   # Проверка версии протокола V2G
            logger.error(
                f"Incorrect protocol version '{protocol_version}' "
                f"for V2GTP message. "
                f"Expected: {V2GTPVersion.PROTOCOL_VERSION}"
            )
            is_valid = False

        inv_protocol_version = header[1]                        # Проверка версии протокола V2G (инвертированной)
        if inv_protocol_version != V2GTPVersion.INV_PROTOCOL_VERSION:
            logger.error(
                f"Incorrect inverse protocol version "
                f"'{inv_protocol_version}' for V2GTP message. "
                f"Expected: {V2GTPVersion.INV_PROTOCOL_VERSION}"
            )
            is_valid = False

        if not cls.is_payload_type_valid(protocol, cls.get_payload_type(header)): # Проверка типа данных для протокола
            is_valid = False

        payload_length = cls.get_payload_length(header)     # Проверка длинны полезной нагрузки
        if payload_length > UINT_32_MAX:
            logger.error(
                f"Payload length of {payload_length} bytes for V2GTP "
                f"message exceeds limit of {UINT_32_MAX} bytes"
            )
            is_valid = False

        if payload_length < 0:                              # Проверка длинны полезной нагрузки
            logger.error(
                "Couldn't determine payload length of V2GTP message " "(got -1)"
            )
            is_valid = False

        return is_valid

    def to_bytes(self) -> bytes:
        header = (
            self.protocol_version.to_bytes(1, "big")
            + self.inv_protocol_version.to_bytes(1, "big")
            + self.payload_type.to_bytes(2, "big")
            + self.payload_length.to_bytes(4, "big")
        )

        return bytes(header) + self.payload

    @classmethod
    def from_bytes(cls, protocol: Protocol, data: bytes) -> "V2GTPMessage":
        """
        Создание V2GTP сообщения на основе байтового массива.
        """
        if len(data) >= 10:         # Наименьший возможный размер полезной нагрузки - SDP запрос (2 байта)
            header = data[:8]

            payload_type: Union[ISOV2PayloadTypes, ISOV20PayloadTypes]  
            if cls.is_header_valid(protocol, header):                 
                if protocol.ns.startswith(Namespace.ISO_V20_BASE):          # Определение типа нагрузки
                    payload_type = ISOV20PayloadTypes(cls.get_payload_type(header))
                else:
                    payload_type = ISOV2PayloadTypes(cls.get_payload_type(header))

                return V2GTPMessage(protocol, payload_type, data[8:])       # Создание V2GTP пакета
            
            raise InvalidV2GTPMessageError("Not a valid V2GTP message " "(header check failed)" )
        
        raise InvalidV2GTPMessageError(
            f"Incoming data is too short to be "
            "a valid V2GTP message"
            f" (only {len(data)} bytes)"
        )

    def __repr__(self):                 # Представление V2G пакета (объекта класса) в виде строки
        return (
            f"[Header = [{hex(self.protocol_version)}, "
            f"{hex(self.inv_protocol_version)}, {hex(self.payload_type)}, "
            f"{self.payload_length}], Payload = {self.payload.hex()})"
            "]"
        )