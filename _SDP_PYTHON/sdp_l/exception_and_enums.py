import logging
from enum import Enum, IntEnum
from typing import List, Union

logger = logging.getLogger(__name__)

class InvalidSDPRequestError(Exception):
    """Ошибка создания SDP запроса из байтового массива"""
class InvalidV2GTPMessageError(Exception):
    """Ошибка создания V2GTP сообщения из байтового массива """
class InvalidPayloadTypeError(Exception):
    """Данный вид протокола не поддерживается EVCC"""
class InvalidProtocolError(Exception):
    """Не известный тип протокола"""
class InvalidSDPResponseError(Exception):
    """Ошибка создания SDP ответа из байтового массива"""

# Для XSD-типа xs:unsignedInt - [0..4294967296]
UINT_32_MAX = 2**32 - 1

class Namespace(str, Enum):
    """
    Пространства имен, используемые в DIN SPEC 70121, ISO 15118-2, и ISO 15118-20.
    Необходимы для пакетов SupportedAppProtocol и EXI кодека.
    """
    DIN_MSG_DEF             = "urn:din:70121:2012:MsgDef"
    DIN_MSG_BODY            = "urn:din:70121:2012:MsgBody"
    DIN_MSG_DT              = "urn:din:70121:2012:MsgDataTypes"
    ISO_V2_MSG_DEF          = "urn:iso:15118:2:2013:MsgDef"
    ISO_V2_MSG_BODY         = "urn:iso:15118:2:2013:MsgBody"
    ISO_V2_MSG_DT           = "urn:iso:15118:2:2013:MsgDataTypes"
    ISO_V20_BASE            = "urn:iso:std:iso:15118:-20"
    ISO_V20_COMMON_MSG      = ISO_V20_BASE + ":CommonMessages"
    ISO_V20_COMMON_TYPES    = ISO_V20_BASE + ":CommonTypes"
    ISO_V20_AC              = ISO_V20_BASE + ":AC"
    ISO_V20_DC              = ISO_V20_BASE + ":DC"
    ISO_V20_WPT             = ISO_V20_BASE + ":WPT"
    ISO_V20_ACDP            = ISO_V20_BASE + ":ACDP"
    XML_DSIG                = "http://www.w3.org/2000/09/xmldsig#"
    SAP                     = "urn:iso:15118:2:2010:AppProtocol"

class DINPayloadTypes(IntEnum):
    """
    Типы полезной нагрузки по DIN SPEC 70121  (глава 8.7.3.1)
    """
    EXI_ENCODED     = 0x8001
    SDP_REQUEST     = 0x9000
    SDP_RESPONSE    = 0x9001

    # 0xA000 - 0xFFFF: специфичные, для использования производителем.
    # Остальные зарезервированы

    @classmethod
    def options(cls) -> list:
        return list(cls)

class ISOV2PayloadTypes(IntEnum):
    """
    Типы полезной нагрузки по ISO 15118-2 (глава 7.8.3, таблица 10)
    """
    EXI_ENCODED     = 0x8001
    SDP_REQUEST     = 0x9000
    SDP_RESPONSE    = 0x9001

    # 0xA000 - 0xFFFF: специфичные, для использования производителем.
    # Остальные зарезервированы

    @classmethod
    def options(cls) -> list:
        return list(cls)

class ISOV20PayloadTypes(IntEnum):
    """Типы полезной нагрузки по ISO 15118-20 (глава 12)"""
    SAP                     = 0x8001
    MAINSTREAM              = 0x8002
    AC_MAINSTREAM           = 0x8003
    DC_MAINSTREAM           = 0x8004
    ACDP_MAINSTREAM         = 0x8005
    WPT_MAINSTREAM          = 0x8006
    # 0x8007 - 0x8100: зарезервировано
    SCHEDULE_RENEGOTIATION  = 0x8101
    METERING_CONFIRMATION   = 0x8102
    ACDP_SYSTEM_STATUS      = 0x8103
    PARKING_STATUS          = 0x8104
    # 0x8105 - 0x8FFF: зарезервировано
    SDP_REQUEST             = 0x9000
    SDP_RESPONSE            = 0x9001
    SDP_REQUEST_WIRELESS    = 0x9002  # Used e.g. for ACDP (ACD Pantograph)
    SDP_RESPONSE_WIRELESS   = 0x9003  # Used e.g. for ACDP (ACD Pantograph)

    # 0xA000 - 0xFFFF: специфичные, для использования производителем.
    # 0x9004 - 0x9FFF: зарезервированы

    @classmethod
    def options(cls) -> list:
        return list(cls)

class V2GTPVersion(IntEnum):
    """
    Версия протокола V2G по ISO 15118-2 и ISO 15118-20.
    """
    PROTOCOL_VERSION        = 0x01
    INV_PROTOCOL_VERSION    = 0xFE

    @classmethod
    def options(cls) -> list:
        return list(cls)


class Protocol(Enum):
    """
    Протоколы связи, поддерживаемые Josev. Задаются кортежами:
    первый элемент - пространство имен, 
    второй элемент - перечисление типов полезной нагрузки
    """

    UNKNOWN                         = ("",                              ISOV2PayloadTypes)
    DIN_SPEC_70121                  = (Namespace.DIN_MSG_DEF,           DINPayloadTypes)
    ISO_15118_2                     = (Namespace.ISO_V2_MSG_DEF,        ISOV2PayloadTypes)
    ISO_15118_20_COMMON_MESSAGES    = (Namespace.ISO_V20_COMMON_MSG,    ISOV20PayloadTypes)
    ISO_15118_20_AC                 = (Namespace.ISO_V20_AC,            ISOV20PayloadTypes)
    ISO_15118_20_DC                 = (Namespace.ISO_V20_DC,            ISOV20PayloadTypes)
    ISO_15118_20_WPT                = (Namespace.ISO_V20_WPT,           ISOV20PayloadTypes)
    ISO_15118_20_ACDP               = (Namespace.ISO_V20_ACDP,          ISOV20PayloadTypes)

    def __init__(
        self,
        namespace: Namespace,
        payload_types: Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes],
    ):
        self.namespace      = namespace
        self.payload_types  = payload_types

    @property
    def ns(self) -> Namespace:
        return self.namespace

    @property
    def payloads(self) -> Union[DINPayloadTypes, ISOV2PayloadTypes, ISOV20PayloadTypes]:
        return self.payload_types

    @classmethod
    def options(cls) -> list:
        return list(cls)

    @classmethod
    def names(cls) -> list:
        return [protocol.name for protocol in cls]

    @classmethod
    def allowed_protocols(cls) -> list:
        return [
            protocol.name
            for protocol in cls
            if protocol.name not in ["UNKNOWN", "ISO_15118_20"]
        ]

    @classmethod
    def get_by_ns(cls, namespace: str) -> "Protocol":
        """Получение протокола по пространству имен"""
        for protocol in cls.options():
            if protocol.ns == namespace:
                return protocol

        logger.error(f"No available protocol matching namespace '{namespace}'")
        return Protocol.UNKNOWN

    def __str__(self):
        return str(self.name)

    @classmethod
    def v20_namespaces(cls) -> List[str]:
        return [
            protocol.namespace
            for protocol in cls
            if "urn:iso:std:iso:15118:-20" in protocol.namespace
        ]