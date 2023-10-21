import logging
from enum import Enum, IntEnum
from typing import List, Union

logger = logging.getLogger(__name__)

# Для XSD xs:unsignedLong диапазон [0..18446744073709551615]
UINT_64_MAX = 2**64 - 1
# Для XSD xs:unsignedInt диапазон [0..4294967296]
UINT_32_MAX = 2**32 - 1
# Для XSD xs:unsignedShort диапазон [0..65535]
UINT_16_MAX = 2**16 - 1
# Для XSD xs:unsignedByte диапазон [0..255]
UINT_8_MAX = 2**8 - 1
# Для XSD xs:short диапазон [-32768..32767]
INT_16_MAX = 2**15 - 1
INT_16_MIN = -(2**15)
# Для XSD xs:byte диапазон [-128..127]
INT_8_MAX = 2**7 - 1
INT_8_MIN = -(2**7)


class AuthEnum(str, Enum):
    """
    Типы авторизации отличаются между  DIN SPEC 70121,
    ISO 15118-2 и ISO 15118-20.
    """

    EIM         = "EIM"
    PNC         = "PnC"
    EIM_V2      = "ExternalPayment"
    PNC_V2      = "Contract"


class AuthorizationStatus(str, Enum):
    """ 
    Состояние запроса на авторизацию.

    В ISO 15118, в отличии от DIN SPEC 70121, также используется Rejected.
    """

    ACCEPTED = "Accepted"
    REJECTED = "Rejected"
    ONGOING  = "Ongoing"


class EnergyTransferModeEnum(str, Enum):
    """
    Общие параметры для DIN SPEC 70121 и ISO 15118-2
    """

    AC_SINGLE_PHASE_CORE    = "AC_single_phase_core"
    AC_THREE_PHASE_CORE     = "AC_three_phase_core"
    DC_CORE                 = "DC_core"
    DC_EXTENDED             = "DC_extended"
    DC_COMBO_CORE           = "DC_combo_core"
    DC_UNIQUE               = "DC_unique"


class UnitSymbol(str, Enum):
    """
    Допустимые физические единицы
    """

    HOURS               = "h"
    MINUTES             = "m"
    SECONDS             = "s"
    AMPERE              = "A"
    VOLTAGE             = "V"
    WATT                = "W"
    WATT_HOURS          = "Wh"
    AMPERE_HOUR         = "Ah"
    VOLT_AMPERE         = "VA"
    WATT_PER_SECOND     = "W/s"

class EVSEProcessing(str, Enum):
    FINISHED    = "Finished"
    ONGOING     = "Ongoing"
    ONGOING_WAITING_FOR_CUSTOMER = (
        "Ongoing_WaitingForCustomerInteraction"  # Не допустимо DIN SPEC 70121
    )

class IsolationLevel(str, Enum):
    INVALID     = "Invalid"
    VALID       = "Valid"
    WARNING     = "Warning"
    FAULT       = "Fault"
    NO_IMD      = "No_IMD"

class DCEVErrorCode(str, Enum):
    NO_ERROR                                = "NO_ERROR"
    FAILED_RESS_TEMPERATURE_INHIBIT         = "FAILED_RESSTemperatureInhibit"
    FAILED_EV_SHIFT_POSITION                = "FAILED_EVShiftPosition"
    FAILED_CHARGER_CONNECTOR_LOCK_FAULT     = "FAILED_ChargerConnectorLockFault"
    FAILED_EV_RESS_MALFUNCTION              = "FAILED_EVRESSMalfunction"
    FAILED_CHARGING_CURRENT_DIFFERENTIAL    = "FAILED_ChargingCurrentdifferential"
    FAILED_CHARGING_VOLTAGE_OUT_OF_RANGE    = "FAILED_ChargingVoltageOutOfRange"
    FAILED_CHARGING_SYSTEM_INCOMPATIBILITY  = "FAILED_ChargingSystemIncompatibility"
    NO_DATA                                 = "NoData"
    RESERVED_A                              = "Reserved_A"
    RESERVED_B                              = "Reserved_B"
    RESERVED_C                              = "Reserved_C"

class V2GTPVersion(IntEnum):
    """
    Версия протокола V2G по ISO 15118-2 и ISO 15118-20.
    """
    PROTOCOL_VERSION        = 0x01
    INV_PROTOCOL_VERSION    = 0xFE

    @classmethod
    def options(cls) -> list:
        return list(cls)


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


class ParameterName(str, Enum):
    CONNECTOR                           = "Connector"
    CONTROL_MODE                        = "ControlMode"
    EVSE_NOMINAL_VOLTAGE                = "EVSENominalVoltage"
    MOBILITY_NEEDS_MODE                 = "MobilityNeedsMode"
    PRICING                             = "Pricing"
    BPT_CHANNEL                         = "BPTChannel"
    GENERATOR_MODE                      = "GeneratorMode"
    GRID_CODE_ISLANDING_DETECTION_MODE  = "GridCodeIslandingDetectionMethod"

class AuthorizationTokenType(str, Enum):
    EMAID = "eMAID"
    EXTERNAL = "external"

class CpState(str, Enum):
    A1 = "A1"
    A2 = "A2"
    B1 = "B1"
    B2 = "B2"
    C1 = "C1"
    C2 = "C2"
    D1 = "D1"
    D2 = "D2"
    E  = "E"
    F  = "F"
    UNKNOWN = "UNKNOWN"

class SessionStopAction(str, Enum):
    TERMINATE   = "terminate"
    PAUSE       = "pause"
