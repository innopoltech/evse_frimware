from enum import Enum, IntEnum
from typing import List, Optional

from pydantic import Field, conbytes, constr, root_validator, validator

from ....shared.messages import BaseModel
from ....shared.messages.datatypes import (
    EVSEStatus,
    PhysicalValue,
    PVEAmount,
    PVEVEnergyCapacity,
    PVEVEnergyRequest,
    PVEVMaxCurrent,
    PVEVMaxCurrentLimit,
    PVEVMaxPowerLimit,
    PVEVMaxVoltage,
    PVEVMaxVoltageLimit,
    PVEVMinCurrent,
    PVEVSEMaxCurrent,
    PVEVSENominalVoltage,
    PVPMax,
    PVStartValue,
)
from ....shared.messages.enums import (
    INT_8_MAX,
    INT_8_MIN,
    INT_16_MAX,
    INT_16_MIN,
    UINT_32_MAX,
    AuthEnum,
    DCEVErrorCode,
    EnergyTransferModeEnum,
)
from ....shared.messages.xmldsig import X509IssuerSerial
from ....shared.validators import one_field_must_be_set

# Подробнее в приложении C.6 или "the certificateType" в V2G_CI_MsgDataTypes.xsd
# https://pydantic-docs.helpmanual.io/usage/types/#constrained-types
Certificate = conbytes(max_length=800)
# Подробнее в приложении C.6 или "the eMAIDType" в V2G_CI_MsgDataTypes.xsd
eMAID = constr(min_length=14, max_length=15)


class EVChargeParameter(BaseModel):
    """Подробности в ISO 15118-2, глава 8.4.3.8.2"""

    # XSD unsignedInt (32-битное целое)
    departure_time: Optional[int] = Field(None, ge=0, le=UINT_32_MAX, alias="DepartureTime")


class ACEVChargeParameter(EVChargeParameter):
    """Подробности в ISO 15118-2, глава 8.5.3.2"""

    e_amount: PVEAmount = Field(..., alias="EAmount")
    ev_max_voltage: PVEVMaxVoltage = Field(..., alias="EVMaxVoltage")
    ev_max_current: PVEVMaxCurrent = Field(..., alias="EVMaxCurrent")
    ev_min_current: PVEVMinCurrent = Field(..., alias="EVMinCurrent")


class ACEVSEStatus(EVSEStatus):
    """Подробности в ISO 15118-2, глава 8.5.3.1"""

    rcd: bool = Field(..., alias="RCD")


class ACEVSEChargeParameter(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.3.3"""

    ac_evse_status: ACEVSEStatus = Field(..., alias="AC_EVSEStatus")
    evse_nominal_voltage: PVEVSENominalVoltage = Field(..., alias="EVSENominalVoltage")
    evse_max_current: PVEVSEMaxCurrent = Field(..., alias="EVSEMaxCurrent")


class SubCertificates(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.5 и 8.5.2.26

    Согласно схеме, SubCertificates может содержать до 4 сертификатов.
    Однако, по [V2G2-656] максимально допустимо 2 сертификата.
    """
    certificates: List[Certificate] = Field(..., max_items=2, alias="Certificate")


class CertificateChain(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.5"""

    id: Optional[str] = Field(None, alias="Id")
    certificate: Certificate = Field(..., alias="Certificate")
    sub_certificates: Optional[SubCertificates] = Field(None, alias="SubCertificates")

    def __str__(self):
        return type(self).__name__


class ChargeProgress(str, Enum):
    """Подробности в ISO 15118-2, глава 8.4.3.9.2"""

    START           = "Start"
    STOP            = "Stop"
    RENEGOTIATE     = "Renegotiate"


class EnergyTransferModeList(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.4"""

    energy_modes: List[EnergyTransferModeEnum] = Field(
        ..., max_items=6, alias="EnergyTransferMode"
    )


class ServiceID(IntEnum):
    """Подробности в ISO 15118-2, глава 8.4.3.3.2"""

    CHARGING    = 1
    CERTIFICATE = 2
    INTERNET    = 3
    CUSTOM      = 4


class ServiceCategory(str, Enum):
    """Подробности в ISO 15118-2, глава 8.4.3.3.2"""

    CHARGING        = "EVCharging"
    CERTIFICATE     = "ContractCertificate"
    INTERNET        = "Internet"
    CUSTOM          = "OtherCustom"


class ServiceName(str, Enum):
    """Подробности в ISO 15118-2, глава 8.6.3.6"""

    CHARGING        = "AC_DC_Charging"
    CERTIFICATE     = "Certificate"
    INTERNET        = "InternetAccess"
    CUSTOM          = "UseCaseInformation"


class ServiceDetails(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.1"""

    # XSD unsignedShort (16 битное целое) диапазон [0..65535]
    service_id: ServiceID = Field(..., ge=0, le=65535, alias="ServiceID")
    service_name: Optional[ServiceName] = Field(None, max_length=32, alias="ServiceName")
    service_category: ServiceCategory = Field(..., alias="ServiceCategory")
    service_scope: Optional[str] = Field(None, max_length=64, alias="ServiceScope")
    free_service: bool = Field(..., alias="FreeService")


class ChargeService(ServiceDetails):
    """Подробности в ISO 15118-2, глава 8.5.2.3"""

    supported_energy_transfer_mode: EnergyTransferModeList = Field(
        ..., alias="SupportedEnergyTransferMode"
    )


class ProfileEntryDetails(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.11"""

    start: int = Field(..., alias="ChargingProfileEntryStart")
    max_power: PVPMax = Field(..., alias="ChargingProfileEntryMaxPower")
    # XSD byte диапазон [1..3]
    max_phases_in_use: Optional[int] = Field(
        None, ge=1, le=3, alias="ChargingProfileEntryMaxNumberOfPhasesInUse"
    )


class ChargingProfile(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.10"""

    profile_entries: List[ProfileEntryDetails] = Field(
        ..., max_items=24, alias="ProfileEntry"
    )


class ChargingSession(str, Enum):
    """Подробности в ISO 15118-2, глава 8.4.3.12.2"""

    TERMINATE   = "Terminate"
    PAUSE       = "Pause"


class CostKind(str, Enum):
    """Подробности в ISO 15118-2, глава 8.5.2.20"""

    RELATIVE_PRICE_PERCENTAGE       = "relativePricePercentage"
    RENEWABLE_GENERATION_PERCENTAGE = "RenewableGenerationPercentage"
    CARBON_DIOXIDE_EMISSION         = "CarbonDioxideEmission"


class Cost(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.20"""

    cost_kind: CostKind = Field(..., alias="costKind")
    amount: int = Field(..., alias="amount")
    # XSD byte диапазон [-3..3]
    amount_multiplier: Optional[int] = Field(None, ge=-3, le=3, alias="amountMultiplier")


class ConsumptionCost(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.19"""

    start_value: PVStartValue = Field(..., alias="startValue")
    cost: List[Cost] = Field(..., max_items=3, alias="Cost")


class EncryptedPrivateKey(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.28"""

    # 'Id' это атрибут XML, но в текущей JSON реализации нет этого атрибута.
    id: str = Field(..., alias="Id")
    value: bytes = Field(..., max_length=48, alias="value")

    def __str__(self):
        return "ContractSignatureEncryptedPrivateKey"


class DCEVStatus(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.4.2"""

    ev_ready: bool = Field(..., alias="EVReady")
    ev_error_code: DCEVErrorCode = Field(..., alias="EVErrorCode")
    # XSD byte диапазон [0..100]
    ev_ress_soc: int = Field(..., ge=0, le=100, alias="EVRESSSOC")


class DCEVChargeParameter(EVChargeParameter):
    """Подробности в ISO 15118-2, глава 8.5.4.3"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_maximum_current_limit: PVEVMaxCurrentLimit = Field(
        ..., alias="EVMaximumCurrentLimit"
    )
    ev_maximum_power_limit: Optional[PVEVMaxPowerLimit] = Field(None, alias="EVMaximumPowerLimit")
    ev_maximum_voltage_limit: PVEVMaxVoltageLimit = Field(
        ..., alias="EVMaximumVoltageLimit"
    )
    ev_energy_capacity: Optional[PVEVEnergyCapacity] = Field(None, alias="EVEnergyCapacity")
    ev_energy_request: Optional[PVEVEnergyRequest] = Field(None, alias="EVEnergyRequest")
    # XSD byte диапазон [0..100]
    full_soc: Optional[int] = Field(None, ge=0, le=100, alias="FullSOC")
    # XSD byte диапазон [0..100]
    bulk_soc: Optional[int] = Field(None, ge=0, le=100, alias="BulkSOC")


class DCEVPowerDeliveryParameter(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.4.5"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    bulk_charging_complete: Optional[bool] = Field(None, alias="BulkChargingComplete")
    charging_complete: bool = Field(..., alias="ChargingComplete")


class DHPublicKey(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.29"""

    id: str = Field(..., alias="Id")
    value: bytes = Field(..., max_length=65, alias="value")

    def __str__(self):
        return "DHpublickey"


class FaultCode(str, Enum):
    """Подробности в ISO 15118-2, глава 8.5.2.8"""

    PARSING_ERROR = "ParsingError"
    NO_TLS_ROOT_CERTIFICATE_AVAILABLE = "NoTLSRootCertificatAvailable"
    UNKNOWN_ERROR = "UnknownError"


class RootCertificateIDList(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.27"""

    x509_issuer_serials: List[X509IssuerSerial] = Field(
        ..., max_items=20, alias="RootCertificateID"
    )


class MeterInfo(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.27"""

    meter_id: str = Field(..., max_length=32, alias="MeterID")
    meter_reading: Optional[int] = Field(None, ge=0, le=999999999, alias="MeterReading")
    sig_meter_reading: Optional[bytes] = Field(None, max_length=64, alias="SigMeterReading")
    # XSD short (16 битное целое) диапазон [-32768..32767]
    meter_status: Optional[int] = Field(None, ge=INT_16_MIN, le=INT_16_MAX, alias="MeterStatus")
    # XSD short (16 битное целое) диапазон [-32768..32767].
    t_meter: Optional[int] = Field(None, alias="TMeter")


class Notification(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.8"""

    fault_code: FaultCode = Field(..., alias="FaultCode")
    fault_msg: Optional[str] = Field(None, max_length=64, alias="FaultMsg")

    def __str__(self):
        additional_info = f" ({self.fault_msg})" if self.fault_msg else ""
        return self.fault_code + additional_info


class Parameter(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.23"""

    # 'Name' это атрибут XML, но в текущей JSON реализации нет этого атрибута.
    name: str = Field(..., alias="Name")
    bool_value: Optional[bool] = Field(None, alias="boolValue")
    # XSD byte диапазон [-128..127]
    byte_value: Optional[int] = Field(None, ge=INT_8_MIN, le=INT_8_MAX, alias="byteValue")
    # XSD short (16 битное целое) диапазон [-32768..32767]
    short_value: Optional[int] = Field(None, ge=INT_16_MIN, le=INT_16_MAX, alias="shortValue")
    int_value: Optional[int] = Field(None, alias="intValue")
    physical_value: Optional[PhysicalValue] = Field(None, alias="physicalValue")
    str_value: Optional[str] = Field(None, alias="stringValue")

    @root_validator(pre=True)
    def at_least_one_parameter_value(cls, values):
        """
        Хотя бы один допустимый тип данных должен быть установлен
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "bool_value",
                "boolValue",
                "byte_value",
                "byteValue",
                "short_value",
                "shortValue",
                "int_value",
                "intValue",
                "physical_value",
                "physicalValue",
                "str_value",
                "stringValue",
            ],
            values,
            True,
        ):
            return values


class ParameterSet(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.22"""

    # XSD unsignedShort (16 битное целое) диапазон [0..65535]
    parameter_set_id: int = Field(..., ge=0, le=65535, alias="ParameterSetID")
    parameters: List[Parameter] = Field(..., max_items=16, alias="Parameter")


class AuthOptionList(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.9"""

    auth_options: List[AuthEnum] = Field(
        ..., min_items=1, max_items=2, alias="PaymentOption"
    )


class RelativeTimeInterval(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.18"""

    start: int = Field(..., ge=0, le=16777214, alias="start")
    duration: Optional[int] = Field(None, ge=0, le=86400, alias="duration")


class PMaxScheduleEntry(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.15"""

    p_max: PVPMax = Field(..., alias="PMax")
    time_interval: RelativeTimeInterval = Field(..., alias="RelativeTimeInterval")


class PMaxSchedule(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.14"""

    schedule_entries: List[PMaxScheduleEntry] = Field(
        ..., max_items=1024, alias="PMaxScheduleEntry"
    )


class ResponseCode(str, Enum):
    """Подробности в ISO 15118-2, страница 271"""

    OK                                  = "OK"
    OK_NEW_SESSION_ESTABLISHED          = "OK_NewSessionEstablished"
    OK_OLD_SESSION_JOINED               = "OK_OldSessionJoined"
    OK_CERTIFICATE_EXPIRES_SOON         = "OK_CertificateExpiresSoon"
    FAILED                              = "FAILED"
    FAILED_SEQUENCE_ERROR               = "FAILED_SequenceError"
    FAILED_SERVICE_ID_INVALID           = "FAILED_ServiceIDInvalid"
    FAILED_UNKNOWN_SESSION              = "FAILED_UnknownSession"
    FAILED_SERVICE_SELECTION_INVALID    = "FAILED_ServiceSelectionInvalid"
    FAILED_PAYMENT_SELECTION_INVALID    = "FAILED_PaymentSelectionInvalid"
    FAILED_CERTIFICATE_EXPIRED          = "FAILED_CertificateExpired"
    FAILED_SIGNATURE_ERROR              = "FAILED_SignatureError"
    FAILED_NO_CERTIFICATE_AVAILABLE     = "FAILED_NoCertificateAvailable"
    FAILED_CERT_CHAIN_ERROR             = "FAILED_CertChainError"
    FAILED_CHALLENGE_INVALID            = "FAILED_ChallengeInvalid"
    FAILED_CONTRACT_CANCELED            = "FAILED_ContractCanceled"
    FAILED_WRONG_CHARGE_PARAMETER       = "FAILED_WrongChargeParameter"
    FAILED_POWER_DELIVERY_NOT_APPLIED   = "FAILED_PowerDeliveryNotApplied"
    FAILED_TARIFF_SELECTION_INVALID     = "FAILED_TariffSelectionInvalid"
    FAILED_CHARGING_PROFILE_INVALID     = "FAILED_ChargingProfileInvalid"
    FAILED_METERING_SIGNATURE_NOT_VALID = "FAILED_MeteringSignatureNotValid"
    FAILED_NO_CHARGE_SERVICE_SELECTED   = "FAILED_NoChargeServiceSelected"
    FAILED_WRONG_ENERGY_TRANSFER_MODE   = "FAILED_WrongEnergyTransferMode"
    FAILED_CONTACTOR_ERROR              = "FAILED_ContactorError"
    FAILED_CERTIFICATE_NOT_ALLOWED_AT_THIS_EVSE = (
        "FAILED_CertificateNotAllowedAtThisEVSE"
    )
    FAILED_CERTIFICATE_REVOKED          = "FAILED_CertificateRevoked"


class ServiceList(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.2"""
    """Подробности в DIN SPEC 70121, глава 9.5.2.13"""

    services: List[ServiceDetails] = Field(..., max_items=8, alias="Service")


class ServiceParameterList(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.21"""

    parameter_set: List[ParameterSet] = Field(..., max_items=255, alias="ParameterSet")


class SalesTariffEntry(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.17"""

    # XSD unsignedByte диапазон [0..255]
    e_price_level: Optional[int] = Field(None, ge=0, le=255, alias="EPriceLevel")
    time_interval: RelativeTimeInterval = Field(..., alias="RelativeTimeInterval")
    consumption_cost: Optional[List[ConsumptionCost]] = Field(
        None, max_items=3, alias="ConsumptionCost"
    )

    @validator("consumption_cost")
    def at_least_one_cost_indicator(cls, value, values):
        """
        Либо e_price_leve, либо consumption_cost должно использоваться
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if not value and not values.get("e_price_level"):
            raise ValueError(
                "At least e_price_level or consumption_cost must "
                "be set, both cannot be optional."
            )
        return value


class SalesTariff(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.16"""

    id: Optional[str] = Field(None, alias="Id")
    # XSD unsignedByte диапазон [0 .. 255]
    sales_tariff_id: int = Field(..., ge=0, le=255, alias="SalesTariffID")
    sales_tariff_description: Optional[str] = Field(
        None, max_length=32, alias="SalesTariffDescription"
    )
    # XSD unsignedByte диапазон [0 .. 255]
    num_e_price_levels: Optional[int] = Field(None, ge=0, le=255, alias="NumEPriceLevels")
    sales_tariff_entry: List[SalesTariffEntry] = Field(
        ..., max_items=102, alias="SalesTariffEntry"
    )

    @validator("sales_tariff_entry")
    def check_num_e_price_levels(cls, value, values):
        """
        Если хотя бы одно поле sales_tariff_entry содержит e_price_level,
        то num_e_price_levels должно быть установлено соответственно суммарному количеству
        количество e_price_levels для всех элементов sales_tariff_entry.
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-
        e_price_levels = 0
        for sales_tariff_entry in value:
            if (
                "e_price_level" in sales_tariff_entry
                or sales_tariff_entry.e_price_level
            ):
                e_price_levels += 1

        if e_price_levels > 0 and "num_e_price_levels" not in values:
            raise ValueError(
                f"SalesTariff contains {e_price_levels} "
                "distinct e_price_level entries, but field "
                "'num_e_price_levels' is not provided."
            )

        return value

    @validator("sales_tariff_id")
    def sales_tariff_id_value_range(cls, value):
        """
        Проверка, что sales_tariff_id field в диапазоне [1..255].
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if not 1 <= value <= 255:
            raise ValueError(
                f"The value {value} is outside the allowed value "
                f"range [1..255] for SalesTariffID"
            )
        return value

    def __str__(self):
        # The XSD conform element name
        return type(self).__name__


class SAScheduleTuple(BaseModel):
    """Подробности в ISO 15118-2, глава 8.5.2.13"""

    # XSD unsignedByte диапазон [1 .. 255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    p_max_schedule: PMaxSchedule = Field(..., alias="PMaxSchedule")
    sales_tariff: Optional[SalesTariff] = Field(None, alias="SalesTariff")


class SAScheduleList(BaseModel):
    schedule_tuples: List[SAScheduleTuple] = Field(
        ..., max_items=3, alias="SAScheduleTuple"
    )


class EMAID(BaseModel):
    """
    Составной атрибут
    """
    # 'Id' это атрибут XML, но в текущей JSON реализации нет этого атрибута.
    id: str = Field(..., alias="Id")
    value: eMAID = Field(..., alias="value")

    def __str__(self):
        return "eMAID"
