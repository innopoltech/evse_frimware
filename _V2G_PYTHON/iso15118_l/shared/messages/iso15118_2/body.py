import logging
from abc import ABC
from typing import Optional, Tuple, Type

from pydantic import Field, root_validator, validator

from ....shared.exceptions import V2GMessageValidationError
from ....shared.messages import BaseModel
from ....shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    PVEVMaxCurrentLimit,
    PVEVMaxPowerLimit,
    PVEVMaxVoltageLimit,
    PVEVSEMaxCurrent,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
    PVRemainingTimeToBulkSOC,
    PVRemainingTimeToFullSOC,
    SelectedServiceList,
)
from ....shared.messages.enums import (
    AuthEnum,
    EnergyTransferModeEnum,
    EVSEProcessing,
)
from ....shared.messages.iso15118_2.datatypes import (
    EMAID,
    ACEVChargeParameter,
    ACEVSEChargeParameter,
    ACEVSEStatus,
    AuthOptionList,
    CertificateChain,
    ChargeProgress,
    ChargeService,
    ChargingProfile,
    ChargingSession,
    DCEVChargeParameter,
    DCEVPowerDeliveryParameter,
    DCEVStatus,
    DHPublicKey,
    EncryptedPrivateKey,
    MeterInfo,
    ResponseCode,
    RootCertificateIDList,
    SAScheduleList,
    ServiceCategory,
    ServiceList,
    ServiceParameterList,
    eMAID,
)
from ....shared.validators import one_field_must_be_set

logger = logging.getLogger(__name__)


class BodyBase(BaseModel, ABC):
    """
    Базовый класс для всех элементов тела V2GMessage Body. Используется для сообщения 
    от sessionSetupReq до SessionStopRes.

    Подробнее в ISO 15118-2 глава 8.3.4
    """
    def __str__(self):
        return type(self).__name__


class Response(BodyBase, ABC):
    """
    Базовый класс для всех ответных сообщений и их кодов ответа
    """

    response_code: ResponseCode = Field(..., alias="ResponseCode")


class AuthorizationReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.7.1"""

    # 'Id' это атрибут XML, но в текущей JSON реализации нет этого атрибута.
    id: str = Field(None, alias="Id")
    gen_challenge: Optional[bytes] = Field(
        None, min_length=16, max_length=16, alias="GenChallenge"
    )

    @root_validator(pre=True)
    def both_fields_set_or_unset(cls, values):
        """
        Если AuthorizationReq подписано, то оба поля (gen_challenge и id) должны существовать.
        Если AuthorizationReq не подписано, то оно должно быть пустым.
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        _id, gen_challenge = values.get("id"), values.get("gen_challenge")
        if (_id and not gen_challenge) or (not _id and gen_challenge):
            raise ValueError(
                "Fields 'id' and 'gen_challenge' must either both "
                "be set (digital signature in header) or unset "
                "(no digital signature in header)"
            )
        return values


class AuthorizationRes(Response):
    """Подробности в ISO 15118-2, глава  8.4.3.7.2"""

    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")


class CableCheckReq(BodyBase):
    """Подробности в ISO 15118-2, глава  8.4.5.2.2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")


class CableCheckRes(Response):
    """Подробности в ISO 15118-2, глава   8.4.5.2.3"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")


class CertificateInstallationReq(BodyBase):
    """Подробности в ISO 15118-2, глава   8.4.3.11.2"""

    id: str = Field(..., alias="Id")
    oem_provisioning_cert: bytes = Field(
        ..., max_length=800, alias="OEMProvisioningCert"
    )
    list_of_root_cert_ids: RootCertificateIDList = Field(
        ..., alias="ListOfRootCertificateIDs"
    )


class CertificateInstallationRes(Response):
    """Подробности в ISO 15118-2, глава   8.4.3.11.3"""

    cps_cert_chain: CertificateChain = Field(
        ..., alias="SAProvisioningCertificateChain"
    )
    contract_cert_chain: CertificateChain = Field(
        ..., alias="ContractSignatureCertChain"
    )
    encrypted_private_key: EncryptedPrivateKey = Field(
        ..., alias="ContractSignatureEncryptedPrivateKey"
    )
    dh_public_key: DHPublicKey = Field(..., alias="DHpublickey")
    emaid: EMAID = Field(..., alias="eMAID")


class CertificateUpdateReq(BodyBase):
    """Подробности в ISO 15118-2, глава   8.4.3.10.2"""

    id: str = Field(..., alias="Id")
    contract_cert_chain: CertificateChain = Field(
        ..., alias="ContractSignatureCertChain"
    )
    emaid: EMAID = Field(..., alias="eMAID")
    list_of_root_cert_ids: RootCertificateIDList = Field(
        ..., alias="ListOfRootCertificateIDs"
    )


class CertificateUpdateRes(Response):
    """Подробности в ISO 15118-2, глава  8.4.3.10.3"""

    cps_cert_chain: CertificateChain = Field(
        ..., alias="SAProvisioningCertificateChain"
    )
    contract_cert_chain: CertificateChain = Field(
        ..., alias="ContractSignatureCertChain"
    )
    encrypted_private_key: EncryptedPrivateKey = Field(
        ..., alias="ContractSignatureEncryptedPrivateKey"
    )
    dh_public_key: DHPublicKey = Field(..., alias="DHpublickey")
    emaid: EMAID = Field(..., alias="eMAID")
    # XSD short (16 битное целое) имеет диапазон [-32768..32767].
    # Но из негативных чисел разрешен только -1 .
    retry_counter: Optional[int] = Field(None, ge=-1, le=32767, alias="RetryCounter")


class ChargeParameterDiscoveryReq(BodyBase):
    """Подробности в ISO 15118-2, глава  8.4.3.8.2"""

    # XSD unsignedShort (16 битное целое) имеет диапазон [0..65535]
    max_entries_sa_schedule_tuple: Optional[int] = Field(
        None, ge=0, le=65535, alias="MaxEntriesSAScheduleTuple"
    )
    requested_energy_mode: EnergyTransferModeEnum = Field(
        ..., alias="RequestedEnergyTransferMode"
    )
    ac_ev_charge_parameter: Optional[ACEVChargeParameter] = Field(
        None, alias="AC_EVChargeParameter"
    )
    dc_ev_charge_parameter: Optional[DCEVChargeParameter] = Field(
        None, alias="DC_EVChargeParameter"
    )

    @root_validator(pre=True)
    def either_ac_or_dc_charge_params(cls, values):
        """
        Один из параметров (ac_ev_charge_parameter или dc_ev_charge_parameter) обязан быть установлен
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        if one_field_must_be_set(
            [
                "ac_ev_charge_parameter",
                "AC_EVChargeParameter",
                "dc_ev_charge_parameter",
                "DC_EVChargeParameter",
            ],
            values,
            True,
        ):
            return values

    @root_validator(skip_on_failure=True)
    def requested_energy_mode_must_match_charge_parameter(cls, values):
        """
        Проверка что используемый параметр соответствует режиму зарядки
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        requested_energy_mode, ac_params, dc_params = (
            values.get("requested_energy_mode"),
            values.get("ac_ev_charge_parameter"),
            values.get("dc_ev_charge_parameter"),
        )
        if ("AC_" in requested_energy_mode and dc_params) or (
            "DC_" in requested_energy_mode and ac_params
        ):
            raise V2GMessageValidationError(
                "[V2G2-477] Wrong charge parameters for requested energy "
                f"transfer mode {requested_energy_mode}",
                ResponseCode.FAILED_WRONG_CHARGE_PARAMETER,
                cls,
            )

        return values


class ChargeParameterDiscoveryRes(Response):
    """Подробности в ISO 15118-2, глава  8.4.3.8.3"""

    evse_processing: EVSEProcessing = Field(..., alias="EVSEProcessing")
    sa_schedule_list: Optional[SAScheduleList] = Field(None, alias="SAScheduleList")
    ac_charge_parameter: Optional[ACEVSEChargeParameter] = Field(
        None, alias="AC_EVSEChargeParameter"
    )
    dc_charge_parameter: Optional[DCEVSEChargeParameter] = Field(
        None, alias="DC_EVSEChargeParameter"
    )

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator(pre=True)
    # def either_ac_or_dc_charge_params(cls, values):
    #     """
    #     Either ac_charge_parameter or dc_charge_parameter must be set,
    #     depending on whether the chosen energy transfer mode is AC or DC.
    #
    #     Pydantic validators are "class methods",
    #     see https://pydantic-docs.helpmanual.io/usage/validators/
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     if one_field_must_be_set(['ac_charge_parameter',
    #                               'AC_EVSEChargeParameter',
    #                               'dc_charge_parameter',
    #                               'DC_EVSEChargeParameter'],
    #                              values,
    #                              True):
    #         return values

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator()
    # def schedule_must_be_set_if_processing_finished(cls, values):
    #     """
    #     Once the field evse_processing is set to EVSEProcessing.FINISHED, the
    #     fields sa_schedule_list and ac_charge_parameter must be set.
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     evse_processing, schedules, ac_charge_params, dc_charge_params = \
    #         values.get('evse_processing'), \
    #         values.get('sa_schedule_list'), \
    #         values.get('ac_charge_parameter'), \
    #         values.get('ac_charge_parameter')
    #     if evse_processing == EVSEProcessing.FINISHED and (
    #             not schedules or not (ac_charge_params or dc_charge_params)):
    #         raise ValueError("SECC set EVSEProcessing to 'FINISHED' but either"
    #                          "SAScheduleList or charge parameters are not set")
    #     return values


class ChargingStatusReq(BodyBase):
    """Подробности в ISO 15118-2, глава  8.4.4.2.2"""


class ChargingStatusRes(Response):
    """Подробности в ISO 15118-2, глава   8.4.4.2.3"""

    evse_id: str = Field(..., min_length=7, max_length=37, alias="EVSEID")
    # XSD unsignedByte - диапазон [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    evse_max_current: Optional[PVEVSEMaxCurrent] = Field(None, alias="EVSEMaxCurrent")
    meter_info: Optional[MeterInfo] = Field(None, alias="MeterInfo")
    receipt_required: Optional[bool] = Field(None, alias="ReceiptRequired")
    ac_evse_status: ACEVSEStatus = Field(..., alias="AC_EVSEStatus")


class CurrentDemandReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.5.4.2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_target_current: PVEVTargetCurrent = Field(..., alias="EVTargetCurrent")
    ev_max_voltage_limit: Optional[PVEVMaxVoltageLimit] = Field(
        None, alias="EVMaximumVoltageLimit"
    )
    ev_max_current_limit: Optional[PVEVMaxCurrentLimit] = Field(
        None, alias="EVMaximumCurrentLimit"
    )
    ev_max_power_limit: Optional[PVEVMaxPowerLimit] = Field(None, alias="EVMaximumPowerLimit")
    bulk_charging_complete: Optional[bool] = Field(None, alias="BulkChargingComplete")
    charging_complete: bool = Field(..., alias="ChargingComplete")
    remaining_time_to_full_soc: Optional[PVRemainingTimeToFullSOC] = Field(
        None, alias="RemainingTimeToFullSoC"
    )
    remaining_time_to_bulk_soc: Optional[PVRemainingTimeToBulkSOC] = Field(
        None, alias="RemainingTimeToBulkSoC"
    )
    ev_target_voltage: PVEVTargetVoltage = Field(..., alias="EVTargetVoltage")


class CurrentDemandRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.5.4.3"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltage = Field(..., alias="EVSEPresentVoltage")
    evse_present_current: PVEVSEPresentCurrent = Field(..., alias="EVSEPresentCurrent")
    evse_current_limit_achieved: bool = Field(..., alias="EVSECurrentLimitAchieved")
    evse_voltage_limit_achieved: bool = Field(..., alias="EVSEVoltageLimitAchieved")
    evse_power_limit_achieved: bool = Field(..., alias="EVSEPowerLimitAchieved")
    evse_max_voltage_limit: Optional[PVEVSEMaxVoltageLimit] = Field(
        None, alias="EVSEMaximumVoltageLimit"
    )
    evse_max_current_limit: Optional[PVEVSEMaxCurrentLimit] = Field(
        None, alias="EVSEMaximumCurrentLimit"
    )
    evse_max_power_limit: Optional[PVEVSEMaxPowerLimit] = Field(
        None, alias="EVSEMaximumPowerLimit"
    )

    # Примечание: В таблице 56 ошибочно отмечен как hexBinary
    evse_id: str = Field(..., min_length=7, max_length=37, alias="EVSEID")
    # XSD unsignedByte диапазон [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    meter_info: Optional[MeterInfo] = Field(None, alias="MeterInfo")
    receipt_required: Optional[bool] = Field(None, alias="ReceiptRequired")


class MeteringReceiptReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.13.2"""

    # 'Id' это атрибут XML, но в текущей JSON реализации нет этого атрибута.
    id: Optional[str] = Field(None, alias="Id")
    # XSD hexBinary кодирующий 8 байт как 16 шестнадцатеричных значений
    session_id: str = Field(..., max_length=16, alias="SessionID")
    # XSD unsignedByte диапазон [1..255]
    sa_schedule_tuple_id: Optional[int] = Field(None, ge=1, le=255, alias="SAScheduleTupleID")
    meter_info: MeterInfo = Field(..., alias="MeterInfo")

    @validator("session_id")
    def check_sessionid_is_hexbinary(cls, value):
        """
        Проверка, действительно ли session_id field это шестнадцатеричное представление 8 байт
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        try:
            int(value, 16)
            return value
        except ValueError as exc:
            raise ValueError(
                f"Invalid value '{value}' for SessionID (must be "
                f"hexadecimal representation of max 8 bytes)"
            ) from exc


class MeteringReceiptRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.13.3"""

    ac_evse_status: Optional[ACEVSEStatus] = Field(None, alias="AC_EVSEStatus")
    dc_evse_status: Optional[DCEVSEStatus] = Field(None, alias="DC_EVSEStatus")

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator(pre=True)
    # def either_ac_or_dc_status(cls, values):
    #     """
    #     Either ac_evse_status or ac_evse_status must be set,
    #     depending on whether the chosen energy transfer mode is AC or DC.
    #
    #     Pydantic validators are "class methods",
    #     see https://pydantic-docs.helpmanual.io/usage/validators/
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     if one_field_must_be_set(['ac_evse_status',
    #                               'AC_EVSEStatus',
    #                               'dc_evse_status',
    #                               'DC_EVSEStatus'],
    #                              values,
    #                              True):
    #         return values


class PaymentDetailsReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.6.2"""

    emaid: eMAID = Field(..., alias="eMAID")
    cert_chain: CertificateChain = Field(..., alias="ContractSignatureCertChain")


class PaymentDetailsRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.6.3"""

    gen_challenge: bytes = Field(
        ..., min_length=16, max_length=16, alias="GenChallenge"
    )
    evse_timestamp: int = Field(..., alias="EVSETimeStamp")


class PaymentServiceSelectionReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.5.2"""

    selected_auth_option: AuthEnum = Field(..., alias="SelectedPaymentOption")
    selected_service_list: SelectedServiceList = Field(..., alias="SelectedServiceList")


class PaymentServiceSelectionRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.5.3"""

class PowerDeliveryReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.9.2"""

    charge_progress: ChargeProgress = Field(..., alias="ChargeProgress")
    # XSD unsignedByte диапазон [1..255]
    sa_schedule_tuple_id: int = Field(..., ge=1, le=255, alias="SAScheduleTupleID")
    charging_profile: Optional[ChargingProfile] = Field(None, alias="ChargingProfile")
    dc_ev_power_delivery_parameter: Optional[DCEVPowerDeliveryParameter] = Field(
        None, alias="DC_EVPowerDeliveryParameter"
    )


class PowerDeliveryRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.9.3"""

    ac_evse_status: Optional[ACEVSEStatus] = Field(None, alias="AC_EVSEStatus")
    dc_evse_status: Optional[DCEVSEStatus] = Field(None, alias="DC_EVSEStatus")

    # TODO Reactivate the validator once you figured out how to deal with the
    #       failed_responses dict
    # @root_validator(pre=True)
    # def either_ac_or_dc_status(cls, values):
    #     """
    #     Either ac_evse_status or dc_evse_status must be set,
    #     depending on whether the chosen energy transfer mode is AC or DC.
    #
    #     Pydantic validators are "class methods",
    #     see https://pydantic-docs.helpmanual.io/usage/validators/
    #     """
    #     # pylint: disable=no-self-argument
    #     # pylint: disable=no-self-use
    #     if one_field_must_be_set(['ac_evse_status',
    #                               'AC_EVSEStatus',
    #                               'dc_evse_status',
    #                               'DC_EVSEStatus'],
    #                              values,
    #                              True):
    #         return values


class PreChargeReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.5.3.2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")
    ev_target_voltage: PVEVTargetVoltage = Field(..., alias="EVTargetVoltage")
    ev_target_current: PVEVTargetCurrent = Field(..., alias="EVTargetCurrent")


class PreChargeRes(Response):
    """Подробности в ISO 15118-2, глава  8.4.5.3.3"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltage = Field(..., alias="EVSEPresentVoltage")


class ServiceDetailReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.4.1"""

    # XSD  unsignedShort (16 битное целое) диапазон [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")


class ServiceDetailRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.4.2"""

    # XSD  unsignedShort (16 битное целое) диапазон [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")
    service_parameter_list: Optional[ServiceParameterList] = Field(
        None, alias="ServiceParameterList"
    )


class ServiceDiscoveryReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.3.2"""

    service_scope: Optional[str] = Field(None, max_length=64, alias="ServiceScope")
    service_category: Optional[ServiceCategory] = Field(None, alias="ServiceCategory")


class ServiceDiscoveryRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.3.3"""

    auth_option_list: AuthOptionList = Field(..., alias="PaymentOptionList")
    charge_service: ChargeService = Field(..., alias="ChargeService")
    service_list: Optional[ServiceList] = Field(None, alias="ServiceList")


class SessionSetupReq(BodyBase):
    """Подробности в ISO 15118-2, глава  8.4.3.2.1"""

    # XSD hexBinary кодирующее 8  байт как 12 шестнадцатеричных значений
    evcc_id: str = Field(..., max_length=12, alias="EVCCID")

    @validator("evcc_id")
    def check_sessionid_is_hexbinary(cls, value):
        """
        Проверка, действительно ли evcc_id это шестнадцатеричное представление 8 байт
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        try:
            int(value, 16)
            return value
        except ValueError as exc:
            raise ValueError(
                f"Invalid value '{value}' for EVCCID (must be "
                f"hexadecimal representation of max 6 bytes)"
            ) from exc


class SessionSetupRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.2.2"""

    evse_id: str = Field(..., min_length=7, max_length=37, alias="EVSEID")
    evse_timestamp: Optional[int] = Field(None, alias="EVSETimeStamp")


class SessionStopReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.3.12.2"""

    charging_session: ChargingSession = Field(..., alias="ChargingSession")


class SessionStopRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.3.12.3"""


class WeldingDetectionReq(BodyBase):
    """Подробности в ISO 15118-2, глава 8.4.5.5.2"""

    dc_ev_status: DCEVStatus = Field(..., alias="DC_EVStatus")


class WeldingDetectionRes(Response):
    """Подробности в ISO 15118-2, глава 8.4.5.5.3"""

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_present_voltage: PVEVSEPresentVoltage = Field(..., alias="EVSEPresentVoltage")


class Body(BaseModel):
    """
    Представляет собой элемент тела сообщения
    Подробности в ISO 15118-2, глава 8.3.4
    """

    session_setup_req: SessionSetupReq = Field(None, alias="SessionSetupReq")
    session_setup_res: SessionSetupRes = Field(None, alias="SessionSetupRes")
    service_discovery_req: ServiceDiscoveryReq = Field(
        None, alias="ServiceDiscoveryReq"
    )
    service_discovery_res: ServiceDiscoveryRes = Field(
        None, alias="ServiceDiscoveryRes"
    )
    service_detail_req: ServiceDetailReq = Field(None, alias="ServiceDetailReq")
    service_detail_res: ServiceDetailRes = Field(None, alias="ServiceDetailRes")
    payment_service_selection_req: PaymentServiceSelectionReq = Field(
        None, alias="PaymentServiceSelectionReq"
    )
    payment_service_selection_res: PaymentServiceSelectionRes = Field(
        None, alias="PaymentServiceSelectionRes"
    )
    certificate_installation_req: CertificateInstallationReq = Field(
        None, alias="CertificateInstallationReq"
    )
    certificate_installation_res: CertificateInstallationRes = Field(
        None, alias="CertificateInstallationRes"
    )
    certificate_update_req: CertificateUpdateReq = Field(
        None, alias="CertificateUpdateReq"
    )
    certificate_update_res: CertificateUpdateRes = Field(
        None, alias="CertificateUpdateRes"
    )
    payment_details_req: PaymentDetailsReq = Field(None, alias="PaymentDetailsReq")
    payment_details_res: PaymentDetailsRes = Field(None, alias="PaymentDetailsRes")
    authorization_req: AuthorizationReq = Field(None, alias="AuthorizationReq")
    authorization_res: AuthorizationRes = Field(None, alias="AuthorizationRes")
    cable_check_req: CableCheckReq = Field(None, alias="CableCheckReq")
    cable_check_res: CableCheckRes = Field(None, alias="CableCheckRes")
    pre_charge_req: PreChargeReq = Field(None, alias="PreChargeReq")
    pre_charge_res: PreChargeRes = Field(None, alias="PreChargeRes")
    charge_parameter_discovery_req: ChargeParameterDiscoveryReq = Field(
        None, alias="ChargeParameterDiscoveryReq"
    )
    charge_parameter_discovery_res: ChargeParameterDiscoveryRes = Field(
        None, alias="ChargeParameterDiscoveryRes"
    )
    power_delivery_req: PowerDeliveryReq = Field(None, alias="PowerDeliveryReq")
    power_delivery_res: PowerDeliveryRes = Field(None, alias="PowerDeliveryRes")
    charging_status_req: ChargingStatusReq = Field(None, alias="ChargingStatusReq")
    charging_status_res: ChargingStatusRes = Field(None, alias="ChargingStatusRes")
    current_demand_req: CurrentDemandReq = Field(None, alias="CurrentDemandReq")
    current_demand_res: CurrentDemandRes = Field(None, alias="CurrentDemandRes")
    metering_receipt_req: MeteringReceiptReq = Field(None, alias="MeteringReceiptReq")
    metering_receipt_res: MeteringReceiptRes = Field(None, alias="MeteringReceiptRes")
    welding_detection_req: WeldingDetectionReq = Field(
        None, alias="WeldingDetectionReq"
    )
    welding_detection_res: WeldingDetectionRes = Field(
        None, alias="WeldingDetectionRes"
    )
    session_stop_req: SessionStopReq = Field(None, alias="SessionStopReq")
    session_stop_res: SessionStopRes = Field(None, alias="SessionStopRes")

    def get_message_name(self) -> str:
        """ Возвращает имя V2GMessage, которое установлено в Body."""
        for k in self.__dict__.keys():
            if getattr(self, k):
                return str(getattr(self, k))

        return ""

    def get_message(self) -> Optional[BodyBase]:
        """ Возвращает V2GMessage, которое установлено в Body."""
        for k in self.__dict__.keys():
            if getattr(self, k):
                return getattr(self, k)

        return None

    def get_message_and_name(self) -> Tuple[Optional[BodyBase], str]:
        """Возвращает имя V2GMessage и V2GMessage, которое установлено в Body."""
        for k in self.__dict__.keys():
            if getattr(self, k):
                return getattr(self, k), str(getattr(self, k))

        return None, ""


def get_msg_type(msg_name: str) -> Optional[Type[BodyBase]]:
    """
    Возвращает тип сообщения по его имени
    """
    msg_dict = {
        "SessionSetupReq"               : SessionSetupReq,
        "SessionSetupRes"               : SessionSetupRes,
        "ServiceDiscoveryReq"           : ServiceDiscoveryReq,
        "ServiceDiscoveryRes"           : ServiceDiscoveryRes,
        "ServiceDetailReq"              : ServiceDetailReq,
        "ServiceDetailRes"              : ServiceDetailRes,
        "PaymentServiceSelectionReq"    : PaymentServiceSelectionReq,
        "PaymentServiceSelectionRes"    : PaymentServiceSelectionRes,
        "CertificateInstallationReq"    : CertificateInstallationReq,
        "CertificateInstallationRes"    : CertificateInstallationRes,
        "PaymentDetailsReq"             : PaymentDetailsReq,
        "PaymentDetailsRes"             : PaymentDetailsRes,
        "AuthorizationReq"              : AuthorizationReq,
        "AuthorizationRes"              : AuthorizationRes,
        "CableCheckReq"                 : CableCheckReq,
        "CableCheckRes"                 : CableCheckRes,
        "PreChargeReq"                  : PreChargeReq,
        "PreChargeRes"                  : PreChargeRes,
        "ChargeParameterDiscoveryReq"   : ChargeParameterDiscoveryReq,
        "ChargeParameterDiscoveryRes"   : ChargeParameterDiscoveryRes,
        "PowerDeliveryReq"              : PowerDeliveryReq,
        "PowerDeliveryRes"              : PowerDeliveryRes,
        "ChargingStatusReq"             : ChargingStatusReq,
        "ChargingStatusRes"             : ChargingStatusRes,
        "CurrentDemandReq"              : CurrentDemandReq,
        "CurrentDemandRes"              : CurrentDemandRes,
        "MeteringReceiptReq"            : MeteringReceiptReq,
        "MeteringReceiptRes"            : MeteringReceiptRes,
        "WeldingDetectionReq"           : WeldingDetectionReq,
        "WeldingDetectionRes"           : WeldingDetectionRes,
        "SessionStopReq"                : SessionStopReq,
        "SessionStopRes"                : SessionStopRes,
    }

    return msg_dict.get(msg_name, None)