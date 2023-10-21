from enum import Enum
from typing import List, Literal, Optional

from pydantic import Field, root_validator

from ...shared.settings import get_ignoring_value_range
import logging

from ...shared.messages import BaseModel
from ...shared.messages.enums import (
    INT_16_MAX,
    INT_16_MIN,
    IsolationLevel,
    UnitSymbol,
)

logger = logging.getLogger(__name__)

class PhysicalValue(BaseModel):
    """
    Все классы наследуемые от PhysicalValue начинаются с 'PV'
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Минимально допустимое значение фиксированно на 0, в  ISO 15118-2 нет отрицательных физических величин.
    """

    #_max_limit: int = 0
    # XSD int16 диапазон [-32768, 32767]
    value: int = Field(..., ge=INT_16_MIN, le=INT_16_MAX, alias="Value")
    # XSD byte диапазон [-3..3]
    multiplier: int = Field(..., ge=-3, le=3, alias="Multiplier")

    @root_validator(skip_on_failure = True)
    def validate_value_range(cls, values):
        value = values.get("value")
        multiplier = values.get("multiplier")
        calculated_value = value * 10**multiplier
        if calculated_value > cls._max_limit.default or calculated_value < 0:
        # if calculated_value > cls._max_limit or calculated_value < 0:
            message: str = (
                f"{cls.__name__[2:]} value limit exceeded: {calculated_value} \n"
                f"Max: {cls._max_limit} \n"
                f"Min: 0"
            )
            if get_ignoring_value_range():
                logger.warning(message)
            else:
                raise ValueError(message)
        return values

    def get_decimal_value(self) -> float:
        return self.value * 10**self.multiplier


class PVChargingProfileEntryMaxPower(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVEAmount(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVEnergyCapacity(PhysicalValue):
    """
     Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVEnergyRequest(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVMaxCurrent(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)
    """

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVMaxCurrentLimit(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVMaxPowerLimit(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVEVMaxVoltage(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVMaxVoltageLimit(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVMinCurrent(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSECurrentRegulationTolerance(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEEnergyToBeDelivered(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT_HOURS] = Field(..., alias="Unit")


class PVEVSEMaxCurrent(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7"""
    """Подробнее в DIN SPEC 70121, глава 9.5.2.4"""
    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEMaxCurrentLimit(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEMaxPowerLimit(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)

    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVEVSEMaxVoltageLimit(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVSENominalVoltage(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVSEMinCurrentLimit(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEMinVoltageLimit(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVSEPeakCurrentRipple(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEPresentCurrent(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVSEPresentVoltage(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVEVTargetCurrent(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 400
    unit: Literal[UnitSymbol.AMPERE] = Field(..., alias="Unit")


class PVEVTargetVoltage(PhysicalValue):
    """Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)"""

    _max_limit: int = 1000
    unit: Literal[UnitSymbol.VOLTAGE] = Field(..., alias="Unit")


class PVPMax(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)
    Максимальное значение ограничено 200000
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


class PVRemainingTimeToBulkSOC(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)
    Максимальное значение ограничено 172800
    """

    _max_limit: int = 172800
    unit: Literal[UnitSymbol.SECONDS] = Field(..., alias="Unit")


class PVRemainingTimeToFullSOC(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)
    Максимальное значение ограничено 172800
    """

    _max_limit: int = 172800
    unit: Literal[UnitSymbol.SECONDS] = Field(..., alias="Unit")


class PVStartValue(PhysicalValue):
    """
    Подробнее в ISO 15118-2, глава 8.5.2.7 (таблица 68)
    Максимальное значение ограничено 172800
    """

    _max_limit: int = 200000
    unit: Literal[UnitSymbol.WATT] = Field(..., alias="Unit")


# class PVEVEnergyCapacityDin(PVEVEnergyCapacity):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Optional[Literal[UnitSymbol.WATT_HOURS]] = Field(None, alias="Unit")


# class PVEVEnergyRequestDin(PVEVEnergyRequest):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.WATT_HOURS] = Field(None, alias="Unit")


# class PVEVMaxCurrentLimitDin(PVEVMaxCurrentLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVMaxPowerLimitDin(PVEVMaxPowerLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.WATT] = Field(None, alias="Unit")


# class PVEVMaxVoltageLimitDin(PVEVMaxVoltageLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.VOLTAGE] = Field(None, alias="Unit")


# class PVEVSECurrentRegulationToleranceDin(PVEVSECurrentRegulationTolerance):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVSEEnergyToBeDeliveredDin(PVEVSEEnergyToBeDelivered):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.WATT_HOURS] = Field(None, alias="Unit")


# class PVEVSEMaxCurrentLimitDin(PVEVSEMaxCurrentLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVSEMaxPowerLimitDin(PVEVSEMaxPowerLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.WATT] = Field(None, alias="Unit")


# class PVEVSEMaxVoltageLimitDin(PVEVSEMaxVoltageLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.VOLTAGE] = Field(None, alias="Unit")


# class PVEVSEMinCurrentLimitDin(PVEVSEMinCurrentLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVSEMinVoltageLimitDin(PVEVSEMinVoltageLimit):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.VOLTAGE] = Field(None, alias="Unit")


# class PVEVSEPeakCurrentRippleDin(PVEVSEPeakCurrentRipple):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVSEPresentCurrentDin(PVEVSEPresentCurrent):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVSEPresentVoltageDin(PVEVSEPresentVoltage):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.VOLTAGE] = Field(None, alias="Unit")


# class PVEVTargetCurrentDin(PVEVTargetCurrent):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.AMPERE] = Field(None, alias="Unit")


# class PVEVTargetVoltageDin(PVEVTargetVoltage):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.VOLTAGE] = Field(None, alias="Unit")


# class PVRemainingTimeToFullSOCDin(PVRemainingTimeToFullSOC):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.SECONDS] = Field(None, alias="Unit")


# class PVRemainingTimeToBulkSOCDin(PVRemainingTimeToBulkSOC):
#     """
#     See section 9.5.2.4 in DIN SPEC 70121

#     In DIN the Element unit is optional, in ISO it is mandatory.
#     """

#     unit: Literal[UnitSymbol.SECONDS] = Field(None, alias="Unit")


class DCEVChargeParams(BaseModel):
    dc_max_current_limit: PVEVMaxCurrentLimit
    dc_max_power_limit: PVEVMaxPowerLimit
    dc_max_voltage_limit: PVEVMaxVoltageLimit
    dc_energy_capacity: PVEVEnergyCapacity
    dc_target_current: PVEVTargetCurrent
    dc_target_voltage: PVEVTargetVoltage


class DCEVSEStatusCode(str, Enum):
    """Подробнее в ISO 15118-2, глава 8.5.4.1"""

    EVSE_NOT_READY                      = "EVSE_NotReady"
    EVSE_READY                          = "EVSE_Ready"
    EVSE_SHUTDOWN                       = "EVSE_Shutdown"
    EVSE_UTILITY_INTERUPT_EVENT         = "EVSE_UtilityInterruptEvent"
    EVSE_ISOLATION_MONITORING_ACTIVE    = "EVSE_IsolationMonitoringActive"
    EVSE_EMERGENCY_SHUTDOWN             = "EVSE_EmergencyShutdown"
    EVSE_MALFUNCTION                    = "EVSE_Malfunction"
    RESERVED_8 = "Reserved_8"
    RESERVED_9 = "Reserved_9"
    RESERVED_A = "Reserved_A"
    RESERVED_B = "Reserved_B"
    RESERVED_C = "Reserved_C"


class EVSENotification(str, Enum):
    """Подробнее в ISO 15118-2, глава 8.5.4.1 и 8.5.3.1"""

    NONE            = "None"
    STOP_CHARGING   = "StopCharging"
    RE_NEGOTIATION  = "ReNegotiation"


class EVSEStatus(BaseModel):
    """Подробнее в ISO 15118-2, глава 8.5.4.1 и 8.5.3.1"""

    # XSD unsignedShort (16 битное целое) диапазон [0..65535]
    notification_max_delay: int = Field(
        ..., ge=0, le=65535, alias="NotificationMaxDelay"
    )
    evse_notification: EVSENotification = Field(..., alias="EVSENotification")


class DCEVSEStatus(EVSEStatus):
    """Подробнее в ISO 15118-2, глава 8.5.4.1"""

    evse_isolation_status: Optional[IsolationLevel] = Field(None, alias="EVSEIsolationStatus")
    evse_status_code: DCEVSEStatusCode = Field(..., alias="EVSEStatusCode")


class DCEVSEChargeParameter(BaseModel):
    """Подробнее в ISO 15118-2, глава 8.5.4.4 """

    dc_evse_status: DCEVSEStatus = Field(..., alias="DC_EVSEStatus")
    evse_maximum_current_limit: PVEVSEMaxCurrentLimit = Field(
        ..., alias="EVSEMaximumCurrentLimit"
    )
    evse_maximum_power_limit: PVEVSEMaxPowerLimit = Field(
        ..., alias="EVSEMaximumPowerLimit"
    )
    evse_maximum_voltage_limit: PVEVSEMaxVoltageLimit = Field(
        ..., alias="EVSEMaximumVoltageLimit"
    )
    evse_minimum_current_limit: PVEVSEMinCurrentLimit = Field(
        ..., alias="EVSEMinimumCurrentLimit"
    )
    evse_minimum_voltage_limit: PVEVSEMinVoltageLimit = Field(
        ..., alias="EVSEMinimumVoltageLimit"
    )
    evse_current_regulation_tolerance: Optional[PVEVSECurrentRegulationTolerance] = Field(
        None, alias="EVSECurrentRegulationTolerance"
    )
    evse_peak_current_ripple: PVEVSEPeakCurrentRipple = Field(
        ..., alias="EVSEPeakCurrentRipple"
    )
    evse_energy_to_be_delivered: Optional[PVEVSEEnergyToBeDelivered] = Field(
        None, alias="EVSEEnergyToBeDelivered"
    )


class SelectedService(BaseModel):
    """Подробнее в DIN SPEC 70121, глава 9.5.2.14 """
    """Подробнее в ISO 15118-2, глава 8.5.2.25 """

    # XSD unsignedShort (16 битное целое) диапазон [0..65535]
    service_id: int = Field(..., ge=0, le=65535, alias="ServiceID")
    # XSD unsignedShort (16 битное целое) диапазон [0..65535]
    parameter_set_id: Optional[int]= Field(None, ge=0, le=65535, alias="ParameterSetID")


class SelectedServiceList(BaseModel):
    """Подробнее в DIN SPEC 70121, глава 9.5.2.13 """
    """Подробнее в ISO 15118-2, глава 8.5.2.24 """
    
    selected_service: List[SelectedService] = Field(
        ..., max_items=16, alias="SelectedService"
    )
