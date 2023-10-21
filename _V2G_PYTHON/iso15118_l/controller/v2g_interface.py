
import logging
import math
import time
import asyncio

from ..Client_base import base
from ..Client_datalink import datalink

from typing import Dict, List, Optional, Union

from .interface import float2Value_Multiplier

from .interface import (
    EVChargeParamsLimits,
    EVDataContext,
    EVSEControllerInterface,
    ServiceStatus,
)

from ..shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    DCEVSEStatusCode,
)
from ..shared.messages.datatypes import EVSENotification as EVSENotificationV2
from ..shared.messages.datatypes import (
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEMinCurrentLimit,
    PVEVSEMinVoltageLimit,
    PVEVSEPeakCurrentRipple,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
)
# from ..shared.messages.din_spec.datatypes import (
#     PMaxScheduleEntry as PMaxScheduleEntryDINSPEC,
# )
# from ..shared.messages.din_spec.datatypes import (
#     PMaxScheduleEntryDetails as PMaxScheduleEntryDetailsDINSPEC,
# )
# from ..shared.messages.din_spec.datatypes import (
#     RelativeTimeInterval as RelativeTimeIntervalDINSPEC,
# )
# from ..shared.messages.din_spec.datatypes import (
#     SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
# )
from ..shared.messages.enums import (
    AuthorizationStatus,
    AuthorizationTokenType,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Protocol,
    SessionStopAction,
    UnitSymbol,
)
from ..shared.messages.iso15118_2.body import Body, CertificateInstallationRes

from ..shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from ..shared.messages.iso15118_2.datatypes import (
    PMaxSchedule,
    PMaxScheduleEntry,
    PVPMax,
    RelativeTimeInterval,
    SAScheduleTuple,
)

from ..OCPP.ocpp_template import ocpp_temp



logger = logging.getLogger(__name__)

class EVSEController(EVSEControllerInterface):
    """
    EVSE контроллер
    """
    @classmethod
    async def create(cls, config):
        """ Создание экземпляра контроллера """
        self = EVSEController()
        self.evseIsolationMonitoringActive = False
        self.ev_data_context = EVDataContext()
        self.config = config
        return self

    def reset_ev_data_context(self):
        self.ev_data_context = EVDataContext()
    
    # ============================================================================
    # |             Стандартные функции                                          |
    # ============================================================================
    async def set_status(self, status: ServiceStatus) -> None:
        ocpp_temp.v2g_status = status
        logger.debug(f"New Status: {status}")

    async def get_evse_id(self, protocol: Protocol) -> str:
        # if protocol == Protocol.DIN_SPEC_70121:
        #     #  To transform a string-based DIN SPEC 91286 EVSE ID to hexBinary
        #     #  representation and vice versa, the following conversion rules shall
        #     #  be used for each character and hex digit: '0' <--> 0x0, '1' <--> 0x1,
        #     #  '2' <--> 0x2, '3' <--> 0x3, '4' <--> 0x4, '5' <--> 0x5, '6' <--> 0x6,
        #     #  '7' <--> 0x7, '8' <--> 0x8, '9' <--> 0x9, '*' <--> 0xA,
        #     #  Unused <--> 0xB .. 0xF.
        #     # Example: The DIN SPEC 91286 EVSE ID “49*89*6360” is represented
        #     # as “0x49 0xA8 0x9A 0x63 0x60”.
        #     evse_id_din: str = EVEREST_CHARGER_STATE.EVSEID_DIN
        #     return evse_id_din
        # else:
        #evse_id: str = EVEREST_CHARGER_STATE.EVSEID
        evse_id: str = self.config.evse_id
        return evse_id

    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        return self.config.supported_transport_mode

    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationStatus:

        if id_token_type is AuthorizationTokenType.EXTERNAL:
            eim_auth_status = ocpp_temp.eim_auth_status
            if eim_auth_status is True:
                return AuthorizationStatus.ACCEPTED 
            else:
                return AuthorizationStatus.REJECTED
        # elif id_token_type is AuthorizationTokenType.EMAID:
        #     pnc_auth_status: str = EVEREST_CHARGER_STATE.auth_pnc_status
        #     certificate_status = EVEREST_CHARGER_STATE.auth_pnc_certificate_status
        #     if pnc_auth_status == "Accepted" and certificate_status in ['Ongoing', 'Accepted']:
        #         return AuthorizationStatus.ACCEPTED
        #     elif (pnc_auth_status == "Ongoing" and certificate_status == "Ongoing"):
        #         return AuthorizationStatus.ONGOING
        #     else:
        #         return AuthorizationStatus.REJECTED

    # async def get_sa_schedule_list_dinspec(
    #     self, max_schedule_entries: Optional[int], departure_time: int = 0
    # ) -> Optional[List[SAScheduleTupleEntryDINSPEC]]:
    #     """Overrides EVSEControllerInterface.get_sa_schedule_list_dinspec()."""
    #     sa_schedule_list: List[SAScheduleTupleEntryDINSPEC] = []
    #     entry_details = PMaxScheduleEntryDetailsDINSPEC(
    #         p_max=200, time_interval=RelativeTimeIntervalDINSPEC(start=0, duration=3600)
    #     )
    #     p_max_schedule_entries = [entry_details]
    #     pmax_schedule_entry = PMaxScheduleEntryDINSPEC(
    #         p_max_schedule_id=0, entry_details=p_max_schedule_entries
    #     )
    #     sa_schedule_tuple_entry = SAScheduleTupleEntryDINSPEC(
    #         sa_schedule_tuple_id=1,
    #         p_max_schedule=pmax_schedule_entry,
    #         sales_tariff=None,
    #     )
    #     sa_schedule_list.append(sa_schedule_tuple_entry)
    #     return sa_schedule_list

    async def get_sa_schedule_list(
        self,
        ev_charge_params_limits: EVChargeParamsLimits,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        sa_schedule_list: List[SAScheduleTuple] = []

        if departure_time == 0:
            # [V2G2-304] Если время до отправления не указанно, 
            # то по умолчанию устанавливается 24 часа.
            departure_time = 86400

        if(ocpp_temp.get_sa_schedule_list() == False):
            p_max_1 = PVPMax(multiplier=0, value=11000, unit=UnitSymbol.WATT)
            p_max_2 = PVPMax(multiplier=0, value=7000, unit=UnitSymbol.WATT)

            p_max_schedule_entry_1 = PMaxScheduleEntry(         # Создание "точек на графике" зарядки
                p_max=p_max_1, time_interval=RelativeTimeInterval(start=0)
            )
            p_max_schedule_entry_2 = PMaxScheduleEntry(     # Последний элемент расписания должен иметь "длительность"
                p_max=p_max_2,
                time_interval=RelativeTimeInterval(
                    start=math.floor(departure_time / 2),
                    duration=math.ceil(departure_time / 2),
                ),
            )

            p_max_schedule = PMaxSchedule(  # Расписания на основе ограничений
                schedule_entries=[p_max_schedule_entry_1, p_max_schedule_entry_2]
            )

            sa_schedule_tuple = SAScheduleTuple(
                sa_schedule_tuple_id=1,
                p_max_schedule=p_max_schedule,
            )

            sa_schedule_list.append(sa_schedule_tuple)

        return sa_schedule_list

    async def get_meter_info_v2(self) -> MeterInfoV2:   # Использует сертификаты
        return None
        # meter_id: str = "EVerest"
        # powermeter: dict = EVEREST_CHARGER_STATE.powermeter
        # meter_reading: int = int(powermeter["energy_Wh_import"]["total"])
        # t_meter_datetime = dateutil.parser.isoparse(powermeter["timestamp"])
        # if powermeter["meter_id"]:
        #     meter_id = str(powermeter["meter_id"])
        # return MeterInfoV2(
        #     meter_id=meter_id, t_meter=int(calendar.timegm(t_meter_datetime.timetuple())), meter_reading=meter_reading
        # )

    async def set_hlc_charging(self, is_ongoing: bool) -> None:
       ocpp_temp.hlc_charging = is_ongoing

    async def stop_charger(self) -> None:
        ocpp_temp.power_enable = False

    async def get_cp_state(self) -> CpState:
        state = await base.GetState()

        state_ = CpState.UNKNOWN
        if(state == "A"):
            state_ = CpState.A1
        if(state == "B"):
            state_ = CpState.B2
        if(state == "C"):
            state_ = CpState.C2
        if(state == "D"):
            state_ = CpState.D2
        if(state == "E"):
            state_ = CpState.E
        if(state == "F"):
            state_ = CpState.F

        return state_

    async def service_renegotiation_supported(self) -> bool:
        return ocpp_temp.service_renegotiation_supported

    async def is_contactor_closed(self) -> bool:
        startTime_ns: int = time.time_ns()
        timeout: int = 0
        PERFORMANCE_TIMEOUT: int = 4500
        while timeout < PERFORMANCE_TIMEOUT:
            return ocpp_temp.is_contactor_closed
            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)
        return False

    async def is_contactor_opened(self) -> bool:
        startTime_ns: int = time.time_ns()
        timeout: int = 0
        PERFORMANCE_TIMEOUT: int = 4500
        while timeout < PERFORMANCE_TIMEOUT:
            return ocpp_temp.is_contactor_opened
            timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
            await asyncio.sleep(0.001)
        return False

    async def get_receipt_required(self) -> bool:
        return ocpp_temp.get_receipt_required

    async def reset_evse_values(self):
        ocpp_temp.reset()
    
    async def get_evse_payment_options(self) -> list:
        return self.config.supported_auth_options

    async def is_free(self) -> bool:
        return ocpp_temp.is_free

    async def set_present_protocol_state(self, state_name: str):
        logger.debug(f"New protocol state: {state_name}")

    async def allow_cert_install_service(self) -> bool:
        return False
    
    # ============================================================================
    # |                          Функции для AC                                  |
    # ============================================================================

    # async def get_ac_evse_status(self) -> ACEVSEStatus:
    #     # Относится к ocpp_temp.stop_charging
    #     # if ocpp_temp.stop_charging is True:
    #     #     notification = EVSENotificationV2.STOP_CHARGING

    #     notification : EVSENotificationV2 = EVSENotificationV2.NONE
    #     return ACEVSEStatus(
    #         notification_max_delay=0,
    #         evse_notification=notification,
    #         rcd = False
    #     )

    # async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
    #     nominal_voltage_value, nominal_voltage_multiplier = float2Value_Multiplier(0)
    #     evse_nominal_voltage = PVEVSENominalVoltage(
    #         multiplier=nominal_voltage_multiplier, value=nominal_voltage_value, unit=UnitSymbol.VOLTAGE
    #     )
    #     max_current_value, max_current_multiplier = float2Value_Multiplier(0)
    #     evse_max_current = PVEVSEMaxCurrent(
    #         multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE
    #     )
    #     return ACEVSEChargeParameter(
    #         ac_evse_status=await self.get_ac_evse_status(),
    #         evse_nominal_voltage=evse_nominal_voltage,
    #         evse_max_current=evse_max_current,
    #     )

    # async def get_ac_evse_max_current(self) -> PVEVSEMaxCurrent:
    #     max_current_value, max_current_multiplier = float2Value_Multiplier(0)
    #     return PVEVSEMaxCurrent( multiplier=max_current_multiplier, value=max_current_value, unit=UnitSymbol.AMPERE)

    # ============================================================================
    # |                          Функции для DC                                  |
    # ============================================================================

    async def get_dc_evse_status(self) -> DCEVSEStatus:
        notification : EVSENotificationV2 = EVSENotificationV2.NONE
        if ocpp_temp.stop_charging is True:
            notification = EVSENotificationV2.STOP_CHARGING
        
        evse_isolation : IsolationLevel = ocpp_temp.isolation_status
        
        evse_status_code: DCEVSEStatusCode = DCEVSEStatusCode.EVSE_READY

        if ocpp_temp.utility_interrupt_event is True:
            evse_status_code = DCEVSEStatusCode.EVSE_UTILITY_INTERUPT_EVENT
        elif ocpp_temp.malfunction is True:
            evse_status_code = DCEVSEStatusCode.EVSE_MALFUNCTION
        elif ocpp_temp.emergencyShutdown is True:
            evse_status_code = DCEVSEStatusCode.EVSE_EMERGENCY_SHUTDOWN
        elif self.evseIsolationMonitoringActive is True:
            evse_status_code = DCEVSEStatusCode.EVSE_ISOLATION_MONITORING_ACTIVE
        elif ocpp_temp.stop_charging is True:
            evse_status_code = DCEVSEStatusCode.EVSE_SHUTDOWN

        return DCEVSEStatus(
            evse_notification=notification,
            notification_max_delay=0,
            evse_isolation_status=evse_isolation,
            evse_status_code=evse_status_code,
        )
		
    async def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:

        c_ripple_value, c_ripple_multiplier = float2Value_Multiplier(
            ocpp_temp.c_ripple_value
        )
        c_max_limit_value, c_max_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.c_max_limit_value
        )
        p_max_limit_value, p_max_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.p_max_limit_value
        )
        v_max_limit_value, v_max_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.v_max_limit_value
        )
        c_min_limit_value, c_min_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.c_min_limit_value
        )
        v_min_limit_value, v_min_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.v_min_limit_value
        )

        dcEVSEChargeParameter: DCEVSEChargeParameter = DCEVSEChargeParameter(
            dc_evse_status= await self.get_dc_evse_status(),
            evse_maximum_power_limit=PVEVSEMaxPowerLimit(
                multiplier=p_max_limit_multiplier, value=p_max_limit_value, unit="W"
            ),
            evse_maximum_current_limit=PVEVSEMaxCurrentLimit(
                multiplier=c_max_limit_multiplier, value=c_max_limit_value, unit="A"
            ),
            evse_maximum_voltage_limit=PVEVSEMaxVoltageLimit(
                multiplier=v_max_limit_multiplier, value=v_max_limit_value, unit="V"
            ),
            evse_minimum_current_limit=PVEVSEMinCurrentLimit(
                multiplier=c_min_limit_multiplier, value=c_min_limit_value, unit="A"
            ),
            evse_minimum_voltage_limit=PVEVSEMinVoltageLimit(
                multiplier=v_min_limit_multiplier, value=v_min_limit_value, unit="V"
            ),
            evse_peak_current_ripple=PVEVSEPeakCurrentRipple(
                multiplier=c_ripple_multiplier, value=c_ripple_value, unit="A"
            )
        )

        # if EVEREST_CHARGER_STATE.EVSECurrentRegulationTolerance is not None:
        #     current_reg_tol_value, current_reg_tol_multiplier = float2Value_Multiplier(
        #         EVEREST_CHARGER_STATE.EVSECurrentRegulationTolerance
        #     )
        #     dcEVSEChargeParameter.evse_current_regulation_tolerance = PVEVSECurrentRegulationTolerance(
        #         multiplier=current_reg_tol_multiplier, value=current_reg_tol_value, unit="A"
        #     )
        # if EVEREST_CHARGER_STATE.EVSEEnergyToBeDelivered is not None:
        #     energy_deliver_value, energy_deliver_multiplier = float2Value_Multiplier(
        #         EVEREST_CHARGER_STATE.EVSEEnergyToBeDelivered
        #     )
        #     dcEVSEChargeParameter.evse_energy_to_be_delivered = PVEVSEEnergyToBeDelivered(
        #         multiplier = energy_deliver_multiplier, value = energy_deliver_value, unit="Wh"
        #     )

        return dcEVSEChargeParameter

    async def get_evse_present_voltage(
        self, protocol: Protocol
    ) -> PVEVSEPresentVoltage:

        v_value, v_multiplier = float2Value_Multiplier(ocpp_temp.v_present)
        return PVEVSEPresentVoltage(multiplier=v_multiplier, value=v_value, unit="V")
    
    async def get_evse_present_current(
        self, protocol: Protocol
    ) -> PVEVSEPresentCurrent:
        
        c_value, c_multiplier =  float2Value_Multiplier(ocpp_temp.c_present)
        return PVEVSEPresentCurrent(multiplier=c_multiplier, value=c_value, unit="A")


    async def start_cable_check(self):
        ocpp_temp.start_cable_check()

    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        return ocpp_temp.isolation_status

    async def set_precharge(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        ocpp_temp.set_precharge(voltage,current)

    async def send_charging_command(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        ocpp_temp.send_charging_command(voltage,current)

    async def is_evse_current_limit_achieved(self) -> bool:
        if ocpp_temp.c_present >= ocpp_temp.c_max_limit_value:
            return True
        return False

    async def is_evse_voltage_limit_achieved(self) -> bool:
        if ocpp_temp.v_present >= ocpp_temp.v_max_limit_value:
            return True
        return False

    async def is_evse_power_limit_achieved(self) -> bool:
        presentPower:float =  ocpp_temp.v_present *  ocpp_temp.c_present
        if presentPower >= ocpp_temp.p_max_limit_value:
            return True
        return False

    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        v_max_limit_value, v_max_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.v_max_limit_value
        )
        return PVEVSEMaxVoltageLimit(multiplier=v_max_limit_multiplier, value=v_max_limit_value, unit="V")

    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        c_max_limit_value, c_max_limit_multiplier = float2Value_Multiplier(
            ocpp_temp.c_max_limit_value
        )
        return PVEVSEMaxCurrentLimit(multiplier=c_max_limit_multiplier, value=c_max_limit_value, unit="A")

    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        p_max_limit_value, p_max_limit_multiplier = float2Value_Multiplier(
           ocpp_temp.p_max_limit_value
        )
        return PVEVSEMaxPowerLimit(multiplier=p_max_limit_multiplier, value=p_max_limit_value, unit="W")

    async def setIsolationMonitoringActive(self, value: bool):
        self.evseIsolationMonitoringActive = value
    
    async def isCableCheckFinished(self) -> bool:
        return ocpp_temp.cable_check_finished

    # async def get_15118_ev_certificate(
    #     self, base64_encoded_cert_installation_req: str, namespace: str
    # ) -> str:
    #     """
    #     Overrides EVSEControllerInterface.get_15118_ev_certificate().
    #     # Here we simply mock the actions of the backend.
    #     # The code here is almost the same as what is done if USE_CPO_BACKEND
    #     # is set to False. Except that both the request and response is base64 encoded.
    #     """
    #     startTime_ns: int = time.time_ns()
    #     timeout: int = 0
    #     PERFORMANCE_TIMEOUT: int = 4500
    #     while timeout < PERFORMANCE_TIMEOUT:
    #         Response: dict = EVEREST_CHARGER_STATE.existream_status
    #         if Response:
    #             if Response["certificateAction"] == "Install":
    #                 if Response["status"] == "Accepted":
    #                     exiResponse: str = str(Response["exiResponse"])
    #                     return exiResponse
    #                 elif Response["status"] == "Failed":
    #                     raise Exception("The CSMS reported: Processing of the message was not successful")
    #             elif Response["certificateAction"] == "Update":
    #                 action: str = str(Response["certificateAction"])
    #                 raise Exception(f"The wrong message was generated by the backend: {action}")        
    #         timeout = (time.time_ns() - startTime_ns) / pow(10, 6)
    #         await asyncio.sleep(0.001)
    #     raise Exception("Timeout - The backend takes too long to generate the CertificateInstallationRes")

    async def update_data_link(self, action: SessionStopAction) -> None:
        await datalink.Terminate()
