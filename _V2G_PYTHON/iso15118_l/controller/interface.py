from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Union

from ..shared.messages.datatypes import (
    DCEVSEChargeParameter,
    DCEVSEStatus,
    PVEAmount,
    PVEVEnergyRequest,
    PVEVMaxCurrent,
    PVEVMaxCurrentLimit,
    PVEVMaxVoltage,
    PVEVMaxVoltageLimit,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxPowerLimit,
    PVEVSEMaxVoltageLimit,
    PVEVSEPresentCurrent,
    PVEVSEPresentVoltage,
    PVEVTargetCurrent,
    PVEVTargetVoltage,
)
# from ..shared.messages.din_spec.datatypes import (
#     SAScheduleTupleEntry as SAScheduleTupleEntryDINSPEC,
# )
from ..shared.messages.enums import (
    AuthEnum,
    AuthorizationStatus,
    AuthorizationTokenType,
    CpState,
    EnergyTransferModeEnum,
    IsolationLevel,
    Protocol,
    SessionStopAction,
)
from ..shared.messages.iso15118_2.datatypes import (
    # ACEVSEChargeParameter,
    # ACEVSEStatus,
    ChargeService,
)
from ..shared.messages.iso15118_2.datatypes import MeterInfo as MeterInfoV2
from ..shared.messages.iso15118_2.datatypes import SAScheduleTuple

def float2Value_Multiplier(value:float):
    """ Вспомогательная функция перевода """
    INT_16_MAX = 2**15 - 1
    p_value     : int = 0
    p_multiplier: int = 0
    exponent    : int = 0

    # Проверка на float
    if (value - int(value)) != 0:
        exponent = 2

    for x in range(exponent, -4, -1):
        if (value * pow(10, x)) < INT_16_MAX:
            exponent = x
            break

    p_multiplier = int(-exponent)
    p_value = int(value * pow(10, exponent))

    return p_value, p_multiplier

@dataclass
class EVDataContext:
    """ Данные от EV"""
    dc_current: Optional[float]     = None
    dc_voltage: Optional[float]     = None
    ac_current: Optional[dict]      = None       # {"l1": 10, "l2": 10, "l3": 10}
    ac_voltage: Optional[dict]      = None       # {"l1": 230, "l2": 230, "l3": 230}
    soc: Optional[int]              = None       # 0-100

    departure_time: Optional[int]       = None
    ev_target_energy_request: float     = 0.0
    ev_max_energy_request: float        = 0.0
    ev_min_energy_request: float        = 0.0

    ev_max_charge_power: float                      = 0.0
    ev_max_charge_power_l2: Optional[float]         = None
    ev_max_charge_power_l3: Optional[float]         = None
    ev_min_charge_power: float                      = 0.0
    ev_min_charge_power_l2: Optional[float]         = None
    ev_min_charge_power_l3: Optional[float]         = None
    ev_present_active_power: float                  = 0.0
    ev_present_active_power_l2: Optional[float]     = None
    ev_present_active_power_l3: Optional[float]     = None
    ev_present_reactive_power: float                = 0.0
    ev_present_reactive_power_l2: Optional[float]   = None
    ev_present_reactive_power_l3: Optional[float]   = None

    # BPT values
    ev_max_discharge_power: float               = 0.0
    ev_max_discharge_power_l2: Optional[float]  = None
    ev_max_discharge_power_l3: Optional[float]  = None
    ev_min_discharge_power: float               = 0.0
    ev_min_discharge_power_l2: Optional[float]  = None
    ev_min_discharge_power_l3: Optional[float]  = None
    ev_max_v2x_energy_request: Optional[float]  = None
    ev_min_v2x_energy_request: Optional[float]  = None

    def update(self, new: dict):
        self.__dict__.update(new)

    def as_dict(self):
        return self.__dict__


class ServiceStatus(str, Enum):
    """ Перечень состояний для V2G цикла связи"""
    READY       = "ready"
    STARTING    = "starting"
    STOPPING    = "stopping"
    ERROR       = "error"
    BUSY        = "busy"


@dataclass
class EVChargeParamsLimits:
    """ Параметры зарядки, предоставляемые EV"""
    ev_max_voltage      : Optional[Union[PVEVMaxVoltageLimit, PVEVMaxVoltage]] = None
    ev_max_current      : Optional[Union[PVEVMaxCurrentLimit, PVEVMaxCurrent]] = None
    e_amount            : Optional[PVEAmount]         = None
    ev_energy_request   : Optional[PVEVEnergyRequest] = None

@dataclass
class EVSessionContext:
    """ Контекст сессии между EV и EVSE,
    необходим для возможности восстановление сессии после паузы """
    session_id          : Optional[str] = None
    auth_options        : Optional[List[AuthEnum]] = None
    charge_service      : Optional[ChargeService] = None
    sa_schedule_tuple_id: Optional[int] = None

class EVSEControllerInterface(ABC):
    """ Интерфейс для связи V2G цикла с другими сервисами"""
    def __init__(self):
        self.ev_data_context = EVDataContext()
        self._selected_protocol = Optional[Protocol]

    def reset_ev_data_context(self):
        self.ev_data_context = EVDataContext()

    def get_ev_data_context(self) -> EVDataContext:
        return self.ev_data_context

    # ============================================================================
    # |             Стандартные функции                                          |
    # ============================================================================

    @abstractmethod
    async def set_status(self, status: ServiceStatus) -> None:
        """
        Установка нового состояния V2G цикла общения
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_id(self, protocol: Protocol) -> str:
        """
        Получить EVSE ID

        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def get_supported_energy_transfer_modes(
        self, protocol: Protocol
    ) -> List[EnergyTransferModeEnum]:
        """
        Получить допустимые EVSE режимы зарядки

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def is_authorized(
        self,
        id_token: Optional[str] = None,
        id_token_type: Optional[AuthorizationTokenType] = None,
        certificate_chain: Optional[bytes] = None,
        hash_data: Optional[List[Dict[str, str]]] = None,
    ) -> AuthorizationStatus:
        """
        Была ли произведена аутентификация в целом

        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def get_sa_schedule_list(
        self,
        ev_charge_params_limits: EVChargeParamsLimits,
        max_schedule_entries: Optional[int],
        departure_time: int = 0,
    ) -> Optional[List[SAScheduleTuple]]:
        """
        Запрашивает расписание зарядки у сервера, если такового не предоставляется, 
        то зарядка происходит на основе ограничений (EV и EVSE).

        Входящие аргументы:
            ev_charge_params_limits : ограничения по току, напряжению и запрашиваемое кол-во энергии.
            max_schedule_entries    : максимальное кол-во элементов в расписании.
            departure_time          : время до отправления EV, если не предоставляетсяЮ то начать зарядку немедленно.

        Возвращает:
            Расписание зарядки.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    # @abstractmethod
    # async def get_sa_schedule_list_dinspec(
    #     self, max_schedule_entries: Optional[int], departure_time: int = 0
    # ) -> Optional[List[SAScheduleTupleEntryDINSPEC]]:
    #     """
    #     Requests the charging schedule from a secondary actor (SA) like a
    #     charge point operator, if available. If no backend information is given
    #     regarding the restrictions imposed on an EV charging profile, then the
    #     charging schedule is solely influenced by the max rating of the charger
    #     and the ampacity of the charging cable.

    #     Args:
    #         max_schedule_entries: The maximum amount of schedule entries the EVCC
    #                               can handle, or None if not provided
    #         departure_time: The departure time given in seconds from the time of
    #                         sending the ChargeParameterDiscoveryReq. If the
    #                         request doesn't provide a departure time, then this
    #                         implies the need to start charging immediately.

    #     Returns:
    #         A list of SAScheduleTupleEntry values to influence the EV's charging profile
    #         if the backend/charger can provide the information already, or None if
    #         the calculation is still ongoing.

    #     Relevant for:
    #     - ISO 15118-2
    #     """
    #     raise NotImplementedError

    @abstractmethod
    async def get_meter_info_v2(self) -> MeterInfoV2:
        """
        Получение показания счетчиков EVSE

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def set_hlc_charging(self, is_ongoing: bool) -> None:
        """
        Уведомления о состоянии общения по HLC.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_cp_state(self) -> CpState:
        """
        Получить состояние CP

        Относится к:
        - IEC 61851-1
        """
        raise NotImplementedError

    @abstractmethod
    async def stop_charger(self) -> None:
        """ Остановить зарядку """
        raise NotImplementedError

    @abstractmethod
    async def is_contactor_opened(self) -> bool:
        """
        Получение состояния контактора

        Относится к:
        - любому протоколу
        """
        raise NotImplementedError

    @abstractmethod
    async def is_contactor_closed(self) -> bool:
        """
        Получение состояния контактора

        Относится к:
        - любому протоколу
        """
        raise NotImplementedError

    @abstractmethod
    async def set_present_protocol_state(self, state_name: str):
        """
        Отображает текущее состояние машины состояний

        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        """
        raise NotImplementedError

    def set_selected_protocol(self, protocol: Protocol) -> None:
        """ Установка выбранного протокола """
        self._selected_protocol = protocol

    def get_selected_protocol(self) -> Protocol:
        """ Получение установленного протокола"""
        return self._selected_protocol

    # ============================================================================
    # |                          Функции для AC                                  |
    # ============================================================================

    # @abstractmethod
    # async def get_ac_evse_status(self) -> ACEVSEStatus:
    #     """
    #     Получение специфичного для AC статуса EVSE

    #     Относится к:
    #     - ISO 15118-2
    #     """
    #     raise NotImplementedError

    # @abstractmethod
    # async def get_ac_charge_params_v2(self) -> ACEVSEChargeParameter:
    #     """
    #     Получение специфичных параметров для AC статуса EVSE (для ChargeParameterDiscoveryRes)

    #      Относится к:
    #     - ISO 15118-2
    #     """
    #     raise NotImplementedError

    # ============================================================================
    # |                          Функции для DC                                  |
    # ============================================================================

    @abstractmethod
    async def get_dc_evse_status(self) -> DCEVSEStatus:
        """
        Получение специфичного для DC статуса EVSE

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_dc_evse_charge_parameter(self) -> DCEVSEChargeParameter:
        """
        Получение специфичных параметров для DC статуса EVSE (для ChargeParameterDiscoveryRes)

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_present_voltage(
        self, protocol: Protocol
    ) -> PVEVSEPresentVoltage:
        """
        Получить текущее напряжение EVSE

        Относится к:
        - ISO 15118-2
        - ISO 15118-20
        - DINSPEC
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_present_current(
        self, protocol: Protocol
    ) ->  PVEVSEPresentCurrent:
        """
        Получить текущую силу тока EVSE

        Относится к:
        - ISO 15118-2
        - ISO 15118-20
        - DINSPEC
        """
        raise NotImplementedError

    @abstractmethod
    async def set_precharge(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        """
        Устанавливает параметры для предварительной зарядки.
        Зарядное устройство должно адаптировать свое напряжение к запрашиваемому EV.
        Ток не должен превышать 2A (61851-23)

        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def start_cable_check(self):
        """
        Запрос на выполнение проверки кабеля (CableCheck)

        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def get_cable_check_status(self) -> Union[IsolationLevel, None]:
        """
        Проверка  состояния кабеля, на основе проверки от прошлого запроса.
        
        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        - ISO 15118-20
        """
        raise NotImplementedError

    @abstractmethod
    async def send_charging_command(
        self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent
    ):
        """
        Устанавливает целевые параметры напряжения и силы тока, необходимые для процесса зарядки.

        Относится к:
        - DIN SPEC 70121
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def is_evse_current_limit_achieved(self) -> bool:
        """
        Достигнуто ли ограничение по току.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def is_evse_voltage_limit_achieved(self) -> bool:
        """
        Достигнуто ли ограничение по напряжению.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def is_evse_power_limit_achieved(self) -> bool:
        """
        Достигнуто ли ограничение по мощности

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_max_voltage_limit(self) -> PVEVSEMaxVoltageLimit:
        """
        Получить максимально допустимое напряжение.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_max_current_limit(self) -> PVEVSEMaxCurrentLimit:
        """
        Получить максимально допустимую силу тока.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    @abstractmethod
    async def get_evse_max_power_limit(self) -> PVEVSEMaxPowerLimit:
        """
        Получить максимально допустимую мощность.

        Относится к:
        - ISO 15118-2
        """
        raise NotImplementedError

    # @abstractmethod
    # async def get_15118_ev_certificate(
    #     self, base64_encoded_cert_installation_req: str, namespace: str
    # ) -> str:
    #     """
    #     Used to fetch base64 encoded CertificateInstallationRes from CPO backend.
    #     Args:
    #      base64_encoded_cert_installation_req : This is the CertificateInstallationReq
    #      from the EV in base64 encoded form.
    #      namespace: This would be the namespace to be passed to the backend and depends
    #       on the protocol.
    #      15118-2:  "urn:iso:15118:2:2013:MsgDef"
    #      15118-20: "urn:iso:std:iso:15118:-20:CommonMessages"
    #     Returns:
    #      CertificateInstallationRes EXI stream in base64 encoded form.

    #     Relevant for:
    #     - ISO 15118-20 and ISO 15118-2
    #     """
    #     raise NotImplementedError

    @abstractmethod
    async def update_data_link(self, action: SessionStopAction) -> None:
        """
        Обновить состояние канального уровня

        Относится к:
        - ISO 15118-20 и ISO 15118-2
        """
        raise NotImplementedError
