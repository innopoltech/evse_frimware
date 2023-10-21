from typing import Optional
from ..shared.messages.datatypes import PVEVTargetVoltage, PVEVTargetCurrent
from ..controller.interface import ServiceStatus
from ..shared.messages.enums import IsolationLevel, Protocol, AuthEnum, EnergyTransferModeEnum

class OCPP_temp:
    # Статус V2G сессии
    v2g_status : ServiceStatus = ServiceStatus.STOPPING
    # Выбранный протокол для общения 
    ev_app_protocol : Protocol = Protocol.UNKNOWN
    # EVCCIDD полученный в запросе на установку сессии
    evccid : str = ""
    # Выбранный способ авторизации 
    selected_auth_option : Optional[AuthEnum] = None
    # Запрос на авторизацию по EIM
    require_auth_EIM : bool = False
    # Была произведена EIM
    eim_auth_status : bool = True
    # Запрошенный режим зарядки
    requested_energy_mode : EnergyTransferModeEnum = EnergyTransferModeEnum.DC_CORE
    # Состояние EV
    ev_status : Optional[dict] = None
    # Время до отправления EV
    departure_time : str = "" 
    # Инициализация завершена
    v2g_setup_finished : bool = False
    # Запрос на паузу
    dlink_pause : bool = False
    # Запрос на завершение сессии
    dlink_terminate : bool = False
    # Начало проверки кабеля
    start_cable_check : bool = False


    # Активно ли HCL-C 
    hlc_charging : bool = False
    # Разрешение на подачу электроэнергии 
    power_enable : bool = False
    # Допустимо ли "горячее переподключение"
    service_renegotiation_supported : bool = False
    # Замкнут ли контактор
    is_contactor_closed : bool = True
    # Размокнут ли контактор 
    is_contactor_opened : bool = False
    # Требуется ли принимать показания счетчиков
    get_receipt_required : bool = True
    # Бесплатная ли зарядка
    is_free : bool = False
    # Запрос на остановку зарядки
    stop_charging : bool = False 
    # Время до окончания зарядки
    ev_reamingTime : Optional[dict] = None
    # Параметры AC

                    # Параметры DC
    # Состояние DC зарядки
    dc_charging_complete : bool = False
    dc_bulk_charging_complete : bool = False
    # Целевые значения зарядки
    ev_targetvalues : Optional[dict] = None
    # Ограничения зарядки от EV
    ev_maxvalues : Optional[dict] = None
    # Емкость батареи EV 
    ev_energy_capacity : float = 0
    # Кол-во энергии запрашиваемое EV
    p_ev_energy_request : float = 0
    # Время до окончания полной зарядки
    full_soc : int = 0
    # Время до окончания частичной зарядки
    bulk_soc : int = 0
    # Зарядка постоянным током завершена
    current_demand_finished : bool = False
    # Зарядка постоянным током начата
    current_demand_started: bool = False
    # Запрос на размыкание контактов 
    dc_open_contactor : bool = False
    # Состояние изоляции 
    isolation_status =  IsolationLevel.VALID
    # Проверка кабеля завершена
    cable_check_finished : bool = True
    # Ошибки
    utility_interrupt_event : bool = False 
    malfunction             : bool = False 
    emergencyShutdown       : bool = False 
    # Параметры зарядки
    c_ripple_value      = 1
    c_max_limit_value   = 50
    p_max_limit_value   = 25000
    v_max_limit_value   = 500
    c_min_limit_value   = 0
    v_min_limit_value   = 50
    
    v_present           = 250
    c_present           = 5


    def __init__(self):
        pass

    def get_sa_schedule_list(self):     # Получить расписание зарядки
        return False
    
    def reset(self):                    # Переинициализация параметров OCPP
        pass

    def start_cable_check(self):         # Инициировать проверку кабеля
        pass
                                    # Инициировать процесс предварительной зарядки
    async def set_precharge(self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent):
        pass
                                    # Установить параметры зарядки на зарядное устройство
    async def send_charging_command(self, voltage: PVEVTargetVoltage, current: PVEVTargetCurrent):
        pass



ocpp_temp = OCPP_temp() # Единственный экземпляр класса OCPP_temp