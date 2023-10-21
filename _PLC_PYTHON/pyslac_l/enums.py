from enum import Enum

# [V2G3-M06-05]- Для случая, когда ШИМ=5% и процесс сопряжения не был запущен, если EVSE
# захочет выставить ШИМ=номинальному зарядному току, то он должен сделать это
# через последовательность B или C (5 %) -> E или F -> B (номинальный ток) для обратной совместимости.
# Минимальной время в состоянии E или F - T_step_EF.

# [V2G3-M06-06] Для случая, когда ШИМ=5% и процесс сопряжения уже запущен или завершен успешно,
# если EVSE захочет выставить ШИМ=номинальному зарядному току, то он должен сделать это
# через последовательность B или C (5 %) -> X1 -> B (nominal value) в соответствии с [IEC-3], глава 9.2
# Минимальной время в состоянии E или F - T_step_EF.

# [V2G3 M06-07] - Для случая, когда ШИМ=5% и истекло время ожидание пакетов SLAC (TT_EVSE_SLAC_init),
# EVSE перед повторной попыткой ожидания, должен пройти через состояние E или F, находясь в них T_step_EF (4 s).
# После чего можно перезапускать TT_EVSE_SLAC_init таймаут, максимальное кол-во попыток TT_EVSE_SLAC_init.
# В конце концов, если никакой реакции не было, то перейти в состояние X1.

# [V2G3-M06-08] После успешной EIM, если процесс сопряжения не был запущен,
# то EVSE должен перейти в состояние X1/X2 (номинальный ток), при этом смена должна включать в себя
# состояния E/F в течении T_step_EF

class Timers(float, Enum):
    """
    Используемые таймауты в соответствии с ISO15118-3, таблица A.1
    Размерность - секунды
    """

    # Время между обнаружением состояния B и получением первого пакета SLAAC (CM_SLAC_PARM.REQ)
    SLAC_INIT_TIMEOUT = 50.0  #TT_EVSE_SLAC_init

    # Время между получением CM_SET_KEY.CNF и отправкой NW_INFO.REQ 
    SLAC_NETWORK_INFO_TIMEOUT = 15.0

    # Время до получения пакетов CM_VALIDATE.REQ или CM_SLAC_MATCH.REQ
    # после получения пакета CM_ATTEN_CHAR.RSP
    SLAC_MATCH_TIMEOUT = 10.0  #TT_EVSE_match_session

    # Задержка перед отправкой CM_ATTEN_CHAR.IND после CM_START_ATTEN_CHAR.IND
    SLAC_ATTEN_RESULTS_TIMEOUT = 1.2  #TT_EV_atten_results

    # Таймаут для ожидания запроса (0.4), x2
    SLAC_REQ_TIMEOUT = 0.8  #TT_match_sequence

    # Таймаут для ожидания ответа (0.2), x4
    SLAC_RESP_TIMEOUT = 0.8  #TT_match_response

    # [V2G3-A09-124] - В случае ошибки сопряжения (matching process = FAILED)
    # необходимо выждать TT_matching_rate перед повторной попыткой сопряжения
    ##SLAC_REPETITION_TIMEOUT = 0.4  #TT_matching_rate

    # [V2G3-A09-125] - Если сопряжение не удалось установить за 
    # TT_matching_repetition попыток, то нужно установить состояние "Unmatched" 

    # Кол-во попыток установки сопряжения C_conn_max_match = 3, одновременно с этим
    # на повторные попытки установлен таймаут TT_matching_repetition = 10 сек.
    # При его истечении, даже если еще есть попытки, нужно установить состояние "Unmatched" 
    SLAC_TOTAL_REPETITIONS_TIMEOUT = 10.0  #TT_matching_repetition

    # Время нахождения в состоянии E или F, для некоторых случаев, определенных в [V2G3-M06-07]
    SLAC_E_F_TIMEOUT = 4.0  #T_step_EF

    # Время до запуска расчета уровня сигнала. С шагом 100 миллисекунды,
    # Для нашего случая возьмем 6 (600 ms (6 * 100))
    SLAC_ATTEN_TIMEOUT = 6  #TT_EVSE_match_MNBC

#MAC адресс широковещательной рассылки
ETHER_ADDR_LEN = 6
BROADCAST_ADDR = b"\xFF" * 6

# Состояния для FSM
STATE_UNMATCHED = 0
STATE_MATCHING  = 1
STATE_MATCHED   = 2

# Стандартный MAC адрес PLC ноды (channel.c в Qualcomm open-plc)
EVSE_PLC_MAC = b"\x00\xb0\x52\x00\x00\x01"

# Тип ethernet пакета - HomePlug AV
ETH_TYPE_HPAV = 0x88E1
HOMEPLUG_MMV  = b"\x01"
HOMEPLUG_FMSN = b"\x00"
HOMEPLUG_FMID = b"\x00"

# MMTypes базовые типы пакетов в нагрузке
MMTYPE_REQ = 0x0000
MMTYPE_CNF = 0x0001
MMTYPE_IND = 0x0002
MMTYPE_RSP = 0x0003
# MMTypes базовые виды пакетов в нагрузке
CM_SET_KEY          = 0x6008
CM_NW_INFO          = 0x6038
CM_SLAC_PARM        = 0x6064
CM_START_ATTEN_CHAR = 0x6068
CM_MNBC_SOUND       = 0x6074
CM_ATTEN_PROFILE    = 0x6084
CM_ATTEN_CHAR       = 0x606C
CM_SLAC_MATCH       = 0x607C
CM_NW_INFO          = 0x6038
# MMTypes расширенные виды пакетов в нагрузке
CM_LINK_STATUS      = 0xA0B8

# Параметры пакета SetKeyReq, относятся к CM_SET_KEY.REQ 
CM_SET_KEY_TYPE         = b"\x01"
CM_SET_KEY_MY_NONCE     = b"\x00\x00\x00\x00"
CM_SET_KEY_YOUR_NONCE   = b"\x00\x00\x00\x00"
CM_SET_KEY_PID          = b"\x04"
CM_SET_KEY_PRN          = b"\x00\x00"
CM_SET_KEY_PMN          = b"\x00"
CM_SET_KEY_NEW_EKS      = b"\x01"
CM_SET_CCO_CAPAB        = b"\x00"

# Таймаут после получения CM_SET_KEY.CNF
# Взят из Qualcomm example
SLAC_SETTLE_TIME = 10

SLAC_RESP_TYPE          = 0x01
SLAC_APPLICATION_TYPE   = 0x00
SLAC_SECURITY_TYPE      = 0x00

# Пауза между отправкой пакетов cm_mnbc_sound - 20 / 50 мс (TP_EV_batch_msg_interval)
SLAC_PAUSE  = 0.02
SLAC_GROUPS = 58

# Кол-во запрашиваемых пакетов M-Sound
SLAC_MSOUNDS = 10

# Пример настроек приватной сети от Qualcomm
# HomePlugAV0123 (определенны в evse.c и evse.ini в Qualcomm open-plc)
QUALCOMM_NID = b"\x02\x6b\xcb\xa5\x35\x4e\x08"
QUALCOMM_NMK = b"\xb5\x93\x19\xd7\xe8\x15\x7b\xa0\x01\xb0\x18\x66\x9c\xce\xe3\x0d"