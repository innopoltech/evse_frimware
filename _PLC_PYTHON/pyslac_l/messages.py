import ctypes
from dataclasses import dataclass
from typing import List

from .enums import (
    Timers,
    BROADCAST_ADDR,
    CM_SET_CCO_CAPAB,
    CM_SET_KEY_MY_NONCE,
    CM_SET_KEY_NEW_EKS,
    CM_SET_KEY_PID,
    CM_SET_KEY_PMN,
    CM_SET_KEY_PRN,
    CM_SET_KEY_TYPE,
    CM_SET_KEY_YOUR_NONCE,
    SLAC_APPLICATION_TYPE,
    SLAC_MSOUNDS,
    SLAC_RESP_TYPE,
    SLAC_SECURITY_TYPE,
)

                                                                        #Работа с пакетами MMe 
@dataclass
class SetKeyReq:                                                            
    """
    Относится к CM_SET_KEY.REQ (HPGP, глава 11.5.4; страница 586, таблица 11-87; ISO15118-3 таблица A.8)

    от EVSE/PEV -> EVSE_PLC/PEV_PLC

    Формат пакета:
    |KeyType|MyNonce|YourNonce|PID|PRN|PMN|CCoCap|NID|NewEKS|NewKey|

    KeyType        [1 байт]         = 0x01          : Фиксированно для NMK
    MyNonce        [4 байта]        = 0x00000000    : Фиксированно
    YourNonce      [4 байта]        = 0x00000000    : Фиксированно, без шифрования данных
    PID            [1 байт]         = 0x04          : Фиксированно для "HLE protocol"
    PRN            [2 байта]        = 0x0000        : Фиксированно, без шифрования данных
    PMN            [1 байт]         = 0x00          : Фиксированно, без шифрования данных
    CCo Capability [1 байт]         = 0x00          : CCo Capability в соответствии с ролью PLC
    NID            [7 байт]         = NID           : Идентификатор сети
    NewEKS         [1 байт]         = 0x01          : Фиксированно для NMK
    NewKey         [16 байт]        = NMK           : Маска сети, для каждой сессии разная

    Размер пакета = 44 байта
    """
    nid     : bytes
    new_key : bytes

    def __bytes__(self, endianess: str = "big"):
        if endianess == "big":
            return (
                CM_SET_KEY_TYPE
                + CM_SET_KEY_MY_NONCE
                + CM_SET_KEY_YOUR_NONCE
                + CM_SET_KEY_PID
                + CM_SET_KEY_PRN
                + CM_SET_KEY_PMN
                + CM_SET_CCO_CAPAB
                + self.nid
                + CM_SET_KEY_NEW_EKS
                + self.new_key
            )
        return (
            self.new_key
            + CM_SET_KEY_NEW_EKS
            + self.nid
            + CM_SET_CCO_CAPAB
            + CM_SET_KEY_PMN
            + CM_SET_KEY_PRN
            + CM_SET_KEY_PID
            + CM_SET_KEY_YOUR_NONCE
            + CM_SET_KEY_MY_NONCE
            + CM_SET_KEY_TYPE
        )

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

@dataclass
class SetKeyCnf:
    """
    Относится к CM_SET_KEY.CNF (HPGP, глава 11.5.5; страница 586, таблица 11-87; ISO15118-3 таблица A.8)

    от EVSE_PLC/PEV_PLC -> EVSE/PEV

    Формат пакета:
    |Result|MyNonce|YourNonce|PID|PRN|PMN|CCoCap|

    Result          [1 байт]      = X             : 0x00 - Успешно, 0x01 - Ошибка (!) см. from_bytes() (!) 
    MyNonce         [4 байта]     = X             : Рандомное, для проверки следующего сообщения
    YourNonce       [4 байта]     = X             : Рандомное, для проверки следующего сообщения
    PID             [1 байт]      = X             : Установленный протокол
    PRN             [2 байта]     = X             : Номер "прогона" при текущем протоколе
    PMN             [1 байт]      = X             : Номер сообщения в текущем "прогоне" текущего протокола
    CCo Capability  [1 байт]      = X             : CCo Capability в соответствии с ролью PLC

    Размер пакета = 14 байт
    """

    result      : int
    my_nonce    : bytes
    your_nonce  : bytes
    pid         : bytes
    prn         : bytes
    pmn         : bytes
    cco_capab   : bytes

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.result.to_bytes(1, "big")
            + self.my_nonce
            + self.your_nonce
            + self.pid
            + self.prn
            + self.pmn
            + self.cco_capab
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "SetKeyCnf":
        # Шапки Ethernet и HP в сумме размером 19 байт.
        return cls(
            result      =payload[19],
            my_nonce    =payload[20:24],
            your_nonce  =payload[24:28],
            pid         =payload[28],
            prn         =payload[29:31],
            pmn         =payload[31],
            cco_capab   =payload[32],
        )


@dataclass
class NwInfoCnf:
    """
    Относится к NW_INFO.CNF (HPGP, глава 11.5.27)

    от EVSE_PLC/PEV_PLC -> EVSE/PEV

    Формат пакета:
    |NumNWs|NWINFO[0]|...|NWINFO[N-1]|
    |NID|SNID|TEI|StationRole|CCo_MACAddr|Access|NumCordNWs|

    NumNWs      [1 байт]        = N             : Кол-во обнаруженных приватных сетей, если сетей несколько, то
                                                    в NWINFO[0] содержится текущая сеть для данного PLC
    NWINFO      [по 18 байт]    = X             : Структуры с параметрами обнаруженных сетей

    Для каждой структуры:
    NID	        [7 байт]        = X	            : Идентификатор сети
    SNID        [1 байт] 	    = X             : Сокращенный идентификатор сети
    TEI	        [1 байт]        = X             : Идентификатор оборудования STA в сети
    StationRole	[1 байт]	    = X             : Роль станции в сети,
                                                    0x00 = STA
                                                    0x01 = Proxy Coordinator
                                                    0x02 = CCo
                                                    0x03 – 0xFF = зарезервировано
    CCo_MACAddr	[6 байт]	    = X             : MAC адрес CCo сети.
    Access	    [1 байт]        = X             : Вид сети,
                                                    0x00 = домашняя сеть
                                                    0x01 = общественная сеть
                                                    0x02 - 0xFF = зарезервировано
    NumCordNWs	[1 байт]        = X             : Кол-во соседних сетей

    Размер пакета = 1+18*N байт
    """
    NumNWs      : bytes
    NID         : bytes
    SNID        : bytes
    TEI         : bytes
    StationRole : bytes
    CCo_MACAddr : bytes
    Access      : bytes
    NumCordNWs  : bytes
    Other       : bytes

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.NumNWs
            + self.NID
            + self.SNID
            + self.TEI
            + self.StationRole
            + self.CCo_MACAddr
            + self.Access
            + self.NumCordNWs
        )
        return frame
    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "NwInfoCnf":
        # Шапки Ethernet и HP в сумме размером 19 байт.
        # Минимальный размер пакета = 19 байт
        # Вернем только с первой структурой NWINFO, если она есть
        if(len(payload) >= 19+19):
            return cls(
                NumNWs      = payload[19],
                NID         = payload[20:27],
                SNID        = payload[27],
                TEI         = payload[28],
                StationRole = payload[29],
                CCo_MACAddr = payload[30:36],
                Access      = payload[36],
                NumCordNWs  = payload[37],
                Other       = payload[37:]
            )
        else:
            return cls(
                NumNWs      = int(0).to_bytes(1, "big"),
                NID         = int(0).to_bytes(7, "big"),
                SNID        = int(0).to_bytes(1, "big"),
                TEI         = int(0).to_bytes(1, "big"),
                StationRole = int(0).to_bytes(1, "big"),
                CCo_MACAddr = int(0).to_bytes(6, "big"),
                Access      = int(0).to_bytes(1, "big"),
                NumCordNWs  = int(0).to_bytes(1, "big"),
                Other       = int(0).to_bytes(1, "big")
            )

@dataclass
class SlacParmReq:
    """
    Широковещательное сообщение
    Относится к CM_SLAC_PARM.REQ (HPGP, глава 11.5.45; страница 586, таблица 11-87; так-же в ISO15118-3, таблица A.2)

    от PEV -> EVSE

    Формат пакета:
    |Application Type|Security Type|Run ID|CipherSuiteSetSize| CipherSuite..

    Application Type	[1 байт]        = 0x00	        : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00          : Фиксированно, без шифрования данных
    Run ID	            [8 байт]        = X             : Рандомый идентификатор сессии, генерируется EV
                                                            и сохраняется на протяжении всего общения 
                                                            в рамках сессии.
    CipherSuiteSetSize	[1 байт]	    = X             : Кол-во поддерживаемых наборов шифров.
    CipherSuite[1]      [2 байта]       = X             : Первый набор шифров
    CipherSuite[N]      [2 байта]	    = X             : N-ый набор шифров

    Однако поскольку Security Type = 0x00, то наборы шифров не используются,
    тогда формат пакета принимает следующий вид:
    |Application Type|Security Type|Run ID|

    Размер пакета = 10 байт
    """

    # 8 байт
    run_id              : bytes
    application_type    : int = SLAC_APPLICATION_TYPE
    security_type       : int = SLAC_SECURITY_TYPE

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.run_id
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "SlacParmReq":
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            run_id              = payload[21:29],
        )


@dataclass
class SlacParmCnf:
    # pylint: disable=too-many-instance-attributes
    """
    Относится к CM_SLAC_PARM.CNF (HPGP, глава 11.5.46; страница 586, таблица 11-87; также в ISO15118-3, таблица A.2)

    от  EVSE -> PEV

    Формат пакета:
    | M-SOUND_TARGET | NUM_SOUNDS| Time_Out| RESP_TYPE |
    | FORWARDING_STA | APPLICATION_TYPE| SECURITY_TYPE| RunID| *CipherSuite*

    M-SOUND_TARGET	    [6 байт]        = 0xFFFFFFFFFFFF	    : Указывает получателя M-Sounds пакетов.
                                                                    Фиксированно, широковещательная рассылка.
    NUM_SOUNDS	        [1 байт]        = SLAC_MSOUNDS	        : Кол-во ожидаемых пакетов M-Sounds.
    Time_Out	        [1 байт]        = SLAC_ATTEN_TIMEOUT    : Длительность TT_EVSE_match_MNBC, для 
                                                                    приема M-Sounds пакетов, 
                                                                    после получения CM_START_ATTEN_CHAR.IND.
                                                                    Кратно 100 мс (Time_Out = 6 соответствует 600 мс.).
    RESP_TYPE	        [1 байт]        = 0x01	                : Фиксированно, для передачи на другие GP станции.
    FORWARDING_STA	    [6 байт]        = X	                    : MAC адрес EV
    APPLICATION_TYPE	[1 байт]        = 0x00	                : Фиксированно, для 'PEV- EVSE matching'
    SECURITY_TYPE       [1 байт] 	    = 0x00                  : Фиксированно, без шифрования данных
    RunID	            [8 байт]        = X                     : Рандомый идентификатор сессии, генерируется EV
                                                                    и сохраняется на протяжении всего общения 
                                                                    в рамках сессии.
    CipherSuite	[2 байта]               = X                     : Выбранный набор шифрования

    Поскольку Security Type = 0x00, CipherSuite не входит в пакет

    Размер пакета = 25 байт
    """
    # 6 байт
    forwarding_sta      : bytes
    # 8 байт
    run_id              : bytes
    msound_target       : bytes = BROADCAST_ADDR
    num_sounds          : int   = SLAC_MSOUNDS
    time_out            : int   = int(Timers.SLAC_ATTEN_TIMEOUT)
    resp_type           : int   = SLAC_RESP_TYPE
    application_type    : int   = SLAC_APPLICATION_TYPE
    security_type       : int   = SLAC_SECURITY_TYPE

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.msound_target
            + self.num_sounds.to_bytes(1, "big")
            + self.time_out.to_bytes(1, "big")
            + self.resp_type.to_bytes(1, "big")
            + self.forwarding_sta
            + self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.run_id
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "SlacParmCnf":
        return cls(
            msound_target       = payload[19:25],
            num_sounds          = payload[25],
            time_out            = payload[26],
            resp_type           = payload[27],
            forwarding_sta      = payload[28:34],
            application_type    = payload[34],
            security_type       = payload[35],
            run_id              = payload[36:44],
        )


@dataclass
class StartAtennChar: 
    """
    Широковещательное сообщение

    Относится к CM_START_ATTEN_CHAR.IND  (HPGP, глава 11.5.47; страница 586, таблица 11-87; так-же в ISO15118-3, таблица A.4)

    от PEV -> EVSE

    Формат пакета:
    |Application Type|Security Type| NUM_SOUNDS| Time_Out| RESP_TYPE |
    |FORWARDING_STA |RunID|


    Application Type	[1 байт]        = 0x00	            : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00              : Фиксированно, без шифрования данных

    Следующие параметры находятся во вложенном поле  ACVarField (Attenuation Characterization Variable Field),
    определенном в HPGP

    NUM_SOUNDS          [1 байт]:       = X                 : Кол-во пакетов M-Sounds в будущей передаче.
    Time_Out            [1 байт]:       = X                 : Длительность TT_EVSE_match_MNBC, при 
                                                                передачи M-Sounds пакетов, 
                                                                после передачи CM_START_ATTEN_CHAR.IND.
                                                                Кратно 100 мс(Time_Out = 6 соответствует 600 мс.).
    RESP_TYPE           [1 байт]        = SLAC_RESP_TYPE    : Фиксированно, для передачи на другие GP станции.
    FORWARDING_STA	    [6 байт]        = X	                : MAC адрес EV
    Run ID	            [8 байт]        = X                 : Рандомый идентификатор сессии, генерируется EV
                                                                и сохраняется на протяжении всего общения 
                                                                в рамках сессии.

    Размер пакета = 19 байт
    """

    num_sounds          : int
    time_out            : int
    # 6 байт
    forwarding_sta      : bytes
    # 8 байт
    run_id              : bytes
    application_type    : int = SLAC_APPLICATION_TYPE
    security_type       : int = SLAC_SECURITY_TYPE
    resp_type           : int = SLAC_RESP_TYPE

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.num_sounds.to_bytes(1, "big")
            + self.time_out.to_bytes(1, "big")
            + self.resp_type.to_bytes(1, "big")
            + self.forwarding_sta
            + self.run_id
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "StartAtennChar":
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            num_sounds          = payload[21],
            time_out            = payload[22],
            resp_type           = payload[23],
            forwarding_sta      = payload[24:30],
            run_id              = payload[30:38],
        )


@dataclass
class MnbcSound:
    """
    Широковещательное сообщение

    Относится к CM_MNBC_SOUND.IND  (HPGP, глава 11.5.54; страница 586, таблица 11-87; так-же в ISO15118-3, таблица A.4)

    от PEV -> EVSE (HPGP узел)

    Формат пакета:
    |Application Type|Security Type|SenderID|Cnt|RunID|RSVD|Rnd|

    Application Type	[1 байт]        = 0x00	            : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00              : Фиксированно, без шифрования данных

    Следующие параметры находятся во вложенном поле  MSVarField  (MNBC Sound Variable Field),
    определенном в HPGP

    SenderID            [17 байт]       = 0x00              : Фиксированно, по 15118-3 
    Cnt                 [1 байт]        = X                 : Кол-во оставшихся для передачи пакетов M-SOUND

    В соотвествии с HPGP RunID - 16 байт, но в 15118-3 используется только 8, так что остальные зарезервированы в 0x00

    Run ID	            [8 байт]        = X                 : Рандомый идентификатор сессии, генерируется EV
                                                                и сохраняется на протяжении всего общения 
                                                                в рамках сессии.
    RSVD                [8 байт]        = 0x00              : Зарезервировано
    Rnd [16 bytes]                      = X                 : Случайное значение

    Размер пакета = 52 байта
    """

    cnt                 : int
    # 8 байт
    run_id              : bytes
    application_type    : int = SLAC_APPLICATION_TYPE
    security_type       : int = SLAC_SECURITY_TYPE
    # 17 байт
    sender_id           : int = 0x00
    # 8 байт
    rsvd                : int = 0x00
    # 16 байт
    rnd                 : int = 0xFF01

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.sender_id.to_bytes(17, "big")
            + self.cnt.to_bytes(1, "big")
            + self.run_id
            + self.rsvd.to_bytes(8, "big")
            + self.rnd.to_bytes(16, "big")
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "MnbcSound":
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            sender_id           = int.from_bytes(payload[21:38], "big"),
            cnt                 = payload[38],
            run_id              = payload[39:47],
            rsvd                = int.from_bytes(payload[47:55], "big"),
            rnd                 = int.from_bytes(payload[55:71], "big"),
        )


@dataclass
class AttenProfile:
    """
    Относится к CM_ATTEN_PROFILE.IND  (ISO15118-3, таблица A.4)

    от EVSE-PLC -> EVSE

    Формат пакета:
    |PEV MAC|NumGroups|RSVD|AAG 1| AAG 2| AAG 3...|

    PEV	        [6 байт]    = X	                    : MAC адрес EV
    NumGroups   [1 байт]    = 0x3A                  : Фиксированно, кол-во групп OFDM, используемых для характеристики сигнала
    RSVD        [1 байт]    = 0x00                  : Зарезервировано
    AAG 1       [1 байт]    = X                     : Среднее затухание в 1 группе
    AAG N       [1 байт]    = X                     : Среднее затухание в N группе

    Размер пакета = 66 байт
    """

    pev_mac     : bytes
    # Длинна = num_groups байт
    aag         : List[int]
    # 0x3A = 58 Групп
    num_groups  : int = 0x3A
    rsvd        : int = 0x00

    def __bytes__(self, endianess: str = "big"):
        aag_bytes = b""
        for group in range(self.num_groups):
            aag_bytes += self.aag[group].to_bytes(1, "big")
        frame = bytearray(
            self.pev_mac
            + self.num_groups.to_bytes(1, "big")
            + self.rsvd.to_bytes(1, "big")
            + aag_bytes
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "AttenProfile":
        num_groups = payload[25]
        return cls(
            pev_mac         = payload[19:25],
            num_groups      = num_groups,
            rsvd            = payload[26],
            aag             = list(payload[27 : 27 + num_groups]),
        )


@dataclass
class AtennChar:
    # pylint: disable=too-many-instance-attributes
    """
    Относится к CM_ATTEN_CHAR.IND  (HPGP, глава 11.5.48; страница 586, таблица 11-87; так-же в ISO15118-3, таблица A.4)

    от EVSE -> PEV 

    Формат пакета:
    |Application Type|Security Type| SOURCE_ADDRESS| RunID| SOURCE_ID| RESP_ID|
    |NumSounds| ATTEN_PROFILE|

    ATTEN_PROFILE = |NumGroups|AAG 1| AAG 2| AAG 3...|


    Application Type	[1 байт]        = 0x00	            : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00              : Фиксированно, без шифрования данных

    Следующие параметры находятся во вложенном поле ACVarField (Attenuation Characterization Variable Field),
    определенном в HPGP

    SOURCE_ADDRESS      [6 байт]        = X                 : MAC адрес EV 
    Run ID	            [8 байт]        = X                 : Рандомый идентификатор сессии, генерируется EV
                                                                и сохраняется на протяжении всего общения 
                                                                в рамках сессии.
    SOURCE_ID           [17 байт]       = 0x00...00         : Уникальный идентификатор станции, с которой отправляются 
                                                                M-Sounds пакеты (не используется в ISO)
    RESP_ID             [17 байт]       = 0x00...00         : Уникальный идентификатор станции, с которой отправляется 
                                                                текущий пакет (не используется в ISO)
    NUM_SOUNDS          [1 байт]        = X                 : Кол-во пакетов M-Sounds использовавшихся при расчете
                                                                ATTEN_PROFILE
    ATTEN_PROFILE       [59 байт]       =X                  : Затухание уровня сигнала (по таблице 'ATTEN_PROFILE' в HPGP)
                                                                ATTEN_PROFILE = |NumGroups|AAG 1| AAG 2| AAG 3...|

    Размер пакета = 110 байт
    """
    # 6 байт
    source_address      : bytes
    # 8 байт
    run_id              : bytes
    num_sounds          : int
    num_groups          : int
    # 255 байт
    aag                 : List[int]
    application_type    : int = SLAC_APPLICATION_TYPE
    security_type       : int = SLAC_SECURITY_TYPE
    # 17 байт
    source_id           : int = 0x00
    # 17 байт
    resp_id             : int = 0x00

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.source_address
            + self.run_id
            + self.source_id.to_bytes(17, "big")
            + self.resp_id.to_bytes(17, "big")
            + self.num_sounds.to_bytes(1, "big")
            + self.num_groups.to_bytes(1, "big")
            + bytearray(self.aag)
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "AtennChar":
        num_groups = payload[70]
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            source_address      = payload[21:27],
            run_id              = payload[27:35],
            source_id           = int.from_bytes(payload[35:52], "big"),
            resp_id             = int.from_bytes(payload[52:69], "big"),
            num_sounds          = payload[69],
            num_groups          = num_groups,
            aag                 = list(payload[71 : 71 + num_groups]),
        )


@dataclass
class AtennCharRsp:
    """
    Относится к CM_ATTEN_CHAR.RSP  (HPGP, глава 11.5.49; страница 586, таблица 11-87; так-же в ISO15118-3, таблица A.4)

    от PEV -> EVSE
    
    Формат пакета:
    |Application Type|Security Type| SOURCE_ADDRESS| RunID| SOURCE_ID| RESP_ID|
    |Result|

    Application Type	[1 байт]        = 0x00	            : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00              : Фиксированно, без шифрования данных

    Следующие параметры находятся во вложенном поле  ACVarField  (Attenuation Characterization Variable Field),
    определенном в HPGP

    SOURCE_ADDRESS      [6 байт]        = X                 : MAC адрес EV 
    Run ID	            [8 байт]        = X                 : Рандомый идентификатор сессии, генерируется EV
                                                                и сохраняется на протяжении всего общения 
                                                                в рамках сессии.
    SOURCE_ID           [17 байт]       = 0x00...00         : Уникальный идентификатор станции, с которой отправляются 
                                                                M-Sounds пакеты (не используется в ISO)
    RESP_ID             [17 байт]       = 0x00...00         : Уникальный идентификатор станции, с которой отправляется 
                                                                текущий пакет (не используется в ISO)
    Result              [1 байт]        = 0x00              : Фиксированно, 0x00 - успех

    Размер пакета = 43 байта
    """

    # 6 байт
    source_address  : bytes
    # 8 байт
    run_id          : bytes
    # 17 байт
    source_id       : int
    # 17 байт
    resp_id         : int
    # 1 байт
    result          : int

    application_type: int = SLAC_APPLICATION_TYPE
    security_type   : int = SLAC_SECURITY_TYPE

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.source_address
            + self.run_id
            + self.source_id.to_bytes(17, "big")
            + self.resp_id.to_bytes(17, "big")
            + self.result.to_bytes(1, "big")
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "AtennCharRsp":
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            source_address      = payload[21:27],
            run_id              = payload[27:35],
            source_id           = int.from_bytes(payload[35:52], "big"),
            resp_id             = int.from_bytes(payload[52:69], "big"),
            result              = payload[69],
        )


@dataclass
class MatchReq:
    # pylint: disable=too-many-instance-attributes
    """
    Относится к CM_SLAC_MATCH.REQ  (HPGP, глава 11.5.57; также в ISO15118-3, таблица A.7)

    от PEV -> EVSE
    
    Формат пакета:
    |Application Type|Security Type| MVFLength| PEV_ID| PEV_MAC| EVSE_ID|
    EVSE MAC|RunID|RSVD|

    Application Type	[1 байт]        = 0x00	            : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00              : Фиксированно, без шифрования данных
    MVFLength           [2 байта]       = 0x3e              : Фиксированно, длинна поля 'Match Variable'
    
    Следующие параметры находятся во вложенном поле  MatchVarField  (Match Variable Field),
    определенном в HPGP

    PEV ID              [17 байт]       = 0x00              : Фиксированно
    PEV MAC             [6 байт]        = X                 : MAC адрес EV
    EVSE ID             [17 байт]       = 0x00              : Фиксированно
    EVSE MAC            [6 байт]        = X                 : MAC адрес EVSE
    Run ID	            [8 байт]        = X                 : Рандомый идентификатор сессии, генерируется EV
                                                                и сохраняется на протяжении всего общения 
                                                                в рамках сессии.
    RSVD                [8 байт]        = 0x00              : Фиксированно

    Размер пакета = 62 байта
    """
    # 6 байт
    pev_mac             : bytes
    # 6 байт
    evse_mac            : bytes
    # 8 байт
    run_id              : bytes
    application_type    : int = SLAC_APPLICATION_TYPE
    security_type       : int = SLAC_SECURITY_TYPE
    # 2 байта
    mvf_length          : int = 0x003E
    # 17 байт
    pev_id              : int = 0x00
    # 17 байт
    evse_id             : int = 0x00
    # 8 байт
    rsvd                : int = 0x00

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.mvf_length.to_bytes(2, "big")
            + self.pev_id.to_bytes(17, "big")
            + self.pev_mac
            + self.evse_id.to_bytes(17, "big")
            + self.evse_mac
            + self.run_id
            + self.rsvd.to_bytes(8, "big")
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "MatchReq":
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            mvf_length          = int.from_bytes(payload[21:23], "big"),
            pev_id              = int.from_bytes(payload[23:40], "big"),
            pev_mac             = payload[40:46],
            evse_id             = int.from_bytes(payload[46:63], "big"),
            evse_mac            = payload[63:69],
            run_id              = payload[69:77],
            rsvd                = int.from_bytes(payload[77:85], "big"),
        )


@dataclass
class MatchCnf:
    # pylint: disable=too-many-instance-attributes
    """
    Относится к CM_SLAC_MATCH.CNF  (HPGP, глава 11.5.58; также в ISO15118-3, таблица A.7)

    от EVSE -> PEV
    
    Формат пакета:
    |Application Type|Security Type| MVFLength| PEV_ID| PEV_MAC| EVSE_ID|
    EVSE MAC|RunID|RSVD1|NID|RSVD2|NMK

    Application Type	[1 байт]        = 0x00	            : Фиксированно, для 'PEV- EVSE matching'
    Security Type       [1 байт] 	    = 0x00              : Фиксированно, без шифрования данных
    MVFLength           [2 байта]       = 0x56              : Фиксированно, длинна поля 'Match Variable'
    
    Следующие параметры находятся во вложенном поле  MatchVarField  (Match Variable Field),
    определенном в HPGP

    PEV ID              [17 байт]       = 0x00              : Фиксированно
    PEV MAC             [6 байт]        = X                 : MAC адрес EV
    EVSE ID             [17 байт]       = 0x00              : Фиксированно
    EVSE MAC            [6 байт]        = X                 : MAC адрес EVSE
    Run ID	            [8 байт]        = X                 : Рандомый идентификатор сессии, генерируется EV
                                                                и сохраняется на протяжении всего общения 
                                                                в рамках сессии.
    RSVD                [8 байт]        = 0x00              : Фиксированно
    NID                 [7 байт]        = X                 : Идентификатор сети, полученный от EVSE
    RSVD2               [8 байт]        = 0x00              : Фиксированно
    NMK                 [16 байт]       = X                 : Маска сети, полученная от EVSE

    Размер пакета = 97 байт
    """
    # 6 байт
    pev_mac             : bytes
    # 6 байт
    evse_mac            : bytes
    # 8 байт
    run_id              : bytes
    # 7 байт
    nid                 : bytes
    # 16 байт
    nmk                 : bytes
    application_type    : int = SLAC_APPLICATION_TYPE
    security_type       : int = SLAC_SECURITY_TYPE
    # 2 байта
    mvf_length          : int = 0x56
    # 17 байт
    pev_id              : int = 0x00
    # 17 байт
    evse_id             : int = 0x00
    # 8 байт
    rsvd_1              : int = 0x00
    # 1 байт
    rsvd_2              : int = 0x00

    def __bytes__(self, endianess: str = "big"):
        frame = bytearray(
            self.application_type.to_bytes(1, "big")
            + self.security_type.to_bytes(1, "big")
            + self.mvf_length.to_bytes(2, "little")  # поле MVF должно быть в формате  "little endian"
            + self.pev_id.to_bytes(17, "big")
            + self.pev_mac
            + self.evse_id.to_bytes(17, "big")
            + self.evse_mac
            + self.run_id
            + self.rsvd_1.to_bytes(8, "big")
            + self.nid
            + self.rsvd_2.to_bytes(1, "big")
            + self.nmk
        )
        if endianess == "big":
            return frame
        return frame.reverse()

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: ctypes) -> "MatchCnf":
        return cls(
            application_type    = payload[19],
            security_type       = payload[20],
            mvf_length          = int.from_bytes(payload[21:23], "big"),
            pev_id              = int.from_bytes(payload[23:40], "big"),
            pev_mac             = payload[40:46],
            evse_id             = int.from_bytes(payload[46:63], "big"),
            evse_mac            = payload[63:69],
            run_id              = payload[69:77],
            rsvd_1              = int.from_bytes(payload[77:85], "big"),
            nid                 = payload[85:92],
            rsvd_2              = payload[92],
            nmk                 = payload[93:109],
        )
