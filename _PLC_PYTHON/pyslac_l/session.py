import asyncio
import logging
from binascii import hexlify
from dataclasses import dataclass, field
from inspect import isawaitable
from os import urandom
from typing import List, Optional, Union

version__ = 0.1
from .enums import (
    Timers,
    CM_ATTEN_CHAR,
    CM_ATTEN_PROFILE,
    CM_MNBC_SOUND,
    CM_SET_KEY,
    CM_NW_INFO,
    CM_SLAC_MATCH,
    CM_SLAC_PARM,
    CM_START_ATTEN_CHAR,
    CM_LINK_STATUS,
    EVSE_PLC_MAC,
    MMTYPE_CNF,
    MMTYPE_IND,
    MMTYPE_REQ,
    MMTYPE_RSP,
    SLAC_GROUPS,
    SLAC_MSOUNDS,
    SLAC_PAUSE,
    SLAC_RESP_TYPE,
    SLAC_SETTLE_TIME,
    STATE_MATCHED,
    STATE_MATCHING,
    STATE_UNMATCHED,
)

from .layer_2_headers import EthernetHeader, HomePlugHeader
from .messages import (
    AtennChar,
    AtennCharRsp,
    AttenProfile,
    MatchCnf,
    MatchReq,
    MnbcSound,
    NwInfoCnf,
    SetKeyCnf,
    SetKeyReq,
    SlacParmCnf,
    SlacParmReq,
    StartAtennChar,
)

from .utils import half_round as hw
from .utils import cancel_task, task_callback, time_now_ms, generate_nid

from .Client_base       import base
from .Server_data_link  import data_link_data

from .utils import get_if_hwaddr

from .async_socket import (
    create_socket,
    readeth,
    sendeth,
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("slac_session")


@dataclass
class SlacSession:                                                  # Самый базовый класс всей сессии, содержит параметры
                                                                    # и функцию сброса
    # pylint: disable=too-many-instance-attributes
    # Состояние подключения (STATE_MATCHED, STATE_MATCHING, STATE_UNMATCHED)
    state: int

    # 16 байт
    # Маска сети (Network Mask), 16 рандомных байт
    nmk: bytes = b""

    # 7 байт Идентификатора сети (NetworkIdentifier)
    # 54 LSBs содержат NID (глава 4.4.3.1)
    # 2 MSBs должным быть 0b00.
    # NID генерируется на основе маски сети
    nid: bytes = b""

    # В соответствии с 15118-3, FORWARDING_STA это MAC адрес EV Host
    forwarding_sta: bytes = b""

    # PEV_ID (извлекается EVSE из принятого сообщения evse_cm_slac_match (от EV)), 17 байт
    pev_id: Optional[int] = None

    # MAC адрес EV (извлекается EVSE из принтяго сообщения evse_cm_slac_param (от EV)), 6 байт
    pev_mac: bytes = b""

    # EVSE MAC адрес, 6 байт
    evse_mac: bytes = b""

    # id текущей сессии (генерируется EV), 8 байт
    run_id: bytes = b""
    # 1 байт APPLICATION_TYPE, для SLAC должен быть 0
    application_type: int = 0x00
    # 1 байт Security Type, для SLAC должен быть 0x00 
    security_type: int = 0x00

    # Счетчик сообщений CM_START_ATTEN_CHAR.IND, EV должен послать 3 последовательно
    num_start_attn_rcvd: int = 0

    # Число "sounds" ожидаемых от EV, в 15118-3 это параметр CM_EV_match_MNBC
    num_expected_sounds: Optional[int] = None

    # NUM_SOUNDS CM_MNBC_SOUND.IND посылается EV во время "attn charac"
    # Со стороны EVSE увеличивается с каждым принятым CM_MNBC_SOUND сообщением
    num_total_sounds: int = 0

    # Используется EV, как число "sounds", которые необходимо передать
    sounds: int = SLAC_MSOUNDS

    # Таймаут для приема всех "sounds" сообщений
    # передается как число*100 миллисекунд , поэтому для стандартных
    # 600 мс (/100) = 0x06
    time_out_ms: int = int(Timers.SLAC_ATTEN_TIMEOUT)

    # SLAC_GROUPS = 58 байт
    # содержится в CM_ATTEN_PROFILE.IND.AAG
    aag: [int] = field(default_factory=lambda: [0] * SLAC_GROUPS)

    # Номер SLAC группы, 1 байт 
    num_groups: Optional[int] = None

    # Рандомные 17 байт
    rnd: bytes = (0).to_bytes(17, "big")

    # Время ожидания для EVSE и EV после отправки CM_SET_KEY.REQ или получения  CM_SET_KEY.CNF (?)
    settle_time: int = SLAC_SETTLE_TIME

    # Список задч запущенных при согласовании
    matching_process_task: Optional[asyncio.Task] = None

    def reset(self):
        """
        Сброс значений на дефолтные, NID и NMK не сбрасываются, они перегенирируются в процессе
        установки параметров приватной сети "evse_set_key".
        """
        self.state = STATE_UNMATCHED
        self.forwarding_sta = b""
        self.pev_id = None
        self.pev_mac = b""
        self.run_id = b""
        self.application_type = 0x00
        self.security_type = 0x00
        self.num_start_attn_rcvd = 0
        self.num_expected_sounds = None
        self.num_total_sounds = 0
        self.sounds = SLAC_MSOUNDS
        self.time_out_ms = int(Timers.SLAC_ATTEN_TIMEOUT)
        self.aag = field(default_factory=lambda: [0] * SLAC_GROUPS)
        self.num_groups = None
        self.rnd = (0).to_bytes(17, "big")
        self.settle_time = SLAC_SETTLE_TIME
        self.matching_process_task = None


class SlacEvseSession(SlacSession):                                     #Класс сессии, работает с пакетами
    # pylint: disable=too-many-instance-attributes, too-many-arguments
    # pylint: disable=logging-fstring-interpolation, broad-except
    def __init__(self, evse_id: str, iface: str):
        self.iface = iface
        self.evse_id = evse_id
        host_mac = get_if_hwaddr(self.iface)            # Узнаем MAC адрес интерфейса
        logger.debug(f"Session created for evse_id {self.evse_id} on " f"interface {self.iface}")

        self.socket = create_socket(iface=self.iface)   # Создаем raw сокет
        self.evse_plc_mac = EVSE_PLC_MAC
        SlacSession.__init__(self, state=STATE_UNMATCHED, evse_mac=host_mac)    # Инициализируем базовый класс

    async def send_frame(self, frame_to_send: bytes) -> None:
        """
        Вспомогательная функция для асинхронного ожидания отправки eth кадра
        """
        bytes_sent = sendeth(s=self.socket, frame_to_send=frame_to_send)
        if isawaitable(bytes_sent):
            await bytes_sent

    async def rcv_frame(self, rcv_frame_rx: HomePlugHeader, timeout: Union[float, int], base_set: bool = True) -> bytes:
        """
        Вспомогательная функция для асинхронного приема сообщения, с учетом таймаута

        """
        return await asyncio.wait_for(
            readeth(s=self.socket, rcv_frame_rx=rcv_frame_rx, dst_mac=self.evse_mac, base_set=base_set),
            timeout,
        )

    async def leave_logical_network(self):
        """
        ISO15118-3 глава 9.6, требование [V2G3-M09-17].
        При выходе из приватной сети необходимо сбросить сопряжение и 
        перегенерировать NMK и NID.
        """
        await self.evse_set_key()
        self.reset()

    async def evse_set_key(self) -> bytes:
        """
        PEV-HLE должен установить NMK и NID в PEV-PLC используя CM_SET_KEY.REQ,
        эти NMK и NID должны быть приняты от EVSE-HLE в пакете CM_SLAC_MATCH.CNF;

        Настройка параметров приватной сети происходит с использованием пакетов MME
        CM_SET_KEY.REQ and CM_SET_KEY.CNF.
        В ISO15118-3, таблице A.8 указан формат пакетов.
        Так же они указаны в HomePlug GP_Specification, глава 11.
        """
        logger.info("CM_SET_KEY: Started...")           # Параметры заново генерируются при каждом вызове функции

        nmk = urandom(16)                               # Генерация маски сети
        nid = generate_nid(nmk)                         # Генерация сетевого идентификатора
        
        logger.debug("New NMK: %s", hexlify(nmk))
        logger.debug("New NID: %s", hexlify(nid))
#########
        ethernet_header = EthernetHeader(dst_mac=self.evse_plc_mac, src_mac=self.evse_mac)        # Создание Eth пакета
        homeplug_header_tx = HomePlugHeader(CM_SET_KEY | MMTYPE_REQ)   # Создание HomePlug пакета отправки
        homeplug_header_rx = HomePlugHeader(CM_SET_KEY | MMTYPE_CNF)   # Создание HomePlug пакета приема
        key_req_payload = SetKeyReq(nid=nid, new_key=nmk)           # Создание MMe пакета

        frame_to_send = (                                           # Сборка кадра
            ethernet_header.pack_big()
            + homeplug_header_tx.pack_big()
            + key_req_payload.pack_big()
        )
        try:
            await self.send_frame(frame_to_send)                    # Отправка CM_SET_KEY.REQ и ожидание CM_SET_KEY.CNF
            data_rcvd = await self.rcv_frame(
                rcv_frame_rx=homeplug_header_rx,
                timeout=Timers.SLAC_INIT_TIMEOUT,
            )
        except asyncio.TimeoutError as e:
            raise TimeoutError("SetKey Timeout raised") from e
        
        try:
            SetKeyCnf.from_bytes(data_rcvd)                         # Извлечение пакета CM_SET_KEY.CNF, результат игнорируем
            self.nmk = nmk
            self.nid = nid
        except ValueError as e:
            logger.error(e)
            if self.nmk and self.nid:
                logger.debug("SetKeyReq has failed, old NMK: %s and NID: %s apply",self.nmk,self.nid,)
            else:
                raise ValueError("SetKeyCnf data parsing into the class failed") from e
#########        
        # (!) Результат игнорируется, поскольку разные чипы Qualcomm имеют разные прошивки
        # которые могу интерпретировать то (0x00 - Успешно, 0x01 - Ошибка), то (0x01 - Успешно, 0x00 - Ошибка)
        # В качестве проверки необходимо подтвердить установку NID через сообщение NW_INFO.REQ
#########
        await asyncio.sleep(Timers.SLAC_NETWORK_INFO_TIMEOUT)           # Ожидание установки новых параметров в PLC

        ethernet_header = EthernetHeader(dst_mac=self.evse_plc_mac, src_mac=self.evse_mac)        #Создание Eth пакета
        homeplug_header_tx = HomePlugHeader(CM_NW_INFO | MMTYPE_REQ)   # Создание HomePlug пакета отправки
        homeplug_header_rx = HomePlugHeader(CM_NW_INFO | MMTYPE_CNF)   # Создание HomePlug пакета приема
        # MMe пакет для CM_NW_INFO.REQ = Null (HPGP, глава 11.5.26)

        frame_to_send = (                                           # Создание кадра
            ethernet_header.pack_big()
            + homeplug_header_tx.pack_big()
        )
        try:
            await self.send_frame(frame_to_send)                    # Отправка CM_NW_INFO.REQ и ожидание NW_INFO.CNF
            data_rcvd = await self.rcv_frame(
                rcv_frame_rx=homeplug_header_rx,
                timeout=Timers.SLAC_INIT_TIMEOUT,
            )
        except asyncio.TimeoutError as e:
            raise TimeoutError("NwInfo Timeout raised") from e
        
        try:
            packet = NwInfoCnf.from_bytes(data_rcvd)                         # Извлечение пакета NW_INFO.CNF
            if(packet.NID != self.nid):                                 # Проверка идентификатора сети                   
                raise ValueError ("NID has not been set")
        except ValueError as e:
            logger.error(e)
            logger.debug("NW_INFO.CNF has failed")

        logger.debug("Registering NMK and NID into the PLC node...")
        # await asyncio.sleep(SLAC_SETTLE_TIME)                           
        logger.info("CM_SET_KEY: Finished!")
        return data_rcvd

    async def evse_slac_parm(self) -> None:                         # Обмен первыми пакетами SLAC с EV
        logger.debug("CM_SLAC_PARM: Started...")
        
        try:
            homeplug_header_rx = HomePlugHeader(CM_SLAC_PARM | MMTYPE_REQ)   # Создание HomePlug пакета приема
            data_rcvd = await self.rcv_frame(                                # Ожидание пакета CM_SLAC_PARM.REQ
                rcv_frame_rx=homeplug_header_rx,
                timeout=Timers.SLAC_INIT_TIMEOUT,
            )
        except asyncio.TimeoutError as e:
            logger.warning(f"Timeout waiting for CM_SLAC_PARM.REQ: {e}")
            raise TimeoutError from e
        
        try:
            ether_frame = EthernetHeader.from_bytes(data_rcvd)      # Извлечение данных из пакета CM_SLAC_PARM.REQ
            slac_parm_req = SlacParmReq.from_bytes(data_rcvd)
        except Exception as e:
            logger.error(e)
            raise e


        # Сохранение параметров из SLAC_PARM_REQ 
        self.application_type   = slac_parm_req.application_type
        self.security_type      = slac_parm_req.security_type
        self.run_id             = slac_parm_req.run_id

        # Оба поля имеют MAC адрес EV
        self.pev_mac = ether_frame.src_mac
        self.forwarding_sta = ether_frame.src_mac

        # Формирование SLAC_PARM_CNF пакета
        ethernet_header = EthernetHeader(dst_mac=self.pev_mac, src_mac=self.evse_mac)     # Создание Eth пакета
        homeplug_header_tx = HomePlugHeader(CM_SLAC_PARM | MMTYPE_CNF)                    # Создание HomePlug пакета отправки
        slac_parm_cnf = SlacParmCnf(forwarding_sta=self.pev_mac, run_id=self.run_id)      # Создание MMe пакета

        frame_to_send = (                               
            ethernet_header.pack_big()
            + homeplug_header_tx.pack_big()
            + slac_parm_cnf.pack_big()
        )

        await self.send_frame(frame_to_send)                # Отправка CM_SLAC_PARM.CNF
        logger.debug("Sent SLAC_PARM.CNF")

        # Установка состояния в "сопряжение в процессе"
        self.state = STATE_MATCHING

        logger.debug("CM_SLAC_PARM: Finished!")

    async def cm_start_atten_charac(self):                      # Обработка пакета начала проверки уровня сигнала
        logger.debug("CM_START_ATTEN_CHAR: Started...")

        try:
            homeplug_header_rx = HomePlugHeader(CM_START_ATTEN_CHAR | MMTYPE_IND)   # Создание HomePlug пакета приема
            data_rcvd = await self.rcv_frame(                                # Ожидание пакета СM_START_ATTEN_CHAR.IND
                rcv_frame_rx=homeplug_header_rx,
                timeout=Timers.SLAC_REQ_TIMEOUT,
            )
            start_atten_char = StartAtennChar.from_bytes(data_rcvd) # Извлечение данных из пакета M_START_ATTEN_CHAR.IND
        except Exception as e:
            logger.error(e)
            raise e

        if (
            self.application_type != start_atten_char.application_type
            or self.security_type != start_atten_char.security_type
            or self.run_id != start_atten_char.run_id
            or start_atten_char.resp_type != SLAC_RESP_TYPE                 # Проверка параметров из сообщения
        ):
            logger.error(ValueError("Error in StartAttenChar"))
            raise ValueError("Error in StartAttenChar")


        # В ISO15118-3 указанно, что EV отправляет 3 пакета CM_START_ATTEN_CHAR,
        # однако они одинаковые, поэтому обрабатываем только один.

        # Сохраняем параметры из пакета START_ATTEN_CHAR
        self.num_expected_sounds = start_atten_char.num_sounds
        # Иногда могут возникнуть таймауты приема пакетов M-Sounds.
        # В [V2G3-A09-30] указанно - что после передачи первого пакета CM_START_ATTEN_CHAR.IND
        # EV должен запустить таймер TT_EV_atten_results (макс. 1200 мс.). 
        # В [V2G3-A09-31] указанно, что в течении этого времени (TT_EV_atten_results)
        # EV должен обрабатывать все входящие CM_ATTEN_CHAR.IND пакеты.
        # В связи с этим мы можем увеличить таймаут, в пределах TT_EV_atten_results,
        # например на +200 мс. от исходного.
        self.time_out_ms = start_atten_char.time_out * 100
        if(self.time_out_ms + 200 < Timers.SLAC_ATTEN_RESULTS_TIMEOUT):
            self.time_out_ms += 200
        logger.debug("CM_START_ATTEN_CHAR: Finished!")

    def process_sound_frame(                            # Обработчик пакетов CM_MNBC_MSOUND.IND и CM_ATTEN_PROFILE.IND
        self,
        homeplug_frame: "HomePlugHeader",
        ether_frame: "EthernetHeader",
        data_rcvd: bytes,
        sounds_rcvd: int,
        aag: List[int],
    ) -> int:
        """
        Проверяет, какой тип пакета был получен, возвращает следующий ожидаемый пакет.
        В случае CM_ATTEN_PROFILE.IND сохраняет значение мощности сигнала
        """
        if homeplug_frame.mm_type == CM_MNBC_SOUND | MMTYPE_IND:    # Если принятый пакет это CM_MNBC_MSOUND.IND
            homeplug_header_rx = HomePlugHeader(CM_ATTEN_PROFILE | MMTYPE_IND)  # Следующий ожидаемый пакет
            mnbc_sound_ind = MnbcSound.from_bytes(data_rcvd)    # Извлечение данных

            if self.run_id != mnbc_sound_ind.run_id:                # Проверка ID сессии
                logger.debug(
                    "Frame received is a CM_MNBC_SOUND but "
                    "it has an invalid Running Session ID. "
                    "Session RunID: %s\n Received RunID: %s",
                    self.run_id,
                    mnbc_sound_ind.run_id,
                )
                return homeplug_header_rx
            
            if self.pev_mac != ether_frame.src_mac:                 # Проверка MAC адреса отправителя
                raise ValueError(
                    f"Unexpected Source MAC Address for sound "
                    f"number {sounds_rcvd}. "
                    f"PEV MAC: {self.pev_mac}; "
                    f"Source MAC: {ether_frame.src_mac}"
                )
            logger.debug("MNBC Sound received")
            logger.debug("Remaining number of sounds: %s", mnbc_sound_ind.cnt)
            return homeplug_header_rx

        if homeplug_frame.mm_type == CM_ATTEN_PROFILE | MMTYPE_IND:  # Если принятый пакет это CM_MNBC_MSOUND.IND
            homeplug_header_rx = HomePlugHeader(CM_MNBC_SOUND | MMTYPE_IND)  # Следующий ожидаемый пакет
            atten_profile_ind = AttenProfile.from_bytes(data_rcvd)          # Извлечение данных
            
            if self.pev_mac != atten_profile_ind.pev_mac:               # Проверка MAC адреса отправителя
                logger.warning(
                    "PEV MAC %s does not match: %s. Ignoring...",
                    self.pev_mac,
                    atten_profile_ind.pev_mac,
                )
                return homeplug_header_rx
            
            for group in range(atten_profile_ind.num_groups):       # Копирование среднего затухания по всем группам
                aag[group] += atten_profile_ind.aag[group]
            self.num_groups = atten_profile_ind.num_groups
            self.num_total_sounds += 1
            logger.debug("ATTEN_Profile Sounds received %s", self.num_total_sounds)
            logger.debug(
                "Num total sounds: %s / Num expected: %s",
                self.num_total_sounds,
                self.num_expected_sounds,
            )
            return homeplug_header_rx

    async def cm_sounds_loop(self):
        """

        В HPGP рекомендуется в качестве флага остановки приема пакетов M-SOUNDS использовать таймаут,
        поскольку некоторые пакеты могут быть потеряны в процессе.

        EV посылает пакеты CM_MNBC_SOUND.IND:
        |Application Type|Security Type|SenderID|Cnt|RunID|RSVD|Rnd|

        Для каждого пакета CM_MNBC_SOUND.IND, EVSE PLC пошлет свой пакет AttenProfile:
        |PEV MAC|NumGroups|RSVD|AAG 1| AAG 2| AAG 3...|

        Пакеты CM_MNBC_SOUND.IND принимаются только при совпадении идентификатора сессии 
        (какой был в CM_SLAC_PARAM.REQ и CM_START_ATTRN_CHAT.IND)

        Каждый пакет CM_MNBC_MSOUND.IND сопровождается CM_ATTEN_PROFILE.IND.

        По истечению таймаута вычисляется среднее AAG значение
        """
        logger.debug("CM_MNBC_SOUND: Started...")

        sounds_rcvd: int        = 0
        aag: List[int]          = [0] * SLAC_GROUPS
        self.aag                = [0] * SLAC_GROUPS
        time_start              = time_now_ms()                  # Засечение времени для таймаута
        self.num_total_sounds   = 0

        # Поочередно получаем пакеты CM_MNBC_SOUND.IND и CM_ATTEN_PROFILE.IND, 
        # первым всегда идет CM_MNBC_SOUND.IND
        homeplug_header_rx = HomePlugHeader(CM_MNBC_SOUND | MMTYPE_IND)   #Создание HomePlug пакета приема

        while True:
            try:
                homeplug_frame = None
                data_rcvd = await self.rcv_frame(                     # Ожидание пакета CM_MNBC_SOUND.IND || CM_ATTEN_PROFILE.IND
                    rcv_frame_rx=homeplug_header_rx,
                    timeout=SLAC_PAUSE,
                )
                ether_frame     = EthernetHeader.from_bytes(data_rcvd)
                homeplug_frame  = HomePlugHeader.from_bytes(data_rcvd)   # Извлечение шапок
            except asyncio.TimeoutError as e:                   # Таймаут по приему тут игнорируем, 
                pass                                            # т.к. опираемся на глобальный таймаут ниже
            except Exception as e:
                logger.error(e)      # Все другие исключения обрабатываем
                raise e
            
            if(homeplug_frame is not None):
                homeplug_header_rx = self.process_sound_frame(                  # Получем тип пакета для след приема
                    homeplug_frame, ether_frame, data_rcvd, sounds_rcvd, aag
                )

            time_elapsed = time_now_ms() - time_start                       # Проверка общего таймаута на прием 
            if (
                time_elapsed < self.time_out_ms
                and self.num_total_sounds < self.num_expected_sounds
            ):
                continue

            # По [V2G3-A09-19] расчет среднего затухания линии
            if self.num_total_sounds > 0:
                for group in range(SLAC_GROUPS):
                    self.aag[group] = hw(aag[group] / self.num_total_sounds)
            logger.debug("CM_MNBC_SOUND: Finished!")
            return

    async def cm_atten_char(self):                          # Отправка результатов проверки уровня сигнала
        logger.debug("CM_ATTEN_CHAR Started...")
        ether_header = EthernetHeader(dst_mac=self.pev_mac, src_mac=self.evse_mac)  # Создание Eth пакета
        homeplug_header_tx = HomePlugHeader(CM_ATTEN_CHAR | MMTYPE_IND)             # Создание HomePlug пакета отправки
        homeplug_header_rx = HomePlugHeader(CM_ATTEN_CHAR | MMTYPE_RSP)             # Создание HomePlug пакета приема
        atten_charac = AtennChar(                                                   # Создание MMe пакета
            source_address=self.pev_mac,
            run_id=self.run_id,
            num_sounds=self.num_total_sounds,
            num_groups=self.num_groups,
            aag=self.aag,
        )
        frame_to_send = (                                   
            ether_header.pack_big()
            + homeplug_header_tx.pack_big()
            + atten_charac.pack_big()
        )
        
        await self.send_frame(frame_to_send)                # Отправка CM_ATTEN_CHAR.IND

        try:
            data_rcvd = await self.rcv_frame(                       # Ожидание CM_ATTEN_CHAR.RSP
                rcv_frame_rx=homeplug_header_rx,
                timeout=Timers.SLAC_RESP_TIMEOUT,
            )
            #logger.debug(f"Payload Received: \n {hexlify(data_rcvd)}")

            atten_charac_response = AtennCharRsp.from_bytes(data_rcvd)  # Извлечение данных
        except Exception as e:
            logger.error(e)
            raise e

        if (self.run_id != atten_charac_response.run_id):           # Проверка идентификатора сессии
            logger.error(atten_charac_response)
            e = ValueError(                                         # По [V2G3-A09-47] должны игнорировать битые пакеты,
                "AttenChar Resp Failed, ether type or homeplug "    # но при этом C_EV_match_retry = 2, так что для упрощения
                "frame are incorrect."                              # вызываем исключение
            )
            logger.error(e)
            raise e

        if atten_charac_response.result != 0:                   # Проверка результата в сообщении
            e = ValueError("Atten Char Resp Failed: Atten Char Result " "is not 0x00")
            logger.error(e)
            raise e
        logger.debug("CM_ATTEN_CHAR: Finished!")
        logger.debug(f"Num sounds received {self.num_total_sounds}")
        logger.debug(f"Num total sounds: {self.num_total_sounds}")
        logger.debug(f"Num expected sounds: {self.num_expected_sounds}")

    async def cm_slac_match(self):                      # Обработка сообщений на передачу параметров приватной сети
        logger.debug("CM_SLAC_MATCH: Started...")
        try:
            homeplug_header_rx = HomePlugHeader(CM_SLAC_MATCH | MMTYPE_REQ)             # Создание HomePlug пакета приема
            data_rcvd = await self.rcv_frame(                       # Ожидание CM_SLAC_MATCH.REQ
                rcv_frame_rx = homeplug_header_rx,
                timeout=Timers.SLAC_MATCH_TIMEOUT,
            )

            #logger.debug(f"Payload Received: \n {hexlify(data_rcvd)}")
            slac_match_req = MatchReq.from_bytes(data_rcvd)         # Извлечение данных
        except Exception as e:
            logger.error(e)
            raise ValueError("SLAC Match Failed") from e

        if (slac_match_req.run_id != self.run_id):                  # Проверка идентефикатора сессии
            logger.debug(
                f"RunId: {slac_match_req.run_id} \n " f"Expected: {self.run_id}"
            )
            raise ValueError("SLAC Match Request Failed") # По [V2G3-A09-98] должны игнорировать битые пакеты,
                                                          # но для упрощения вызываем исключение

        self.pev_id = slac_match_req.pev_id
        self.pev_mac = slac_match_req.pev_mac

        ether_header = EthernetHeader(dst_mac=self.pev_mac, src_mac=self.evse_mac)      # Создание Eth пакета
        homeplug_header = HomePlugHeader(CM_SLAC_MATCH | MMTYPE_CNF)                    # Создание HomePlug пакета отправки
        slac_match_conf = MatchCnf(                                                     # Создание MMe пакета
            pev_mac=self.pev_mac,
            evse_mac=self.evse_mac,
            run_id=self.run_id,
            nid=self.nid,
            nmk=self.nmk,
        )
        frame_to_send = (
            ether_header.pack_big()
            + homeplug_header.pack_big()
            + slac_match_conf.pack_big()
        )
        await self.send_frame(frame_to_send)                                            # Отправка пакета CM_SLAC_MATCH.CNF

        logger.debug("CM_SLAC_MATCH: Finished!")
        self.state = STATE_MATCHED

    async def is_link_status_active(self) -> bool:
        """
        Фрагмент от Intec для проверки состояния линии.
        Периодическая отправка HPGP LINK_STATUS.REQ пакета.
        Отправка должна осуществляться только после получения CM_SLAC_MATCH.CNF.
        """
        logger.debug("Checking Link Status: Started...")

        ethernet_header = EthernetHeader(                                   # Создание Eth пакета
            dst_mac=self.evse_plc_mac, src_mac=self.evse_mac
        )

        mmv         = b"\x00"                                               # Формирование не стандартного сообщения
        mm_type     = CM_LINK_STATUS | MMTYPE_REQ
        vendor_mme  = 0x00B052
        homeplug_header_no_fragm    = mmv + mm_type.to_bytes(2, "little")
        link_status_req_payload     = vendor_mme.to_bytes(3, "big")

        frame_to_send = (
            ethernet_header.pack_big()
            + homeplug_header_no_fragm
            + link_status_req_payload
        )
        await self.send_frame(frame_to_send)                                            # Отправка пакета LINK_STATUS.REQ

        try:
            homeplug_header_rx = HomePlugHeader(CM_LINK_STATUS | MMTYPE_CNF)             # Создание HomePlug пакета приема
            data_rcvd = await self.rcv_frame(                       # Ожидание CM_LINK_STATUS.CNF
                rcv_frame_rx = homeplug_header_rx,
                timeout=Timers.SLAC_TOTAL_REPETITIONS_TIMEOUT,
                base_set = False,
            )
            #logger.debug(f"Payload Received {data_rcvd}")
        except Exception as e:
            logger.error(e)
            logger.debug("Link Status: Error")
            return False
        logger.debug("Link Status: Active")
        return True

    async def atten_charac_routine(self):           # Последовательность событий из основного цикла установки сопряжения
        await self.cm_start_atten_charac()
        await self.cm_sounds_loop()
        await self.cm_atten_char()
        await self.cm_slac_match()


class SlacSessionController:                       # Обрабатывает текущее состояние по базовым сигналам, FSM
    def __init__(self):
        logger.info(
            f"\n\n#################################################"
            f"\n ###### Starting PySlac version: {version__} #######"
            f"\n#################################################\n"
        )
        self.cp_state_prev = ' '

    async def notify_matching_ongoing(self, evse_id: str):  #Эквиваленты  D-LINK_ индикаторам
        """
        Начался процесс установки сопряжения
        """
        data_link_data.SetState(f"ongoing:{evse_id}")
        pass

    async def notify_matching_failed(self, evse_id: str):
        """
        Процесс сопряжения провалился
        """
        data_link_data.SetState(f"failed:{evse_id}")
        pass

    async def notify_matching_completed(self, evse_id: str):
        """
        Процесс сопряжения завершился успешно
        """
        data_link_data.SetState(f"completed:{evse_id}")
        pass

    async def process_cp_state(self, slac_session : "SlacEvseSession", state: str):     #Обработчик состояний базовых сигналов
        """
        Если процесc согласования не запущен и был задетектирован переход в состояние
        B, C или D, то тогда создается задача сопряжения.
        Если же был задетектирован переход в состояние A, E или F и процесс сопряжения запущен И успешно 
        завершен, то эта задача удаляется.
        Если же был задетектирован переход в состояние E или F и процесс сопряжения запущен И НЕ завершен,
        то ничего не делается, поскольку EVSE может устанавливать состояния E или F,
        если EIM будет завешен до конца сопряжения.
        """
                                # Состояния могут состояить как из букв, так и из комбинации буквы и цифры
                                # (например A1, A2); Цифра нас не интересует, так что извлекаем только букву 
        cp_state = state[0]
        if(cp_state == self.cp_state_prev): # Сравнение с прошлым значением
            return
        self.cp_state_prev = cp_state

        logger.debug(f"CP State Received: {state}")                            
        if (cp_state in ["A", "E", "F"] and slac_session.matching_process_task):
            if cp_state == "A" or slac_session.state == STATE_MATCHED:
                                # Завершаем задачу, если обнаружен переход в состояние A,
                                # или в состояние E/F (при условии установленного сопряжения 'Matched')
                await cancel_task(slac_session.matching_process_task)
                logger.debug("Matching process task canceled")
                                # Выход из приватной сети, перегенерация параметров
                
                await base.SetPWM(100) 
                await slac_session.leave_logical_network()
                slac_session.matching_process_task = None
                logger.debug("Leaving Logical Network")

        elif(cp_state in ["B", "C", "D"] and                    
                                # Задачи нет или она завершена (в том числе с ошибкой)
            (slac_session.matching_process_task is None or slac_session.matching_process_task.done())):

                                                                    # Создаем задачу сопряжения
            slac_session.matching_process_task = asyncio.create_task(
                self.start_matching(slac_session)
            )
            slac_session.matching_process_task.set_name(
                f"Session for EVSE {slac_session.evse_id}"
            )
                                                                    # Для обработки исключений фоновой задачи
            slac_session.matching_process_task.add_done_callback(task_callback)

    async def start_matching(                                       
        self, slac_session: "SlacEvseSession", number_of_retries=3                      # Алгорим сопряжения с EV
    ) -> None:
        """
        Запуск алгоритма сопряжения с EV. Максимальное число попыток по ISO 15118-3 - 3 раза.
        """
        await base.SetPWM(5)            # Устанавливаем ШИМ на контакте CP = 5%
        
        try:
            while (number_of_retries > 0):
                number_of_retries -= 1          # Уменьшаем счетчик допустимых попыток
                            ### Условный этап 1 ###
                try:
                    await slac_session.evse_slac_parm()
                except Exception as e:
                    slac_session.state = STATE_UNMATCHED
                    logger.debug(
                        f"Exception Occurred during Evse Slac Parm:"
                        f"{e} \n"
                        f"Number of retries left {number_of_retries}"
                    )  
                            ### Условный этап 2 ###
                if slac_session.state == STATE_MATCHING:
                    logger.info(
                        f"Matching ongoing (EVSE ID: {slac_session.evse_id}. Run ID: {slac_session.run_id})."
                    )
                    await self.notify_matching_ongoing(slac_session.evse_id)  # Вызываем внешнее уведомление
                    try:
                        await slac_session.atten_charac_routine()             # Обработка последовательности основных сообщений
                    except Exception as e:
                        slac_session.state = STATE_UNMATCHED
                        logger.debug(
                            f"Exception Occurred during Attenuation Charc Routine:"
                            f"{e} \n"
                            f"Number of retries left {number_of_retries}"
                        )
                            ### Условный этап 3 ###
                if slac_session.state == STATE_MATCHED:
                    logger.info(
                        f"PEV-EVSE MATCHED Successfully, Link Established (EVSE ID: {slac_session.evse_id}. Run ID: {slac_session.run_id})."
                    )
                    await self.notify_matching_completed(slac_session.evse_id)

                    while (data_link_data.GetTerminate() == False):
                        await asyncio.sleep(2.0)        # Подключение успешно установлено, переодическая проверка соединения
                        if(await slac_session.is_link_status_active() == False):
                            break
                    logger.warning("A command from the supreme commander to terminate")

                    number_of_retries = 0
                    slac_session.state = STATE_UNMATCHED

                if slac_session.state == STATE_UNMATCHED:           # Не получили нужного пакета
                    if number_of_retries > 0:
                        logger.warning("PEV-EVSE MATCHED Failed; Retrying..")
                    
                        await base.SetPWM(0,Lock=True)     # Состояние E
                        await asyncio.sleep(4)          
                        await base.SetPWM(5,Unlock=True)   
                        
                    else:
                        logger.error("PEV-EVSE MATCHED Failed: No more retries " "possible")
                        await self.notify_matching_failed(slac_session.evse_id)             # Вызываем внешнее уведомление
                else:
                    logger.error(f"SLAC State not recognized {slac_session.state}")

        except Exception as e:
             logger.error(f"SLAC Protocol Global Error... \n {e}")
        logger.debug("SLAC Protocol Concluded...")

        await base.SetPWM(100) 
        await slac_session.leave_logical_network()

