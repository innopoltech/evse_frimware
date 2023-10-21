from dataclasses import dataclass

from .enums import ETH_TYPE_HPAV, HOMEPLUG_FMID, HOMEPLUG_FMSN, HOMEPLUG_MMV


@dataclass
class EthernetHeader:                                           # Работа с Ethernet пакетом
    #  6 bytes адрес назначения
    dst_mac     : bytes
    #  6 bytes адрес отправителя
    src_mac     : bytes
    #  2 bytes тип пакета
    ether_type  : int = ETH_TYPE_HPAV

    def __bytes__(self, endianess: str = "big"):
        if endianess == "big":
            return self.dst_mac + self.src_mac + self.ether_type.to_bytes(2, "big")
        return (
            self.ether_type.to_bytes(2, "little")
            + (int.from_bytes(self.src_mac, "big")).to_bytes(6, "little")
            + (int.from_bytes(self.dst_mac, "big")).to_bytes(6, "little")
        )

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: bytes):
        return cls(
            dst_mac     = payload[:6],
            src_mac     = payload[6:12],
            ether_type  = int.from_bytes(payload[12:14], "big"),
        )


@dataclass
class HomePlugHeader:                                           # Работа с HomePlug пакетом
    """
    Все сообщения определенные в HomePlug GREEN PHY specification 1.0 должны заполнять поле
    MMV значением 0x01. (HPGP, страница 494)

    Формат заголовок:
    | MMV | MMTYPE | FMSN | FMID |


    MMV            [1 байт]         = 0x01          : Фиксированно
    MMTYPE         [2 байта]        = X             : Допустимые значения определенны в HPGP, на странице 501, таблица 11-5
    FMSN           [1 байт]         = 0x00          : Фиксировано, порядковый номер сообщения в последовательности сообщений
    FMID           [1 байт]         = 0x00          : Фиксированно
    """

    mm_type     : int
    mmv         : bytes  = HOMEPLUG_MMV
    fmsn        : bytes = HOMEPLUG_FMSN
    fmid        : bytes = HOMEPLUG_FMID

    def __bytes__(self, endianess: str = "big"):
        if endianess == "big":
            # MMType должен быть представлен в формате little endian
            return self.mmv + self.mm_type.to_bytes(2, "little") + self.fmsn + self.fmid
        return self.fmid + self.fmsn + self.mm_type.to_bytes(2, "little") + self.mmv

    def pack_big(self):
        return self.__bytes__()

    def pack_little(self):
        return self.__bytes__("little")

    @classmethod
    def from_bytes(cls, payload: bytes):
        return cls(
            mmv             = payload[14].to_bytes(1, "big"),
            mm_type         = int.from_bytes(payload[15:17], "little"),
            fmsn            = payload[17].to_bytes(1, "big"),
            fmid            = payload[18].to_bytes(1, "big"),
        )
