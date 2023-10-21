import asyncio
from binascii import hexlify
import threading
import logging
import queue

from .enums import ETH_TYPE_HPAV, BROADCAST_ADDR
from .layer_2_headers import HomePlugHeader, EthernetHeader
from scapy.all import (Ether, sniff, sendp)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("async_socket")


class socket():    # Для платформонезависимости использования, сокет переопределяется на виртуальный
    '''
    Кастомный сокет. Работа с пакетами через библиотеку scapy.
    '''

    '''Функции в базовом потоке'''
    def __init__(self, iface):
        self.iface  = iface
        self.filter = ETH_TYPE_HPAV.to_bytes(2,"big")
        self.queue           : queue = queue.Queue()
        self.running         : bool = False
        self.sniffer_thread  : threading.Thread = None

    def set_iface(self, iface) -> None:
        self.iface =  iface

    def get_iface(self) -> str:
        return self.iface
    
    def get_queue(self) -> queue:
        return self.queue
    
    def get_runnnig(self) -> bool:
        return self.running

    def sock_sendall(self, frame_) -> None:
        eth_frame = Ether(frame_)
        sendp(eth_frame, iface=self.iface, verbose=False)          # Scapy отправка raw пакета в сетевой интерфейс

    def run(self):                         # Запуск цикла приема и фильтрации сообщений в отдельном потоке
        if(self.running == True):
            return
        self.running = True
        self.sniffer_thread = threading.Thread(target=self.packet_rx_loop)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def close(self) -> None:
        pass

    '''Функции в отдельном потоке'''
    def packet_handler(self,packet):                                # Фильтрация по типу eth кадра
        raw = bytes(packet)                                         # 12-14 байты - тип кадра Eth
        if(raw[12:14] == self.filter):                              # Для нашего случая должны быть [0x88,0xE1] (ETH_TYPE_HPAV)
            if(self.queue.qsize() < 999):
                #print(packet.show())
                self.queue.put(raw)                                 # Добавление пакета в очередь приема

    def packet_rx_loop(self):
        try:
            sniff(iface= self.iface, prn=self.packet_handler)       # Scapy перехват пакетов
        except Exception as e:                                      # Сброс потока в случае возникновения исключения
            self.running = False
            logger.error(e)
            logger.debug("Sudden socket outage...")

local_socket = socket("")   # Необходим только один экземпляр


def create_socket(iface: str) -> socket:
    """
    Устанавливает интерфейс, всегда возвращает singleton сокета
    """
    local_socket.set_iface(iface)

    if (local_socket.get_runnnig() == False):      # Запуск цикла приема сообщений, если он еще не запущен
       local_socket.run()

    return local_socket


async def sendeth(frame_to_send: bytes, s: socket = None):
    """
    Отправка raw пакета в сетевой интерфейс
    """
    if(len(frame_to_send) < 60):
        padding_bytes = b"\x00" * (60 - len(frame_to_send))     # Дополнение нулями до минимального размера в 60 байт
        frame_to_send = frame_to_send + padding_bytes
    #print("###########",hexlify(frame_to_send))
    s.sock_sendall(frame_to_send)

    return None                                                 # Функция не поддерживает ожидание

async def readeth(s: socket = None, rcv_frame_rx: HomePlugHeader = None, dst_mac : bytes = None,
                  base_set : bool = True) -> bytes:
    """
    Ожидание нужного raw пакета из очереди приема сокета
    """
    if(rcv_frame_rx == None):               # Необходим для фильтрации сообщений
        raise TypeError("No HomePlugHeaderRX has been provided")       
    
    #time_start = time_now_ms()
    if (local_socket.get_runnnig() == False):      # Запуск цикла приема сообщений, если он еще не запущен
       local_socket.run()

    #logger.debug("Start of waiting for packet reception")

    queue_ : queue = s.get_queue()         
    while True:                             # Проверка сообщений в очереди
        try:
            raw = queue_.get_nowait()[:]    # Не блокирующая попытка получить копию кадра из очереди
            queue_.task_done()
            try:
                Eth_header = EthernetHeader.from_bytes(raw)    # Извлекаем шапку Ethernet из raw пакета
                HP_header  = HomePlugHeader.from_bytes(raw)    # Извлекаем шапку HomePlug из raw пакета
                
                if(base_set == True):          # В базовый набор входят сообщения представленные в HPGP
                    if( 
                        (Eth_header.dst_mac == BROADCAST_ADDR    or
                        Eth_header.dst_mac == dst_mac          )
                                                                and # Проверка MAC адреса получателя
                    HP_header.fmid       == rcv_frame_rx.fmid and
                    HP_header.fmsn       == rcv_frame_rx.fmsn and   # Проверка пакета HomePlug, в частотности типа ответа
                    HP_header.mmv        == rcv_frame_rx.mmv  and 
                    HP_header.mm_type    == rcv_frame_rx.mm_type):
                        return raw                                  # Пакет именно тот, что и ожидался
                else:                           # В остальное включены сообщения "Vendor Specific"
                    mm_type_rcvd = int.from_bytes(raw[15:17], "little")
                    if( 
                        (Eth_header.dst_mac == BROADCAST_ADDR    or
                        Eth_header.dst_mac == dst_mac          ) 
                                                                 and
                        HP_header.mm_type    == mm_type_rcvd):
                        return raw                                  # Пакет именно тот, что и ожидался

            except ValueError:                  # Битые пакеты игнорируются
                pass
        except queue.Empty:                     # Перехват только исключения пустой очереди
            #print("Time", (time_now_ms()- time_start)/1000.0)
            await asyncio.sleep(0.1)
