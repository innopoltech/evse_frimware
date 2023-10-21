import xmlrpc.client
import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("client_datalink")

class DataLink():                       # Базовый класс клиента RPC
    def __init__(self):
        self.lock    = False
        self.open    = False
    
    def OpenLINK(self, address):
        if(self.open == False):         # Подключаемся к RPC серверу
            try:
                self.client  = xmlrpc.client.ServerProxy(address, use_builtin_types=True, verbose=False)
                # _ = self.client.check()
                self.address = address
                self.open    = True              
                logger.debug(f"Connected to the datalink server!")
            except Exception as e:
                logger.error(f"datalink server not available!")
                raise Exception from e
    
    def CloseLINK(self):
        if(self.open == False):
            return
        
        try:
            self.client.__close()
        except  Exception:
            pass

        self.open = False

    async def Restart(self):
        try_ = 3
        print("restart")
        while (try_ > 0):
            logger.warning(f"Trying to reconnect to datalink server: {try_} left")
            try_ -= 1
            try:
                self.CloseLINK()
                self.OpenLINK(self.address)
                break
            except Exception as e:
                logger.error(f"Failed to connect to datalink server: {e}")
                await asyncio.sleep(0.5)
        
        if(try_ == 0):
            raise Exception("Running out of connection attempts to datalink server")

    def Lock(self):
        self.lock = True
    
    def Unlock(self):
        self.lock = False



class ClientDataLink(DataLink):
    """
    Клиент PRC. Позволяет обмениваться информацией с сервером базовых сигналов.
    """
    def __init__(self):
        super().__init__()

    async def Terminate(self):
        '''
        Отправка сигнала для завершения связи по канальному уровню
        '''
        if(not hasattr (self, "client")):   # Запрос без подключения не допустим
            raise AttributeError("The data_link client has no exist")
        
        try:
            await asyncio.to_thread(self.client.SetTerminate)
        except Exception as e:
            logger.error(f"In data_link  client (SetTerminate): {e}")
            await self.Restart()                     # В случае ошибки перезапускаем подключение
            await asyncio.to_thread(self.client.SetTerminate)

        return 
    
datalink = ClientDataLink() # Необходим только один экземпляр