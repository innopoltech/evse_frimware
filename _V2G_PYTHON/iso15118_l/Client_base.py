import xmlrpc.client
import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("client_base")

class BaseLink():                       # Базовый класс клиента RPC
    def __init__(self):
        self.lock    = False
        self.open    = False
    
    def OpenLINK(self, address):
        if(self.open == False):         # Подключаемся к RPC серверу базовых сигналов
            try:
                self.client  = xmlrpc.client.ServerProxy(address, use_builtin_types=True, verbose=False)
                _ = self.client.check()
                self.address = address
                self.open    = True              
                logger.debug(f"Connected to the base server!")
            except Exception as e:
                logger.error(f"Base server not available!")
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
            logger.warning(f"Trying to reconnect to base server: {try_} left")
            try_ -= 1
            try:
                self.CloseLINK()
                self.OpenLINK(self.address)
                break
            except Exception as e:
                logger.error(f"Failed to connect to base server: {e}")
                await asyncio.sleep(0.5)
        
        if(try_ == 0):
            raise Exception("Running out of connection attempts to base server")

    def Lock(self):
        self.lock = True
    
    def Unlock(self):
        self.lock = False



class ClientBase(BaseLink):
    """
    Клиент PRC. Позволяет обмениваться информацией с сервером базовых сигналов.
    """
    def __init__(self):
        super().__init__()

    async def GetState(self):
        '''
        Запрос текущего состояния линии CP по напряжению
        '''
        if(not hasattr (self, "client")):   # Запрос без подключения не допустим
            raise AttributeError
        
        while(self.lock):                   # Обработка блокировки приема
            await asyncio.sleep(0.5)

        try:
            volt = await asyncio.to_thread(self.client.ReadVOLT)
        except Exception as e:
            logger.error(f"In basic signals client (GetState): {e}")
            await self.Restart()             # В случае ошибки перезапускаем подключение
            return 'F'

        state = 'F'
        if(volt >= 10 and volt <= 13):      # Конвертация напряжения CP (int)(Вольт) в состояние линии ('A','B','C'...)
            state = 'A'
        elif(volt >= 7 and volt <= 10):
            state = 'B'
        elif(volt >= 4 and volt <= 7):
            state = 'C'
        elif(volt >= 2 and volt <= 4):
            state = 'D'
        else:
            state = 'E'
        return state

    async def SetPWM(self, PWM, Lock=False, Unlock=False):
        '''
        Установка % заполнения ШИМ сигнала по линии CP. Позволяет также управлять блокировкой приема.
        '''
        if(not hasattr (self, "client")):   # Запрос без подключения не допустим
            raise AttributeError("The basic signals client has no exist")
        
        if(Lock):
            self.Lock()
        
        try:
            await asyncio.to_thread(self.client.WritePWM, PWM)
        except Exception as e:
            logger.error(f"In basic signals client (SetPWM): {e}")
            await self.Restart()                     # В случае ошибки перезапускаем подключение
            await asyncio.to_thread(self.client.WritePWM, PWM)

        if(Unlock):
            self.Unlock()

        return 
    
base = ClientBase() # Необходим только один экземпляр