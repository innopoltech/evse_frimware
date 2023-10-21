import logging
import threading
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("server_data_link")

class RequestHandler(SimpleXMLRPCRequestHandler):    # Указатель пути к функциям RPC сервера
    rpc_paths = ("/DATA_LINK",)


class ServerDataLinkData():                          # Экземпляр для регистрации в RPC сервере 
    def __init__(self):
        self.state = "no data"
        self.terminate : bool = False

    def SetState(self, state : str):
        self.state = state
        return 0
    
    def GetState(self):
        return self.state

    def GetTerminate(self):
        if(self.terminate == True):
            self.terminate = False
            return True
        return False
    
    def SetTerminate(self):
        self.terminate = True
        return 0

data_link_data = ServerDataLinkData()  # Необходим только один экземпляр


class ServerDataLink():                 # RPC сервер
    def __init__(self):
        self.run = False

    def StartServer(self, address, port):   # Запуск RPC сервера 
        if(self.run == True):   
            return 
        
        try:
            self.address = address
            self.port    = port
        
            self.server = SimpleXMLRPCServer((self.address, self.port), requestHandler=RequestHandler, logRequests=False)
            self.server.register_instance(data_link_data)               # Регистрация "расшариваемого" экземпляра

            server_thread = threading.Thread(target=self.server.serve_forever)  
            server_thread.daemon = True
            server_thread.start()

            self.run     = True

            logger.debug(f"Started data link server!")
        except Exception as e:
            logger.error(f"Error while starting data link server!")
            raise Exception from e

    def StopServer(self):  
        if(self.run == False):   
            return 
        
        self.server.shutdown()
        self.run = False

datalink = ServerDataLink() # Необходим только один экземпляр

