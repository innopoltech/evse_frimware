'''
Модификация - https://github.com/EVerest/ext-switchev-iso15118
'''
__version__ = "0.20.0"

import asyncio
import json
import logging
import os

from secc_settings import Config
from comm_session_handler import CommunicationSessionHandler
from iso15118_l.controller.interface import ServiceStatus
from iso15118_l.controller.v2g_interface import EVSEController
from iso15118_l.shared.exificient_exi_codec import ExificientEXICodec

from iso15118_l.Client_base import base
from iso15118_l.Client_datalink import datalink


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("main")

async def prepare(config : Config):
    logger.info(f"Starting 15118 version: {__version__}")   
                                                    
    while(True):
        try:
            v2g_evse_controller = await EVSEController.create(config=config) # Создание экземпляра контроллера
            await v2g_evse_controller.set_status(ServiceStatus.STARTING)
                                                            # Создание экземпляра сессии
            session = CommunicationSessionHandler(config, ExificientEXICodec(), v2g_evse_controller)
            await session.start_session_handler(config.iface)       # Запуск сессии
        except Exception as exc:
            logger.error(f"SECC terminated: {exc}")
            await asyncio.sleep(1.0)




async def main():
    logger.info(f"SECC Start")

    root_dir  = os.path.dirname(os.path.abspath(__file__))
    json_file = open(os.path.join(root_dir, "cs_configuration.json"))  
    cs_config = json.load(json_file)
    json_file.close()                                                  # Загрузка параметров SECC из файла

    config = Config()                                                  # Создание класса конфигурации SECC
    config.load_conf(cs_config)

    base.OpenLINK(cs_config["client_base_addr"])                       # Запуск RPC клиента базовых сигналов 
    datalink.OpenLINK(cs_config["datalink_base_addr"])                 # Запуск RPC клиента канального уровня 

    await prepare(config)



def run():
    asyncio.run(main())

if __name__ == "__main__":
    run()
