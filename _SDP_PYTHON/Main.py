
'''
Проект взятый за основу - https://github.com/EVerest/ext-switchev-iso15118
'''

import asyncio
import json
import logging
import os

from sdp_l.utils import wait_for_tasks
from sdp_l.receive_loop import ReceiveLoop

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("main")                                    # Настройка логера

async def prepare(cs_config):
        
    logger.info("SDP SECC Prepare")
                                            # Допустима только одна сессия, с одним интерфейсом
    if cs_config["number_of_evses"] != 1 or \
        (len(cs_config["parameters"]) != cs_config["number_of_evses"]):
            raise AttributeError("Number of evses provided is invalid.")

    evse_params: dict = cs_config["parameters"][0]
    network_interface: str = evse_params["network_interface"]   # Извлечение параметров
    secc_addr   : str = evse_params["secc_addr"]
    secc_port   : int = evse_params["secc_port"]

    while(True):
        try:
            receive_loop = ReceiveLoop(network_interface, secc_addr, secc_port)
            await receive_loop.run()
        except Exception as e:                              # Бесконечный цикл для SDP сервера
            logger.error(f"SDP Exception!!! {e} ")
            await asyncio.sleep(1)

async def main():
    logger.info(f"SDP SECC Start")

    root_dir  = os.path.dirname(os.path.abspath(__file__))
    json_file = open(os.path.join(root_dir, "cs_configuration.json"))  
    cs_config = json.load(json_file)
    json_file.close()                                                    # Загрузка параметров

    tasks = [prepare(cs_config)]
    await wait_for_tasks(tasks)

def run():
    asyncio.run(main())

if __name__ == "__main__":
    run()
