'''
Модификация - https://github.com/SwitchEV/pyslac
'''

import asyncio
import json
import logging
import os

from pyslac_l.session import SlacEvseSession, SlacSessionController
from pyslac_l.utils import wait_for_tasks
from pyslac_l.Client_base import base
from pyslac_l.Server_data_link import datalink

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("main")                                    # Настройка логера

async def enable_hlc_and_trigger_slac(session):
    """
    Обработка состояний базовых сигналов
    """

    Controller = SlacSessionController()    # Контроллер сессии
    while(True):
        try:
            await base.SetPWM(100)                          # Устанавливаем ШИМ=100% 
            while(True):
                state = await base.GetState()
                await Controller.process_cp_state(session, state)
                await asyncio.sleep(0.1)
        except Exception as e:                              # Главная функция контроля зациклена
            logger.error(f"HLC_SLAC Exception!!! {e} ")
            await asyncio.sleep(1)

async def prepare(cs_config):
    logger.info("PLC SECC Prepare")
                                            # Допустима только одна сессия, с одним интерфейсом
    if cs_config["number_of_evses"] != 1 or \
        (len(cs_config["parameters"]) != cs_config["number_of_evses"]):
            raise AttributeError("Number of evses provided is invalid.")

    evse_params: dict = cs_config["parameters"][0]
    evse_id: str = evse_params["evse_id"]
    network_interface: str = evse_params["network_interface"]   # Извлечение ID и интерфейса

    try:
        slac_session = SlacEvseSession(evse_id, network_interface)      # Создание сессии
        await slac_session.evse_set_key()                               # Установка параметров приватной сети
    except Exception as e:
        logger.error(
            f"PLC chip initialization failed for "
            f"EVSE {evse_id}, interface "
            f"{network_interface}: {e}. \n"
            f"Please check your settings."
        )
        return

    await enable_hlc_and_trigger_slac(slac_session)                     # Запуск обработчика базовых сигналов

async def main():
    logger.info(f"PLC SECC Start")

    root_dir  = os.path.dirname(os.path.abspath(__file__))
    json_file = open(os.path.join(root_dir, "cs_configuration.json"))  
    cs_config = json.load(json_file)
    json_file.close()                                                  # Загрузка EVSE_ID и связанных с ними интерфейсов 

    base.OpenLINK(cs_config["client_base_addr"])                       # Запуск RPC клиента базовых сигналов 
    datalink.StartServer(cs_config["server_data_link_addr"], 
                         cs_config["server_data_link_port"])           # Запуск RPC сервера канального уровня

    tasks = [prepare(cs_config)]
    await wait_for_tasks(tasks)

def run():
    asyncio.run(main())

if __name__ == "__main__":
    run()
