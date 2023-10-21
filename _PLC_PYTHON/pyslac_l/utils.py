import asyncio
import logging
import time

from hashlib import sha256
from math import copysign
from sys import platform
from typing import Coroutine, List

import psutil
import netifaces

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("slac_utils")


def generate_nid(nmk: bytes):
    """
    Генерация NID основанного на NMK (16 рандомных байт).
    NID генерируется через рекурсивный хэш NMK 5 раз, каждый раз сбрасывая sha256 буфер.
    Затем используются первые 7 байт результата и смещенный на 4 lsb.
    Реализация алгоритма взята из
    https://github.com/qca/open-plc-utils/blob/master/key/HPAVKeyNID.c

    Процесс генерации не совпадает с указанным HPGP 1.1, глава 4.4.3.1,
    почему - не известно.
    """
    NID_LENGTH = 7

    digest = nmk
    for _ in range(5):
        _sha256 = sha256()
        _sha256.update(digest)
        digest = _sha256.digest() 

    truncated_digest = digest[:NID_LENGTH]
    last_byte = NID_LENGTH - 1
    nid = truncated_digest[:last_byte] + (truncated_digest[last_byte] >> 4).to_bytes(
        1, "big"
    )

    return nid

def half_round(x):
    """
    Вместо стандартного округления Python 3.x (http://en.wikipedia.org/wiki/Banker's_rounding).
    Реализуется более общепринятое:
    """
    return int(x + copysign(0.5, x))

def str2mac(s):
    """
    Изменяет тип MAC адреса на массив байт
    """
    if platform.startswith("linux"):
        hex_values = s.split(":")
    else:
        hex_values = s.split("-")
    byte_array = bytes([int(hex_value, 16) for hex_value in hex_values])
    return byte_array


def get_if_hwaddr(iff: str):
    """
    Получить MAC адрес выбранного интерфейса
    """
    try:
        if platform.startswith("linux"):
            interfaces = netifaces.interfaces()
            if iff in interfaces:
                ninterface_info = netifaces.ifaddresses(iff)[netifaces.AF_LINK]
                return str2mac(ninterface_info[0]['addr'])
        else:
            interfaces = psutil.net_if_addrs()
            if iff in interfaces:
                interface_info = interfaces[iff]
                for address in interface_info:
                    if address.family == psutil.AF_LINK:
                        return str2mac(address.address)

    except Exception as e:
        logger.error("An error occurred while obtaining the MAC address:", e)
        raise Exception from e
    return None

def time_now_ms():
    return round(time.time() * 1000)

async def cancel_task(task):
    """Безопасная отмена задачи"""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def task_callback(task: asyncio.Task):
    """
    Регистрация Callback для задачи.
    Когда используется asyncio.create_task задача создается в фоновом режиме и
    любые исключения не регистрируются. Поэтому должны использовать такой финт.
    https://stackoverflow.com/questions/66293545/asyncio-re-raise-exception-from-a-task
    """
    try:
        task.result()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Exception raised by task: {task.get_name()}, {e}")


async def wait_for_tasks(
    await_tasks: List[Coroutine], return_when=asyncio.FIRST_EXCEPTION
):
    """
    Одновременное выполнения нескольких задач.

    Источники:
    * https://python.plainenglish.io/how-to-manage-exceptions-when-waiting-on-multiple-asyncio-tasks-a5530ac10f02
    * https://stackoverflow.com/questions/63583822/asyncio-wait-on-multiple-tasks-with-timeout-and-cancellation

    """
    tasks = []

    for task in await_tasks:
        if not isinstance(task, asyncio.Task):
            task = asyncio.create_task(task)
        tasks.append(task)

    done, pending = await asyncio.wait(tasks, return_when=return_when)

    for task in pending:
        await cancel_task(task)

    for task in done:
        try:
            task.result()
        except Exception as e:
            logger.error(e)
