import asyncio
import logging
from typing import Coroutine, List

logger = logging.getLogger(__name__)


# def _format_list(read_settings: List[str]) -> List[str]:
#     read_settings = list(filter(None, read_settings))
#     read_settings = [setting.strip().upper() for setting in read_settings]
#     read_settings = list(set(read_settings))
#     return read_settings


# def load_requested_protocols(read_protocols: Optional[List[str]]) -> List[Protocol]:
#     supported_protocols = [
#         "ISO_15118_2",
#         "ISO_15118_20_AC",
#         "ISO_15118_20_DC",
#         "DIN_SPEC_70121",
#     ]

#     protocols = _format_list(read_protocols)
#     valid_protocols = list(set(protocols).intersection(supported_protocols))
#     if not valid_protocols:
#         raise NoSupportedProtocols(
#             f"No supported protocols configured. Supported protocols are "
#             f"{supported_protocols} and could be configured in evcc_config.json"
#         )
#     supported_protocols = [Protocol[x] for x in valid_protocols]
#     return supported_protocols

# def load_requested_auth_modes(read_auth_modes: Optional[List[str]]) -> List[AuthEnum]:
#     default_auth_modes = [
#         "EIM",
#         "PNC",
#     ]
#     auth_modes = _format_list(read_auth_modes)
#     valid_auth_options = list(set(auth_modes).intersection(default_auth_modes))
#     if not valid_auth_options:
#         raise NoSupportedAuthenticationModes(
#             f"No supported authentication modes configured. Supported auth modes"
#             f" are {default_auth_modes} and could be configured in .env"
#             f" file with key 'AUTH_MODES'"
#         )
#     return [AuthEnum[x] for x in valid_auth_options]


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
