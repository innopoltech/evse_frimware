import asyncio
import logging
from typing import Coroutine, List

logger = logging.getLogger(__name__)


async def cancel_task(task):
    """Безопасная отмена задачи"""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


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
