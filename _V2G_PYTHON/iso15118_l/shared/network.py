import asyncio
import logging
import socket
from ipaddress import IPv6Address
from random import randint
from typing import Tuple, Union

import psutil

from ..shared.exceptions import (
    InvalidInterfaceError,
    MACAddressNotFound,
    NoLinkLocalAddressError,
)

logger = logging.getLogger(__name__)

SDP_MULTICAST_GROUP = "FF02::1"
SDP_SERVER_PORT = 15118


def _get_link_local_addr(nic: str) -> Union[IPv6Address, None]:
    """
    Получение локального IPv6 адреса для выбранного сетевого интерфейса
    """
    nics_with_addresses = psutil.net_if_addrs()
    nic_addr_list = nics_with_addresses[nic]
    for nic_addr in nic_addr_list:
        addr_family = nic_addr[0]
        # Удаление дополнительной информации из адреса (та что после '%')
        address = nic_addr[1].split("%")[0]

        if addr_family == socket.AF_INET6 and IPv6Address(address).is_link_local:
            return IPv6Address(address)

    raise NoLinkLocalAddressError(
        f"No link-local address was found for interface {nic}"
    )


async def _get_full_ipv6_address(host: str, port: int) -> Tuple[str, int, int, int]:
    """
    loop.getaddrinfo возвращает кортеж:
        [(address_family, socktype, proto, canonname, socket_address)].

    Например:
    [ (<AddressFamily.AF_INET6: 30>, <SocketKind.SOCK_STREAM: 1>, 6, '',
    ('fe80::4fd:9dc8:b138:3bcc', 65334, 0, 5)) ]
    
    https://docs.python.org/3/library/asyncio-eventloop.html?highlight=getaddrinfo#asyncio.loop.getaddrinfo # noqa: E501
    https://docs.python.org/3/library/socket.html#socket.getaddrinfo
    """
    loop = asyncio.get_running_loop()

    # addr_info_list = socket.getaddrinfo(
    #     host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM
    # )

    addr_info_list = await loop.getaddrinfo(
        host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM
    )
    # Нам необходим только socket_address
    _, _, _, _, socket_address = addr_info_list[0]
    return socket_address


def validate_nic(nic: str) -> None:

    """
    Проверка, существует ли сетевая карта с указанным локальным адресом
    """
    try:
        _get_link_local_addr(nic)
    except KeyError as exc:
        raise InvalidInterfaceError(
            f"No interface {nic} with this name was found"
        ) from exc
    except NoLinkLocalAddressError as exc:
        raise InvalidInterfaceError(
            f"Interface {nic} has no link-local address " f"associated with it"
        ) from exc


async def get_link_local_full_addr(port: int, nic: str) -> Tuple[str, int, int, int]:
    """
    Предоставляет полный локальный IPv6 адрес.

    Например:
    ('fe80::4fd:9dc8:b138:3bcc', 65334, 0, 5) - где 0 - flowinfo, 5 - scope_id
    """
    ip_address = _get_link_local_addr(nic)

    nic_address = str(ip_address) + f"%{nic}"
    socket_address = await _get_full_ipv6_address(nic_address, port)
    return socket_address


# def get_tcp_port() -> int:
#     """
#     A port number in the range of Dynamic Ports (49152-65535) as defined in
#     IETF RFC 6335 are allowed for TCP.
#     """
#     return randint(49152, 65535)


def get_nic_mac_address(nic: str) -> str:
    """
    Возвращает MAC-адрес конкретной сетевой карты или первый MAC-адрес
    связанный с IPv6 link-local адресом.
    """
    nics_with_addresses = psutil.net_if_addrs()
    nic_addr_list = nics_with_addresses[nic]
    for addr in nic_addr_list:
        if addr.family == psutil.AF_LINK:
            return addr.address
    raise MACAddressNotFound(f"MAC not found for NIC {nic}")
