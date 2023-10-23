# evse_frimware
Основной репозиторий проекта, устанавливается на одноплатный компьютер с Linux:
_PLC_PYTHON - физический канальный уровень общения с PLC модем (см. раздел 4
Процесс установки связи на физическом и канальном уровне через PLC).
_SDP_PYTHON - сервис поиска зарядки (см. раздел 5 Процесс определения SECC через SDP).
_V2G_PYTHON - сервис V2G для высокоуровненного общения EVSE и EV (см. раздел 6
Процесс общения в V2G цикле).
base.py - сервер работы с базовым сигналом (CP/PE).

Зависимости Python, необходимые для работы ПО на Linux:
netifaces==0.11.0
psutil==5.9.5
scapy==2.5.0
py4j==0.10.9.7
pydantic==2.4.2
typing_extensions==4.8.0
pyserial==3.5
