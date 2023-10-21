import logging
from dataclasses import dataclass
from typing import List, Type

from iso15118_l.controller.interface import EVSEControllerInterface
from iso15118_l.controller.interface import EVSessionContext
from iso15118_l.shared.messages.enums import AuthEnum, Protocol, EnergyTransferModeEnum


logger = logging.getLogger("secc_setting")

@dataclass
class Config:
    iface                       : str = None
    addr                        : str = None
    port                        : int = None
    log_level                   : int = None
    evse_id                     : str = None
    evse_controller             : Type[EVSEControllerInterface] = None
    enforce_tls                 : bool = False
    free_charging_service       : bool = False
    free_cert_install_service   : bool = True
    allow_cert_install_service  : bool = True
    use_cpo_backend             : bool = False
    supported_protocols         : List[Protocol] = None
    supported_auth_options      : List[AuthEnum] = None
    supported_transport_mode    : List[EnergyTransferModeEnum] = None
    standby_allowed             : bool = False
    default_protocols = [
        # "DIN_SPEC_70121",     
        Protocol.ISO_15118_2      # Допускаем только ISO_15118_2
        # "ISO_15118_20_AC",
        # "ISO_15118_20_DC",
    ]
    default_auth_modes = [
        AuthEnum.EIM_V2                  # Допускаем только EIM
        # "PNC",
    ]
    default_transfer_mode = [
        EnergyTransferModeEnum.DC_CORE,
        EnergyTransferModeEnum.DC_EXTENDED,
        EnergyTransferModeEnum.DC_COMBO_CORE
    ]
    # По ISO 15118-20, SECC должен поддерживать оба набора шифров.
    ciphersuites: List[str] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDH-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256"

    verify_contract_cert_chain = False

    def load_conf(self, cs_config) -> None:
        """
        Извлечение параметров из файла и сохранение их как полей класса Config.
        """
        logger.info("SECC Extract config")
                                                # Допустим только один набор параметров
        if cs_config["number_of_evses"] != 1 or \
            (len(cs_config["parameters"]) != cs_config["number_of_evses"]):
                raise AttributeError("Number of evses provided is invalid.")

        evse_params: dict = cs_config["parameters"][0]

        self.iface      = evse_params["network_interface"]
        self.addr       = evse_params["secc_addr"]
        self.port       = evse_params["secc_port"]

        self.log_level  = evse_params["log_level"]

        self.evse_id    = evse_params["evse_id"]

        # Указывает должен ли всегда запускаться TLS, не зависимо от контекста
        self.enforce_tls: bool = evse_params["secc_enforce_tls"]

        # Является ли сервис зарядки бесплатным (определяется через OCPP)
        self.free_charging_service: bool = evse_params["free_charging_service"]
        
        # Является ли установка сертификатов бесплатной (определяется через OCPP)
        self.free_cert_install_service: bool = evse_params["free_cert_install_service"]

        # Доступен ли CPO для установки контрактных сертификатов
        self.use_cpo_backend: bool = evse_params["use_cpo_backend"]

        # Доступны ли сервисы обновления и установки сертификатов (определяется через OCPP)
        self.allow_cert_install_service: bool = evse_params["allow_cert_install_service"]

        # Список протоколов для SupportedAppProtocol (SAP).
        # Первый протокол в списке имеет высший приоритет.
        self.supported_protocols = self.default_protocols

        # Поддерживаемые варианты оплаты (EIM и/или PnC)
        self.supported_auth_options = self.default_auth_modes
        
        # Поддерживаемые методы зарядки
        self.supported_transport_mode = self.default_transfer_mode

        # Разрешено ли состояние "Standby" - пользование сервисами без потребления электроэнергии
        self.standby_allowed: bool = evse_params["standby_allowed"]

save_ev_session_context: EVSessionContext = EVSessionContext()      # Единственный экземпляр контекста сессии