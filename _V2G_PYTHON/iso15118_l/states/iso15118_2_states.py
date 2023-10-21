
import asyncio
from datetime import datetime, timedelta
import logging
import time
from typing import List, Optional, Type, Union


from comm_session_handler import SECCCommunicationSession
from ..controller.interface import (
    EVChargeParamsLimits,
    EVSessionContext,
)
from .secc_state import StateSECC
# from ..shared.exceptions import (
#     CertAttributeError,
#     CertChainLengthError,
#     CertExpiredError,
#     CertNotYetValidError,
#     CertRevokedError,
#     CertSignatureError,
#     EncryptionError,
#     PrivateKeyReadError,
# )
from ..shared.exi_codec import EXI
from ..shared.messages.app_protocol import (
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
from ..shared.messages.datatypes import DCEVSEChargeParameter, DCEVSEStatus, DCEVSEStatusCode
# from ..shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from ..shared.messages.enums import (
    AuthEnum,
    AuthorizationStatus,
    AuthorizationTokenType,
    CpState,
    DCEVErrorCode,
    EVSEProcessing,
    IsolationLevel,
    Namespace,
    Protocol,
    SessionStopAction,
)
from ..shared.messages.iso15118_2.body import (
    # EMAID,
    AuthorizationReq,
    AuthorizationRes,
    BodyBase,
    CableCheckReq,
    CableCheckRes,
    CertificateInstallationReq,
    # CertificateInstallationRes,
    # CertificateUpdateReq,
    # CertificateUpdateRes,
    ChargeParameterDiscoveryReq,
    ChargeParameterDiscoveryRes,
    # ChargingStatusReq,
    # ChargingStatusRes,
    CurrentDemandReq,
    CurrentDemandRes,
    # MeteringReceiptReq,
    # MeteringReceiptRes,
    PaymentDetailsReq,
    # PaymentDetailsRes,
    PaymentServiceSelectionReq,
    PaymentServiceSelectionRes,
    PowerDeliveryReq,
    PowerDeliveryRes,
    PreChargeReq,
    PreChargeRes,
    ResponseCode,
    ServiceDetailReq,
    ServiceDetailRes,
    ServiceDiscoveryReq,
    ServiceDiscoveryRes,
    SessionSetupReq,
    SessionSetupRes,
    SessionStopReq,
    SessionStopRes,
    WeldingDetectionReq,
    WeldingDetectionRes,
)
from ..shared.messages.iso15118_2.datatypes import (
    ACEVSEChargeParameter,
    ACEVSEStatus,
    AuthOptionList,
    # CertificateChain,
    ChargeProgress,
    ChargeService,
    DCEVChargeParameter,
    ChargingSession,
    # DHPublicKey,
    # EncryptedPrivateKey,
    EnergyTransferModeList,
    # Parameter,
    ParameterSet,
    SAScheduleList,
    SAScheduleTuple,
    ServiceCategory,
    ServiceDetails,
    ServiceID,
    ServiceList,
    ServiceName,
    ServiceParameterList,
    # SubCertificates,
)
from ..shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from ..shared.messages.timeouts import Timeouts
from ..shared.messages.xmldsig import Signature
from ..shared.notifications import StopNotification
from ..shared.security import (
#     CertPath,
#     KeyEncoding,
#     KeyPasswordPath,
#     KeyPath,
#     build_pem_certificate_chain,
#     create_signature,
#     encrypt_priv_key,
#     get_cert_cn,
#     get_certificate_hash_data,
    get_random_bytes,
#     load_cert,
#     load_priv_key,
#     log_certs_details,
#     verify_certs,
#     verify_signature,
)
from ..shared.states import Pause, State, Terminate

from ..OCPP.ocpp_template import ocpp_temp


logger = logging.getLogger(__name__)


# ============================================================================
# |     Стандартные состояния (Для AC и DC) - ISO 15118-2                    |
# ============================================================================


class SessionSetup(StateSECC):
    """
    Обработка SessionSetupReq (ISO 15118-2)
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(message, [SessionSetupReq])
        if not msg:
            return

        session_setup_req: SessionSetupReq = msg.body.session_setup_req

        # OCPP code start #
        evcc_id : str = session_setup_req.evcc_id[0:2]
        MAC_COLONS = 5
        if session_setup_req.evcc_id.find(':') == -1:
            for i in range (MAC_COLONS):
                evcc_id+=':' + session_setup_req.evcc_id[i*2+2:i*2+4]
        ocpp_temp.evccid = evcc_id
        await self.comm_session.evse_controller.reset_evse_values()
        # OCPP code end #     

        # Проверка ID сессии, возможно это возобновление приостановленной сессии
        session_id: str = get_random_bytes(8).hex().upper()
        if msg.header.session_id == bytes(1).hex():
            # Установка новой сессии
            self.response_code = ResponseCode.OK_NEW_SESSION_ESTABLISHED
            self.comm_session.ev_session_context = EVSessionContext()
            self.comm_session.ev_session_context.session_id = session_id
        elif (
            self.comm_session.ev_session_context.session_id and
            msg.header.session_id == self.comm_session.ev_session_context.session_id
        ):
            # Восстановление приостановленной сессий
            session_id = self.comm_session.ev_session_context.session_id
            self.response_code = ResponseCode.OK_OLD_SESSION_JOINED
        else:
            # Не стандартный номер сессии,  сохраним его
            logger.warning(
                f"EVCC's session ID {msg.header.session_id} "
                f"does not match {self.comm_session.ev_session_context.session_id}. "
                f"New session ID {session_id} assigned"
            )
            self.response_code = ResponseCode.OK_NEW_SESSION_ESTABLISHED
            self.comm_session.ev_session_context = EVSessionContext()
            self.comm_session.ev_session_context.session_id = session_id

        session_setup_res = SessionSetupRes(        # Создание класса ответа
            response_code=self.response_code,
            evse_id=await self.comm_session.evse_controller.get_evse_id(
                Protocol.ISO_15118_2
            ),
            evse_timestamp=int(time.time()),
        )

        self.comm_session.evcc_id = session_setup_req.evcc_id
        self.comm_session.session_id = session_id

        self.create_next_message(       # Создание сообщения для ответа, установка нового состояния
            ServiceDiscovery,
            session_setup_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )


class ServiceDiscovery(StateSECC):
    """
    Обработка ServiceDiscoveryReq (ISO 15118-2)

    В текущем состоянии возможно принять следующие сообщения:
    1. ServiceDiscoveryReq
    2. ServiceDetailReq
    3. PaymentServiceSelectionReq

    При первом вызове явно ожидается только ServiceDiscoveryReq, в последующих вызовах
    это может быть либо  ServiceDetailReq, либо PaymentServiceSelectionReq.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_service_discovery_req: bool = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(        # Проверка сообщения
            message,
            [ServiceDiscoveryReq, ServiceDetailReq, PaymentServiceSelectionReq],
            self.expecting_service_discovery_req,
        )
        if not msg:
            return
                # В случае сообщений service_detail_req и payment_service_selection_req, обработка на стороне
        if msg.body.service_detail_req: 
            await ServiceDetail(self.comm_session).process_message(message, message_exi)
            return

        if msg.body.payment_service_selection_req:
            await PaymentServiceSelection(self.comm_session).process_message(
                message, message_exi
            )
            return

        if msg.body.service_discovery_req and not self.expecting_service_discovery_req:
            self.stop_state_machine(
                f"{str(message)}' not accepted in state " f"{str(self)}",
                message,
                ResponseCode.FAILED_SEQUENCE_ERROR,
            )
            return
            # Обработка ServiceDiscoveryReq
        service_discovery_req: ServiceDiscoveryReq = msg.body.service_discovery_req
        service_discovery_res = await self.get_services(    # Извлечение категории запрашиваемых сервисов
            service_discovery_req.service_category
        )

        self.create_next_message( 
            None,
            service_discovery_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_service_discovery_req = False

    async def get_services(
        self, category_filter: ServiceCategory
    ) -> ServiceDiscoveryRes:
        """
        Предоставляем все допустимые сервисы, включая обязательный сервис зарядки 
        """
        auth_options: List[AuthEnum] = []

        if self.comm_session.ev_session_context.auth_options:
            logger.info("AuthOptions available in context. This is a resumed session.")
            # Если сессия восстановлена, то извлекаем сохранный метод авторизации
            auth_options = self.comm_session.ev_session_context.auth_options
        elif self.comm_session.selected_auth_option:
            # Если метод авторизации уже был выбран ранее
            if self.comm_session.selected_auth_option == AuthEnum.EIM_V2:
                auth_options.append(AuthEnum.EIM_V2)
            else:
                auth_options.append(AuthEnum.PNC_V2)
        else:
            # OCPP code start #
            evse_payment_options: list = await self.comm_session.evse_controller.get_evse_payment_options()
            for payment_options in evse_payment_options:
                auth_options.append(AuthEnum(payment_options))
            if AuthEnum.PNC_V2 in auth_options and not self.comm_session.is_tls:
                auth_options.remove(AuthEnum.PNC_V2)
            # OCPP code end #

        self.comm_session.offered_auth_options = auth_options

        energy_modes = (    # Допустимые режимы зарядки
            await self.comm_session.evse_controller.get_supported_energy_transfer_modes(
                Protocol.ISO_15118_2
            )
        )

        if self.comm_session.ev_session_context.charge_service:
            logger.info("ChargeService available in context. This is a resumed session.")
            charge_service = self.comm_session.ev_session_context.charge_service
        else:
            charge_service = ChargeService(     # Создание класса сервиса зарядки
                service_id=ServiceID.CHARGING,
                service_name=ServiceName.CHARGING,
                service_category=ServiceCategory.CHARGING,
                free_service= await self.comm_session.evse_controller.is_free(),
                supported_energy_transfer_mode=EnergyTransferModeList(
                    energy_modes=energy_modes
                ),
            )
            self.comm_session.ev_session_context.charge_service = charge_service

        service_list: List[ServiceDetails] = []
        # Дополнительные сервисы (VAS), доступны только если подключение защищено TLS.
        # if self.comm_session.is_tls:
        #     if await self.comm_session.evse_controller.allow_cert_install_service() and (
        #         category_filter is None
        #         or category_filter == ServiceCategory.CERTIFICATE
        #     ):
        #         cert_install_service = ServiceDetails(
        #             service_id=2,
        #             service_name=ServiceName.CERTIFICATE,
        #             service_category=ServiceCategory.CERTIFICATE,
        #             free_service=self.comm_session.config.free_cert_install_service,
        #         )

        #         service_list.append(cert_install_service)

        # списки необязательных параметров в EXI не могут быть пустыми, поэтому передается как None
        offered_services = None
        if len(service_list) > 0:
            offered_services = ServiceList(services=service_list)

        service_discovery_res = ServiceDiscoveryRes(
            response_code=ResponseCode.OK,
            auth_option_list=AuthOptionList(auth_options=auth_options),
            charge_service=charge_service,
            service_list=offered_services,
        )

        self.comm_session.offered_services = service_list

        return service_discovery_res


class ServiceDetail(StateSECC):
    """
    Обработка ServiceDetailReq (ISO 15118-2)

    В текущем состоянии возможно принять следующие сообщения:
    1. ServiceDetailReq
    2. PaymentServiceSelectionReq

    EVCC может отправлять ServiceDetailReq несколько раз, для каждой существующей услуги.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_service_detail_req: bool = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [ServiceDetailReq, PaymentServiceSelectionReq],
            self.expecting_service_detail_req,
        )
        if not msg:
            return

            # Обработка payment_service_selection_req на стороне
        if msg.body.payment_service_selection_req:
            await PaymentServiceSelection(self.comm_session).process_message(
                message, message_exi
            )
            return
            # Обработка ServiceDetailReq
        service_detail_req: ServiceDetailReq = msg.body.service_detail_req

        is_found = False
        for service_details in self.comm_session.offered_services:  # Проверка, что запрашиваемый сервис был предложен ранее
            if service_detail_req.service_id == service_details.service_id:
                is_found = True
                break

        if not is_found:
            # По [V2G2-425] SECC должен ответить ResponseCode='FAILED_ServiceIDInvalid',
            # если запрашиваемый сервис не был преложен ранее
            error_service_detail_res = ServiceDetailRes(
                response_code=ResponseCode.FAILED_SERVICE_ID_INVALID,
                service_id=service_detail_req.service_id,
            )
            self.create_next_message(
                None,
                error_service_detail_res,
                Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
                Namespace.ISO_V2_MSG_DEF,
            )
            logger.error(f"Service ID is invalid for {message}")
            return

        parameter_set: List[ParameterSet] = []

        # Если запрашивается Certificate installation
        # if service_detail_req.service_id == ServiceID.CERTIFICATE:
        #     install_parameter = Parameter(name="Service", str_value="Installation")
        #     install_parameter_set = ParameterSet(
        #         parameter_set_id=1, parameters=[install_parameter]
        #     )
        #     parameter_set.append(install_parameter_set)
        #     update_parameter = Parameter(name="Service", str_value="Update")
        #     update_parameter_set = ParameterSet(
        #         parameter_set_id=2, parameters=[update_parameter]
        #     )
        #     parameter_set.append(update_parameter_set)

        # Если запрашивается Internet service
        # if service_detail_req.service_id == ServiceID.INTERNET:
        #     pass

        service_detail_res = ServiceDetailRes(
            response_code=ResponseCode.OK,
            service_id=service_detail_req.service_id,
            service_parameter_list=ServiceParameterList(parameter_set=parameter_set),
        )

        self.create_next_message(
            None,
            service_detail_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_service_detail_req = False


class PaymentServiceSelection(StateSECC):
    """
    Обработка PaymentServiceSelectionReq (ISO 15118-2)

    В текущем состоянии возможно принять следующие сообщения:
    1. a PaymentServiceSelectionReq
    2. a CertificateInstallationReq
    3. a PaymentDetailsReq
    4. an AuthorizationReq

    При первом вызове явно ожидается только PaymentServiceSelectionReq, в последующих вызовах
    это может быть либо  CertificateInstallationReq, либо PaymentDetailsReq, либо AuthorizationReq
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_service_selection_req: bool = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [
                PaymentServiceSelectionReq,
                CertificateInstallationReq,
                PaymentDetailsReq,
                AuthorizationReq,
            ],
            self.expecting_service_selection_req,
        )
        if not msg:
            return
                    # Не поддерживаются в текущей версии
        if msg.body.certificate_installation_req or msg.body.certificate_update_req or msg.body.payment_details_req:
            return 
        
        # if msg.body.certificate_installation_req:
        #     await CertificateInstallation(self.comm_session).process_message(
        #         message, message_exi
        #     )
        #     return
        
        # if msg.body.certificate_update_req:
        #     await CertificateUpdate(self.comm_session).process_message(
        #         message, message_exi
        #     )
        #     return

        # if msg.body.payment_details_req:
        #     await PaymentDetails(self.comm_session).process_message(
        #         message, message_exi
        #     )
        #     return

            # Обработка authorization_req на стороне
        if msg.body.authorization_req:
            await Authorization(self.comm_session).process_message(message, message_exi)
            return

            # Обработка PaymentServiceSelectionReq
        service_selection_req: PaymentServiceSelectionReq = (msg.body.payment_service_selection_req)
        selected_service_list = service_selection_req.selected_service_list

        # OCPP code start #
        ocpp_temp.selected_auth_option = service_selection_req.selected_auth_option
        # OCPP code end #

        charge_service_selected: bool = False
        for service in selected_service_list.selected_service:
            if service.service_id == ServiceID.CHARGING:
                charge_service_selected = True
                continue
            if service.service_id not in [              # Проверка на наличие выбранного сервиса
                offered_service.service_id
                for offered_service in self.comm_session.offered_services
            ]:
                self.stop_state_machine(
                    f"Selected service with ID {service.service_id} "
                    f"was not offered",
                    message,
                    ResponseCode.FAILED_SERVICE_SELECTION_INVALID,
                )
                return

        if not charge_service_selected: # Сервис зарядки должен быть выбран обязательно
            self.stop_state_machine(
                "Charge service not selected",
                message,
                ResponseCode.FAILED_NO_CHARGE_SERVICE_SELECTED,
            )
            return

        if service_selection_req.selected_auth_option.value not in [    # Если выбранный способ авторизации не доступен
            auth_option.value for auth_option in self.comm_session.offered_auth_options
        ]:
            self.stop_state_machine(
                "Selected authorization method "
                f"{service_selection_req.selected_auth_option} "
                f"was not offered",
                message,
                ResponseCode.FAILED_PAYMENT_SELECTION_INVALID,
            )
            return

        logger.debug(
            "EVCC chose authorization option "
            f"{service_selection_req.selected_auth_option.value}"
        )
        self.comm_session.selected_auth_option = AuthEnum(
            service_selection_req.selected_auth_option.value
        )

        self.comm_session.ev_session_context.auth_options: List[AuthEnum] = [
            self.comm_session.selected_auth_option
        ]

        service_selection_res = PaymentServiceSelectionRes(
            response_code=ResponseCode.OK
        )

        self.create_next_message(
            None,
            service_selection_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_service_selection_req = False


# class CertificateInstallation(StateSECC):
#     """
#     The ISO 15118-2 state in which the SECC processes a
#     CertificateInstallationReq message from the EVCC.
#     """

#     def __init__(self, comm_session: SECCCommunicationSession):
#         super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

#     async def process_message(
#         self,
#         message: Union[
#             SupportedAppProtocolReq,
#             SupportedAppProtocolRes,
#             V2GMessageV2,
#         #   V2GMessageV20,
#         #   V2GMessageDINSPEC,
#         ],
#         message_exi: bytes = None,
#     ):
#         msg = self.check_msg_v2(message, [CertificateInstallationReq])
#         if not msg:
#             return

#         if not self.validate_message_signature(msg):
#             self.stop_state_machine(
#                 "Signature verification failed for " "CertificateInstallationReq",
#                 message,
#                 ResponseCode.FAILED_SIGNATURE_ERROR,
#             )
#             return

#         # In a real world scenario we need to fetch the certificate from the backend.
#         # We call get_15118_ev_certificate method, which would be a direct mapping
#         # to the Get15118EVCertificateRequest
#         # message from OCPP 2.0.1 for the installation case.
#         # This accepts 2 arguments:
#         # 1. The raw EXI CertificateInstallationReq message coming from the EV
#         # in base64 encoded form.
#         # 2. A string that specifies `15118SchemaVersion` which would be either of
#         # "urn:iso:15118:2:2013:MsgDef" or "urn:iso:std:iso:15118:-20:CommonMessages"
#         signature = None

#         try:
#             if self.comm_session.config.use_cpo_backend:
#                 logger.info("Using CPO backend to fetch CertificateInstallationRes")
#                 # CertificateInstallationReq must be base64 encoded before forwarding
#                 # to backend.
#                 # Call to b64encode returns byte[] - hence the .decode("utf-8")
#                 base64_certificate_install_req = base64.b64encode(message_exi).decode(
#                     "utf-8"
#                 )

#                 exiRequest: dict = dict([
#                     ("exiRequest", base64_certificate_install_req),
#                     ("iso15118SchemaVersion", Namespace.ISO_V2_MSG_DEF),
#                     ("certificateAction", "Install")
#                 ])

#                 EVEREST_CTX.publish('Certificate_Request', exiRequest)

#                 # The response received below is EXI response in base64 encoded form.
#                 # Decoding to EXI happens later just before V2GTP packet is built.
#                 base64_certificate_installation_res = (
#                     await self.comm_session.evse_controller.get_15118_ev_certificate(
#                         base64_certificate_install_req, Namespace.ISO_V2_MSG_DEF
#                     )
#                 )
#                 certificate_installation_res: Base64 = Base64(
#                     message=base64_certificate_installation_res,
#                     message_name=CertificateInstallationRes.__name__,
#                     namespace=Namespace.ISO_V2_MSG_DEF,
#                 )
#             else:
#                 (
#                     certificate_installation_res,
#                     signature,
#                 ) = self.generate_certificate_installation_res()
#         except Exception as e:
#             error = f"Error building CertificateInstallationRes: {e}"
#             logger.error(error)
#             self.stop_state_machine(
#                 error,
#                 message,
#                 ResponseCode.FAILED_NO_CERTIFICATE_AVAILABLE,
#             )
#             return

#         self.create_next_message(
#             PaymentDetails,
#             certificate_installation_res,
#             Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
#             Namespace.ISO_V2_MSG_DEF,
#             signature=signature,
#         )

    # def validate_message_signature(self, message: V2GMessageV2) -> bool:
    #     # For the CertificateInstallation, the min. the SECC can do is
    #     # to verify the message signature, using the OEM provisioning
    #     # certificate (public key) - this is available in the cert installation req.
    #     # The chain of signatures, from the signature in the
    #     # CertificateInstallationReq's header all the way to the
    #     # self-signed OEM/V2G root certificate, can be verified if the
    #     # OEM Sub-CA and OEM/V2G root CA certificate are available.

    #     cert_install_req: CertificateInstallationReq = (
    #         message.body.certificate_installation_req
    #     )

    #     sub_ca_certificates_oem = None
    #     root_ca_certificate_oem = None

    #     try:
    #         sub_ca_certificates_oem = [
    #             load_cert(os.path.join(get_PKI_PATH(), CertPath.OEM_SUB_CA2_DER)),
    #             load_cert(os.path.join(get_PKI_PATH(), CertPath.OEM_SUB_CA1_DER)),
    #         ]
    #         root_ca_certificate_oem = load_cert(os.path.join(get_PKI_PATH(), CertPath.OEM_ROOT_DER))
    #     except (FileNotFoundError, IOError):
    #         pass

    #     return verify_signature(
    #         signature=message.header.signature,
    #         elements_to_sign=[
    #             (
    #                 cert_install_req.id,
    #                 EXI().to_exi(cert_install_req, Namespace.ISO_V2_MSG_DEF),
    #             )
    #         ],
    #         leaf_cert=cert_install_req.oem_provisioning_cert,
    #         sub_ca_certs=sub_ca_certificates_oem,
    #         root_ca_cert=root_ca_certificate_oem,
    #     )

    # def generate_certificate_installation_res(
    #     self,
    # ) -> (CertificateInstallationRes, Signature):
    #     # Here we create the CertificateInstallationRes message ourselves as we
    #     # have access to all certificates and private keys needed.
    #     # This is however not the real production case.
    #     # Note: the Raw EXI encoded message that includes the Header and the Body of the
    #     # CertificateInstallationReq must be used.
    #     try:
    #         dh_pub_key, encrypted_priv_key_bytes = encrypt_priv_key(
    #             oem_prov_cert=load_cert(os.path.join(get_PKI_PATH(), CertPath.OEM_LEAF_DER)),
    #             priv_key_to_encrypt=load_priv_key(
    #                 os.path.join(get_PKI_PATH(), KeyPath.CONTRACT_LEAF_PEM),
    #                 KeyEncoding.PEM,
    #                 os.path.join(get_PKI_PATH(), KeyPasswordPath.CONTRACT_LEAF_KEY_PASSWORD),
    #             ),
    #         )
    #     except EncryptionError:
    #         raise EncryptionError(
    #             "EncryptionError while trying to encrypt the "
    #             "private key for the contract certificate"
    #         )
    #     except PrivateKeyReadError as exc:
    #         raise PrivateKeyReadError(
    #             f"Can't read private key to encrypt for "
    #             f"CertificateInstallationRes: {exc}"
    #         )

    #     # The elements that need to be part of the signature
    #     contract_cert_chain = CertificateChain(
    #         id="id1",
    #         certificate=load_cert(os.path.join(get_PKI_PATH(), CertPath.CONTRACT_LEAF_DER)),
    #         sub_certificates=SubCertificates(
    #             certificates=[
    #                 load_cert(os.path.join(get_PKI_PATH(), CertPath.MO_SUB_CA2_DER)),
    #                 load_cert(os.path.join(get_PKI_PATH(), CertPath.MO_SUB_CA1_DER)),
    #             ]
    #         ),
    #     )
    #     encrypted_priv_key = EncryptedPrivateKey(
    #         id="id2", value=encrypted_priv_key_bytes
    #     )
    #     dh_public_key = DHPublicKey(id="id3", value=dh_pub_key)
    #     emaid = EMAID(
    #         id="id4", value=get_cert_cn(load_cert(os.path.join(get_PKI_PATH(), CertPath.CONTRACT_LEAF_DER)))
    #     )
    #     cps_certificate_chain = CertificateChain(
    #         certificate=load_cert(os.path.join(get_PKI_PATH(), CertPath.CPS_LEAF_DER)),
    #         sub_certificates=SubCertificates(
    #             certificates=[
    #                 load_cert(os.path.join(get_PKI_PATH(), CertPath.CPS_SUB_CA2_DER)),
    #                 load_cert(os.path.join(get_PKI_PATH(), CertPath.CPS_SUB_CA1_DER)),
    #             ]
    #         ),
    #     )

    #     cert_install_res = CertificateInstallationRes(
    #         response_code=ResponseCode.OK,
    #         cps_cert_chain=cps_certificate_chain,
    #         contract_cert_chain=contract_cert_chain,
    #         encrypted_private_key=encrypted_priv_key,
    #         dh_public_key=dh_public_key,
    #         emaid=emaid,
    #     )

    #     try:
    #         # Elements to sign, containing its id and the exi encoded stream
    #         contract_cert_tuple = (
    #             cert_install_res.contract_cert_chain.id,
    #             EXI().to_exi(
    #                 cert_install_res.contract_cert_chain, Namespace.ISO_V2_MSG_DEF
    #             ),
    #         )
    #         encrypted_priv_key_tuple = (
    #             cert_install_res.encrypted_private_key.id,
    #             EXI().to_exi(
    #                 cert_install_res.encrypted_private_key, Namespace.ISO_V2_MSG_DEF
    #             ),
    #         )
    #         dh_public_key_tuple = (
    #             cert_install_res.dh_public_key.id,
    #             EXI().to_exi(cert_install_res.dh_public_key, Namespace.ISO_V2_MSG_DEF),
    #         )
    #         emaid_tuple = (
    #             cert_install_res.emaid.id,
    #             EXI().to_exi(cert_install_res.emaid, Namespace.ISO_V2_MSG_DEF),
    #         )

    #         elements_to_sign = [
    #             contract_cert_tuple,
    #             encrypted_priv_key_tuple,
    #             dh_public_key_tuple,
    #             emaid_tuple,
    #         ]
    #         # The private key to be used for the signature
    #         signature_key = load_priv_key(
    #             os.path.join(get_PKI_PATH(), KeyPath.CPS_LEAF_PEM),
    #             KeyEncoding.PEM,
    #             os.path.join(get_PKI_PATH(), KeyPasswordPath.CPS_LEAF_KEY_PASSWORD),
    #         )

    #         signature = create_signature(elements_to_sign, signature_key)

    #     except PrivateKeyReadError as exc:
    #         raise PrivateKeyReadError(
    #             "Can't read private key needed to create signature "
    #             f"for CertificateInstallationRes: {exc}",
    #             ResponseCode.FAILED,
    #         )

    #     return cert_install_res, signature


# class CertificateUpdate(StateSECC):
#     """
#     The ISO 15118-2 state in which the SECC processes a
#     CertificateUpdateReq message from the EVCC.
#     """
#     def __init__(self, comm_session: SECCCommunicationSession):
#         super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
    
#     async def process_message(
#         self,
#         message: Union[
#             SupportedAppProtocolReq,
#             SupportedAppProtocolRes,
#             V2GMessageV2,
#         #   V2GMessageV20,
#         #   V2GMessageDINSPEC,
#         ],
#         message_exi: bytes = None,
#     ):
#         msg = self.check_msg_v2(message, [CertificateUpdateReq])
#         if not msg:
#             return

#         if not self.validate_message_signature(msg):
#             self.stop_state_machine(
#                 "Signature verification failed for " "CertificateUpdateReq",
#                 message,
#                 ResponseCode.FAILED_SIGNATURE_ERROR,
#             )
#             return
        
#         signature = None
#         try:
#             logger.info("Using CPO backend to fetch CertificateUpdateRes")
#             # CertificateInstallationReq must be base64 encoded before forwarding
#             # to backend.
#             # Call to b64encode returns byte[] - hence the .decode("utf-8")
#             base64_certificate_update_req = base64.b64encode(message_exi).decode(
#                 "utf-8"
#             )

#             exiRequest: dict = dict([
#                 ("exiRequest", base64_certificate_update_req),
#                 ("iso15118SchemaVersion", Namespace.ISO_V2_MSG_DEF),
#                 ("certificateAction", "Update")
#             ])

#             EVEREST_CTX.publish('Certificate_Request', exiRequest)

#             # The response received below is EXI response in base64 encoded form.
#             # Decoding to EXI happens later just before V2GTP packet is built.
#             base64_certificate_update_res = (
#                 await self.comm_session.evse_controller.get_15118_ev_certificate(
#                     base64_certificate_update_req, Namespace.ISO_V2_MSG_DEF
#                 )
#             )
#             certificate_update_res: Base64 = Base64(
#                 message=base64_certificate_update_res,
#                 message_name=CertificateUpdateRes.__name__,
#             )
#         except Exception as e:
#             error = f"Error building CertificateUpdateRes: {e}"
#             logger.error(error)
#             self.stop_state_machine(
#                 error,
#                 message,
#                 ResponseCode.FAILED_NO_CERTIFICATE_AVAILABLE,
#             )
#             return

#         self.create_next_message(
#             PaymentDetails,
#             certificate_update_res,
#             Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
#             Namespace.ISO_V2_MSG_DEF,
#             signature=signature,
#         )

    # def validate_message_signature(self, message: V2GMessageV2) -> bool:
    #     # For the CertificateUpdate, the min. the SECC can do is
    #     # to verify the message signature, using the contract certificate
    #     # (public key) - this is available in the cert update req.

    #     cert_update_req: CertificateUpdateReq = (
    #         message.body.certificate_update_req
    #     )

    #     return verify_signature(
    #         signature=message.header.signature,
    #         elements_to_sign=[
    #             (
    #                 cert_update_req.id,
    #                 EXI().to_exi(cert_update_req, Namespace.ISO_V2_MSG_DEF),
    #             )
    #         ],
    #         leaf_cert=cert_update_req.contract_cert_chain.certificate,
    #         sub_ca_certs=None,
    #         root_ca_cert=None,
    #     )

# class PaymentDetails(StateSECC):
#     """
#     The ISO 15118-2 state in which the SECC processes a
#     PaymentDetailsReq message from the EVCC.

#     The PaymentDetailsReq contains the EV's contract certificate and sub-CA
#     certificate(s) used to automatically authenticate and authorize for
#     charging. The EMAID (E-Mobility Account Identifier) is stored in the
#     Common Name (CN) field of the contract certificate's 'Subject' attribute
#     and is used as a credential for authorization, digitally signed by the
#     issuer of the contract certificate. The contract certificate is the leaf
#     certificate in the PaymentDetailsReq's certificate chain.

#     The SECC needs to verify the certificate chain (e.g. signature check and
#     validity check of each certificate and store the certificate chain in the
#     communication session, so it can later verify digitally signed messages
#     (such as the AuthorizationReq) from the EVCC.

#     In general, a CPO (charge point operator) can decide if they want the SECC
#     to perform this verification and validity checks locally or if the SECC
#     shall defer that task to the CPO backend.
#     """

#     def __init__(self, comm_session: SECCCommunicationSession):
#         super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

#     def _mobility_operator_root_cert_path(self) -> str:
#         """Return the path to the MO root.  Included to be patched in tests."""
#         return os.path.join(get_PKI_PATH(), CertPath.MO_ROOT_DER)

#     async def process_message(
#         self,
#         message: Union[
#             SupportedAppProtocolReq,
#             SupportedAppProtocolRes,
#             V2GMessageV2,
#         #   V2GMessageV20,
#         #   V2GMessageDINSPEC,
#         ],
#         message_exi: bytes = None,
#     ):
#         msg = self.check_msg_v2(message, [PaymentDetailsReq])
#         if not msg:
#             return

#         payment_details_req: PaymentDetailsReq = msg.body.payment_details_req

#         try:
#             leaf_cert = payment_details_req.cert_chain.certificate
#             sub_ca_certs = payment_details_req.cert_chain.sub_certificates.certificates

#             # Logging MO certificate and chain details to help with debugging.
#             log_certs_details([leaf_cert])
#             log_certs_details(sub_ca_certs)
#             # TODO There should be an OCPP setting that determines whether
#             #      or not the charging station should verify (is in
#             #      possession of MO or V2G Root certificates) or if it
#             #      should rather forward the certificate chain to the CSMS
#             # TODO Either an MO Root certificate or a V2G Root certificate
#             #      could be used to verify, need to be flexible with regards
#             #      to the PKI that is used.
#             root_cert_path = self._mobility_operator_root_cert_path()
#             pem_certificate_chain = None

#             try:
#                 root_cert = load_cert(root_cert_path)
#                 # verify contract certificate against MO root if this is enabled
#                 if (self.comm_session.config.verify_contract_cert_chain):
#                     verify_certs(leaf_cert, sub_ca_certs, root_cert)
#                 else:
#                     root_cert = None
#                     pem_certificate_chain = build_pem_certificate_chain(payment_details_req.cert_chain, root_cert)
#             except FileNotFoundError:
#                 logger.warning(f"MO Root Cert cannot be found {root_cert_path}")
#                 root_cert = None
#                 pem_certificate_chain = build_pem_certificate_chain(payment_details_req.cert_chain, root_cert)

#             # Note that the eMAID format (14 or 15 characters) will be validated
#             # by the definition of the eMAID type in
#             # shared/messages/iso15118_2/datatypes.py
#             self.comm_session.emaid = payment_details_req.emaid
#             self.comm_session.contract_cert_chain = payment_details_req.cert_chain

#             try:
#                 hash_data = get_certificate_hash_data(
#                     self.comm_session.contract_cert_chain, root_cert
#                 )
#             except Exception as e:
#                 logger.warning("Could not retrieve OCSP request data from certificate")
#                 hash_data = None
            
#             ProvidedIdToken: dict = dict([
#                 ("id_token", payment_details_req.emaid),
#                 ("authorization_type", "PlugAndCharge"),
#                 ("id_token_type", "eMAID"),
#             ])
 
#             if hash_data is not None:
#                 ProvidedIdToken.update({"iso15118CertificateHashData": hash_data})
            
#             if pem_certificate_chain is not None:
#                 ProvidedIdToken.update({"certificate": pem_certificate_chain})

#             EVEREST_CTX.publish('Require_Auth_PnC', ProvidedIdToken)

#             authorization_result = (
#                 await self.comm_session.evse_controller.is_authorized(
#                     id_token_type=AuthorizationTokenType.EMAID,
#                 )
#             )

#             if authorization_result in [
#                 AuthorizationStatus.ACCEPTED,
#                 AuthorizationStatus.ONGOING,
#             ]:
#                 self.comm_session.gen_challenge = get_random_bytes(16)
#                 payment_details_res = PaymentDetailsRes(
#                     response_code=ResponseCode.OK,
#                     gen_challenge=self.comm_session.gen_challenge,
#                     evse_timestamp=time.time(),
#                 )

#                 self.create_next_message(
#                     Authorization,
#                     payment_details_res,
#                     Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
#                     Namespace.ISO_V2_MSG_DEF,
#                 )
#             else:
#                 # TODO: investigate if it is feasible to get a more detailed
#                 # response code error

#                 # TODO_SL: Send the correct ResponseCode (for the CertificateStatus too)
#                 self.stop_state_machine(
#                     "Authorization was rejected",
#                     message,
#                     ResponseCode.FAILED_CERTIFICATE_NOT_ALLOWED_AT_THIS_EVSE,
#                 )

#         except (
#             CertSignatureError,
#             CertNotYetValidError,
#             CertExpiredError,
#             CertRevokedError,
#             CertAttributeError,
#             CertChainLengthError,
#         ) as exc:
#             reason = ""
#             if isinstance(exc, CertSignatureError):
#                 response_code = ResponseCode.FAILED_CERT_CHAIN_ERROR
#                 reason = (
#                     f"CertSignatureError for {exc.subject}, "
#                     f"tried to verify with issuer: "
#                     f"{exc.issuer}. \n{exc.extra_info}"
#                 )
#             elif isinstance(exc, CertChainLengthError):
#                 response_code = ResponseCode.FAILED_CERT_CHAIN_ERROR
#                 reason = (
#                     f"CertChainLengthError, max "
#                     f"{exc.allowed_num_sub_cas} sub-CAs allowed "
#                     f"but {exc.num_sub_cas} sub-CAs provided"
#                 )
#             elif isinstance(exc, CertExpiredError):
#                 response_code = ResponseCode.FAILED_CERTIFICATE_EXPIRED
#                 reason = f"CertExpiredError for {exc.subject}"
#             elif isinstance(exc, CertRevokedError):
#                 response_code = ResponseCode.FAILED_CERTIFICATE_REVOKED
#                 reason = f"CertRevokedError for {exc.subject}"
#             else:
#                 # Unfortunately, for other certificate-related errors
#                 # ISO 15118-2 does not have specific enough failure codes
#                 response_code = ResponseCode.FAILED
#                 reason = f"{exc.__class__.__name__} for {exc.subject}"

#             if reason:
#                 logger.error(reason)
#             self.stop_state_machine(reason, message, response_code)
#             return


class Authorization(StateSECC):
    """
    Обработка AuthorizationReq (ISO 15118-2)


    EVCC будет отправлять этот запрос до тех пор пока процесс авторизации на стороне SECC не завершится.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        # В соответствии с [V2G2-684], в случае использования PnC,
        # только первое сообщение AuthorizationReq будет содержать подпись, остальные запросы будут пустыми
        self.signature_verified_once = False
        self.authorizationRequested = False

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(message, [AuthorizationReq])

        if not msg:
            return

        authorization_req: AuthorizationReq = msg.body.authorization_req
            # PnC не поддерживается
        # if self.comm_session.selected_auth_option == AuthEnum.PNC_V2:
        #     if not self.comm_session.contract_cert_chain:
        #         self.stop_state_machine(
        #             "No contract certificate chain available to "
        #             "verify AuthorizationReq",
        #             message,
        #             ResponseCode.FAILED_SIGNATURE_ERROR,
        #         )
        #         return

        #     if not self.signature_verified_once:
        #         self.signature_verified_once = True

        #         # [V2G2-475] The message 'AuthorizationRes' shall contain
        #         # the ResponseCode 'FAILED_ChallengeInvalid' if the challenge
        #         # response contained in the AuthorizationReq message in attribute
        #         # GenChallenge is not valid versus the provided GenChallenge
        #         # in PaymentDetailsRes.
        #         if authorization_req.gen_challenge != self.comm_session.gen_challenge:
        #             self.stop_state_machine(
        #                 "[V2G2-475] GenChallenge is not the same in PaymentDetailsRes",
        #                 message,
        #                 ResponseCode.FAILED_CHALLENGE_INVALID,
        #             )
        #             return

        #         if not verify_signature(
        #             signature=msg.header.signature,
        #             elements_to_sign=[
        #                 (
        #                     authorization_req.id,
        #                     EXI().to_exi(authorization_req, Namespace.ISO_V2_MSG_DEF),
        #                 )
        #             ],
        #             leaf_cert=self.comm_session.contract_cert_chain.certificate,
        #         ):
        #             self.stop_state_machine(
        #                 "Unable to verify signature of AuthorizationReq",
        #                 message,
        #                 ResponseCode.FAILED_SIGNATURE_ERROR,
        #             )
        #             return

        auth_status: EVSEProcessing = EVSEProcessing.ONGOING
        next_state: Optional[Type[State]] = None

        if await self.comm_session.evse_controller.is_free() is True:
            self.authorizationFinished = AuthorizationStatus.ACCEPTED
        else: 
            if (self.isAuthorizationRequested() is False and     # Отправка запроса на авторизацию
                self.comm_session.selected_auth_option is AuthEnum.EIM_V2
            ):
                ocpp_temp.require_auth_EIM = True
                self.authorizationRequested = True
                            # Ожидание результата авторизации
        authorization_result = await self.comm_session.evse_controller.is_authorized(      
            id_token_type=(
                AuthorizationTokenType.EMAID
                if self.comm_session.selected_auth_option == AuthEnum.PNC_V2
                else AuthorizationTokenType.EXTERNAL
            )
        )    
        
        if authorization_result == AuthorizationStatus.ACCEPTED:
            auth_status = EVSEProcessing.FINISHED
            next_state = ChargeParameterDiscovery
        elif authorization_result == AuthorizationStatus.REJECTED:
            # В соответствии с таблицей 112 (ISO 15118-2) код ответа может следующего типа:
            # FAILED, FAILED_Challenge_Invalid,
            # Failed_SEQUENCE_ERROR, Failed_SIGNATURE_ERROR,
            # FAILED_Certificate_Revoked and Failed_UNKNOWN_SESSION
            self.stop_state_machine(
                "Authorization was rejected",
                message,
                ResponseCode.FAILED,
            )
            return
        else:
            # Если выбран режим EIM, и авторизовывает третья сторона,
            #  и решение об авторизации еще не было принято,
            #  то необходимо отправить код возврата в значении „Ongoing_WaitingForCustomerInteraction“
            if self.comm_session.selected_auth_option is AuthEnum.EIM_V2:
                auth_status = EVSEProcessing.ONGOING_WAITING_FOR_CUSTOMER
            
        authorization_res = AuthorizationRes(
            response_code=ResponseCode.OK, evse_processing=auth_status
        )

        self.create_next_message(
            next_state,
            authorization_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

    def isAuthorizationRequested(self) -> bool:
        return self.authorizationRequested


class ChargeParameterDiscovery(StateSECC):
    """
    Обработка ChargeParameterDiscoveryReq (ISO 15118-2)

    В текущем состоянии возможно принять следующие сообщения:
    1. a ChargeParameterDiscoveryReq
    2. a PowerDeliveryReq (AC)
    3. a CableCheckReq (DC)

    При первом вызове явно ожидается только ChargeParameterDiscoveryReq, в последующих вызовах
    это может быть либо  PowerDeliveryReq, либо CableCheckReq.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_charge_parameter_discovery_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [ChargeParameterDiscoveryReq, PowerDeliveryReq, CableCheckReq],
            self.expecting_charge_parameter_discovery_req,
        )
        if not msg:
            return
            # Обработка power_delivery_req и cable_check_req на стороне
        if msg.body.power_delivery_req:
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return

        if msg.body.cable_check_req:
            await CableCheck(self.comm_session).process_message(message, message_exi)
            return
        
            # Обработка ChargeParameterDiscoveryReq
        charge_params_req: ChargeParameterDiscoveryReq = (
            msg.body.charge_parameter_discovery_req
        )

        # OCPP code start #
        ocpp_temp.requested_energy_mode = charge_params_req.requested_energy_mode
        # OCPP code end #

        if charge_params_req.requested_energy_mode not in (
            await self.comm_session.evse_controller.get_supported_energy_transfer_modes(
                Protocol.ISO_15118_2
            )                       # Не поддерживаемый режим зарядки
        ):  # noqa: E501
            self.stop_state_machine(
                f"{charge_params_req.requested_energy_mode} not "
                f"offered as energy transfer mode",
                message,
                ResponseCode.FAILED_WRONG_ENERGY_TRANSFER_MODE,
            )
            return

        self.comm_session.selected_energy_mode = charge_params_req.requested_energy_mode
        self.comm_session.selected_charging_type_is_ac = (
            self.comm_session.selected_energy_mode.value.startswith("AC")
        )

        max_schedule_entries: Optional[
            int
        ] = charge_params_req.max_entries_sa_schedule_tuple

        ac_evse_charge_params: Optional[ACEVSEChargeParameter] = None
        dc_evse_charge_params: Optional[DCEVSEChargeParameter] = None
        # if charge_params_req.ac_ev_charge_parameter:    
        #     ac_evse_charge_params = (
        #         await self.comm_session.evse_controller.get_ac_charge_params_v2()
        #     )
        #     ev_max_voltage = charge_params_req.ac_ev_charge_parameter.ev_max_voltage
        #     ev_max_current = charge_params_req.ac_ev_charge_parameter.ev_max_current
        #     e_amount = charge_params_req.ac_ev_charge_parameter.e_amount
        #     ev_min_current = charge_params_req.ac_ev_charge_parameter.ev_min_current
        #     ev_charge_params_limits = EVChargeParamsLimits(
        #         ev_max_voltage=ev_max_voltage,
        #         ev_max_current=ev_max_current,
        #         e_amount=e_amount,
        #     )
        #     departure_time = charge_params_req.ac_ev_charge_parameter.departure_time

        #     # OCPP code start #
        #     p_e_amount: float = e_amount.value * pow(10, e_amount.multiplier)
        #     # EVEREST_CTX.publish('AC_EAmount', p_e_amount)
        #     p_ev_max_voltage: float = ev_max_voltage.value * pow(10, ev_max_voltage.multiplier)
        #     # if p_ev_max_voltage < 0: p_ev_max_voltage = 0
        #     # EVEREST_CTX.publish('AC_EVMaxVoltage', p_ev_max_voltage)
        #     p_ev_max_current: float = ev_max_current.value * pow(10, ev_max_current.multiplier)
        #     # if p_ev_max_current < 0: p_ev_max_current = 0
        #     # EVEREST_CTX.publish('AC_EVMaxCurrent', p_ev_max_current)
        #     p_ev_min_current: float = ev_min_current.value * pow(10, ev_min_current.multiplier)
        #     # if p_ev_min_current < 0: p_ev_min_current = 0
        #     # EVEREST_CTX.publish('AC_EVMinCurrent', p_ev_min_current)
        #     # OCPP code end #

        # else:         # Извлечение параметров DC
        dc_evse_charge_params = (
            await self.comm_session.evse_controller.get_dc_evse_charge_parameter()
        )
        ev_max_voltage = (
            charge_params_req.dc_ev_charge_parameter.ev_maximum_voltage_limit
        )
        ev_max_current = (
            charge_params_req.dc_ev_charge_parameter.ev_maximum_current_limit
        )
        ev_energy_request = (
            charge_params_req.dc_ev_charge_parameter.ev_energy_request
        )
        ev_charge_params_limits = EVChargeParamsLimits(
            ev_max_voltage=ev_max_voltage,
            ev_max_current=ev_max_current,
            ev_energy_request=ev_energy_request,
        )
        departure_time = charge_params_req.dc_ev_charge_parameter.departure_time

        # OCPP code start #
        dc_ev_charge_params: DCEVChargeParameter = charge_params_req.dc_ev_charge_parameter
        ev_max_current_limit: float = dc_ev_charge_params.ev_maximum_current_limit.value * pow(
            10, dc_ev_charge_params.ev_maximum_current_limit.multiplier
        )
        if ev_max_current_limit < 0: ev_max_current_limit = 0
        ev_max_voltage_limit: float = dc_ev_charge_params.ev_maximum_voltage_limit.value * pow(
            10, dc_ev_charge_params.ev_maximum_voltage_limit.multiplier
        )
        if ev_max_voltage_limit < 0: ev_max_voltage_limit = 0
        ev_maxvalues: dict = dict([
            ("DC_EVMaximumCurrentLimit", ev_max_current_limit),
            ("DC_EVMaximumVoltageLimit", ev_max_voltage_limit)
        ])

        if dc_ev_charge_params.ev_maximum_power_limit:
            ev_max_power_limit: float = dc_ev_charge_params.ev_maximum_power_limit.value * pow(
                10, dc_ev_charge_params.ev_maximum_power_limit.multiplier
            )
            if ev_max_power_limit < 0: ev_max_power_limit = 0
            ev_maxvalues.update({"DC_EVMaximumPowerLimit": ev_max_power_limit})

        ocpp_temp.ev_maxvalues = ev_maxvalues

        if dc_ev_charge_params.ev_energy_capacity:
            ev_energy_capacity: float = dc_ev_charge_params.ev_energy_capacity.value * pow(
                10, dc_ev_charge_params.ev_energy_capacity.multiplier
            )
            ocpp_temp.ev_energy_capacity = ev_energy_capacity
        if ev_energy_request:
            p_ev_energy_request: float = ev_energy_request.value * pow(
                10, ev_energy_request.multiplier
            )
            ocpp_temp.p_ev_energy_request = p_ev_energy_request
        
        if dc_ev_charge_params.full_soc:
            ocpp_temp.full_soc = dc_ev_charge_params.full_soc
        if dc_ev_charge_params.bulk_soc:
            ocpp_temp.bulk_soc = dc_ev_charge_params.bulk_soc

        ev_status: dict = dict([
            ("DC_EVReady", dc_ev_charge_params.dc_ev_status.ev_ready),
            ("DC_EVErrorCode", dc_ev_charge_params.dc_ev_status.ev_error_code),
            ("DC_EVRESSSOC",dc_ev_charge_params.dc_ev_status.ev_ress_soc),
        ])
        ocpp_temp.ev_status = ev_status
        # OCPP code end #

        if not departure_time:
            departure_time = 0
        else:
            # OCPP code start #
            d_Time_utc = datetime.utcnow() + timedelta(seconds=departure_time)
            format = "%Y-%m-%dT%H:%M:%SZ" #"yyyy-MM-dd'T'HH:mm:ss'Z'"
            ocpp_temp.departure_time =  d_Time_utc.strftime(format)
            # OCPP code end #

        sa_schedule_list = await self.comm_session.evse_controller.get_sa_schedule_list(    # Получение расписания зарядки
            ev_charge_params_limits, max_schedule_entries, departure_time
        )

        sa_schedule_list_valid = self.validate_sa_schedule_list(    # Проверка расписания зарядки
            sa_schedule_list, departure_time
        )
                                                        # Проверка расписаний из контекста сессии
        if sa_schedule_list_valid and self.comm_session.ev_session_context.sa_schedule_tuple_id: 
            filtered_list = list(
                filter(
                    lambda schedule_entry: schedule_entry.sa_schedule_tuple_id
                    == self.comm_session.ev_session_context.sa_schedule_tuple_id,
                    sa_schedule_list,
                )
            )
            if len(filtered_list) != 1:
                logger.warning(
                    f"Resumed session. Previously selected sa_schedule_list is"
                    f" not present {sa_schedule_list}"
                )
            else:
                logger.info(
                    f"Resumed session. SAScheduleTupleID "
                    f"{self.comm_session.ev_session_context.sa_schedule_tuple_id} "
                    f"present in context"
                )

        if not sa_schedule_list_valid:
            # V2G2-305 : Если расписание не валидно, EVCC может повторно запросить расписание
            logger.warning(
                f"validate_sa_schedule_list() failed. departure_time: {departure_time} "
                f" {sa_schedule_list}"
            )

        signature = None
        next_state = None
        if sa_schedule_list:
            self.comm_session.offered_schedules = sa_schedule_list
            if charge_params_req.ac_ev_charge_parameter:
                next_state = PowerDelivery
            else:
                next_state = CableCheck         # Для DC зарядки

            # SalesTariff не поддерживается
            # for schedule in sa_schedule_list:
            #     if schedule.sales_tariff:
            #         try:
            #             element_to_sign = (
            #                 schedule.sales_tariff.id,
            #                 EXI().to_exi(
            #                     schedule.sales_tariff, Namespace.ISO_V2_MSG_DEF
            #                 ),
            #             )
            #             signature_key = load_priv_key(
            #                 os.path.join(get_PKI_PATH(), KeyPath.MO_SUB_CA2_PEM),
            #                 KeyEncoding.PEM,
            #                 os.path.join(get_PKI_PATH(), KeyPasswordPath.MO_SUB_CA2_PASSWORD),
            #             )
            #             signature = create_signature([element_to_sign], signature_key)
            #         except PrivateKeyReadError as exc:
            #             logger.warning(
            #                 "Can't read private key to needed to create "
            #                 f"signature for SalesTariff:" #{exc}"
            #             )
            #             # If a SalesTariff isn't signed, that's not the end of the
            #             # world, no reason to stop the charging process here
            #     break

            self.expecting_charge_parameter_discovery_req = False
        else:
            self.expecting_charge_parameter_discovery_req = True

        charge_params_res = ChargeParameterDiscoveryRes(
            response_code=ResponseCode.OK,
            evse_processing=EVSEProcessing.FINISHED
            if sa_schedule_list
            else EVSEProcessing.ONGOING,
            sa_schedule_list=SAScheduleList(schedule_tuples=sa_schedule_list),
            ac_charge_parameter=ac_evse_charge_params,
            dc_charge_parameter=dc_evse_charge_params,
        )

        self.create_next_message(
            next_state,
            charge_params_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
            signature=signature,
        )

    def validate_sa_schedule_list(
        self, sa_schedules: List[SAScheduleTuple], departure_time: int
    ) -> bool:
        # V2G2-303 - суммарная длительность расписания должна совпадать с временем отбытия EV
        # V2G2-304 - если время отбытия не указанно, то оно принимается равным 24 часа
        # V2G2-305 - В случае не совпадений длительности в расписании и времени отправки, 
        # может запросить расписание повторно
        valid = True
        duration_24_hours_in_seconds = 86400
        for schedule_tuples in sa_schedules:
            schedule_duration = 0

            p_max_sched = schedule_tuples.p_max_schedule
            if p_max_sched.schedule_entries is not None:
                first_entry_start_time = p_max_sched.schedule_entries[
                    0
                ].time_interval.start
                last_entry_start_time = p_max_sched.schedule_entries[
                    -1
                ].time_interval.start
                last_entry_schedule_duration = p_max_sched.schedule_entries[
                    -1
                ].time_interval.duration
                schedule_duration = (
                    last_entry_start_time - first_entry_start_time
                ) + last_entry_schedule_duration

            if departure_time == 0 and schedule_duration < duration_24_hours_in_seconds:
                logger.warning(
                    f"departure_time is not set. schedule duration {schedule_duration}"
                )
                logger.warning(f"Schedule tuples {schedule_tuples}")
                valid = False
                break

            elif departure_time != 0 and departure_time < schedule_duration:
                valid = False
                break
        return valid


class PowerDelivery(StateSECC):
    """
    Обработка PowerDeliveryReq (ISO 15118-2)

    В текущем состоянии возможно принять следующие сообщения:
    1. a PowerDeliveryReq
    2. a ChargeParameterDiscoveryReq
    3. a ChargingStatusReq (AC-Message)
    4. a SessionStopReq
    5. a CurrentDemandReq (DC-Message)
    6. a WeldingDetectionReq (DC-Message)

    При первом вызове явно ожидается только PowerDeliveryReq, в последующих вызовах
    это может быть другое сообщение из списка.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_power_delivery_req = True
        # OCPP code start #
        self.v2GSetupFinishedReached = False
        # OCPP code end #

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [
                PowerDeliveryReq,
                SessionStopReq,
                WeldingDetectionReq,
            ],
            self.expecting_power_delivery_req,
        )
        if not msg:
            return
            # Обработка session_stop_req и welding_detection_req на стороне
        if msg.body.session_stop_req:
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return

        if msg.body.welding_detection_req:
            await WeldingDetection(self.comm_session).process_message(
                message, message_exi
            )
            return

            # Обработка PowerDeliveryReq
        power_delivery_req: PowerDeliveryReq = msg.body.power_delivery_req

        # OCPP code start #
        if not self.comm_session.selected_charging_type_is_ac:
            ocpp_temp.dc_charging_complete =  power_delivery_req.dc_ev_power_delivery_parameter.charging_complete

            ev_status: dict = dict([
                ("DC_EVReady", power_delivery_req.dc_ev_power_delivery_parameter.dc_ev_status.ev_ready),
                ("DC_EVErrorCode", power_delivery_req.dc_ev_power_delivery_parameter.dc_ev_status.ev_error_code),
                ("DC_EVRESSSOC", power_delivery_req.dc_ev_power_delivery_parameter.dc_ev_status.ev_ress_soc),
            ])
            ocpp_temp.ev_status = ev_status
            
            if power_delivery_req.dc_ev_power_delivery_parameter.bulk_charging_complete is not None:
                ocpp_temp.dc_bulk_charging_complete = power_delivery_req.dc_ev_power_delivery_parameter.bulk_charging_complete
        # OCPP code end #
                                        # Проверка, что расписание из тех, что были предоставлены ранее
        if power_delivery_req.sa_schedule_tuple_id not in [   
            schedule.sa_schedule_tuple_id
            for schedule in self.comm_session.offered_schedules
        ]:
            self.stop_state_machine(
                f"{power_delivery_req.sa_schedule_tuple_id} "
                "does not match any offered tariff IDs",
                message,
                ResponseCode.FAILED_TARIFF_SELECTION_INVALID,
            )
            return

        # TODO: Требуется дополнительное изучение вопроса
        # if (
        #     power_delivery_req.charge_progress == ChargeProgress.START
        #     and not power_delivery_req.charging_profile
        # ):
        #     # Note Lukas Lombriser: I am not sure if I am correct:
        #     # But there is hardly no EV that sends a profile (DC-Charging)
        #     # According Table 40 and Table 104, ChargingProfile is optional
        #
        #     # Although the requirements don't make this 100% clear, it is
        #     # the intention of ISO 15118-2 for the EVCC to always send a
        #     # charging profile if ChargeProgress is set to 'Start'
        #     self.stop_state_machine(
        #         "No charge profile provided although "
        #         "ChargeProgress was set to 'Start'",
        #         message,
        #         ResponseCode.FAILED_CHARGING_PROFILE_INVALID,
        #     )
        #     return

        # [V2G2-225] SECC должен отказать в зарядке, если расписание переданное EVCC выходит за рамки
        # расписания, составленного на основании максимальной мощности SECC
        if power_delivery_req.charging_profile:
            if not self._is_charging_profile_valid(power_delivery_req):
                logger.warning("[V2G2-225] ChargingProfile is not adhering to the Pmax values in ChargeParameterDiscoveryRes")
                self.stop_state_machine(
                    "[V2G2-225] ChargingProfile is not adhering to the Pmax values in "
                    "ChargeParameterDiscoveryRes",
                    message,
                    ResponseCode.FAILED_CHARGING_PROFILE_INVALID,
                )
                return

        logger.debug(f"ChargeProgress set to {power_delivery_req.charge_progress}")

        next_state: Type[State]
        if power_delivery_req.charge_progress == ChargeProgress.START:

            # OCPP code start #
            if not self.v2GSetupFinishedReached:
                ocpp_temp.v2g_setup_finished = True
                self.v2GSetupFinishedReached = True
            # OCPP code end #
            
            # В соответствии с главой 8.7.4 ISO 15118-2,ставим флаг активации зарядки HLC-C
            await self.comm_session.evse_controller.set_hlc_charging(True)
            # [V2G2-847] - После получения первого сообщенияPowerDeliveryReq с значением "Start"
            # EV устанавливает состояние C или D (на линии CP) в течении 250 мс.

            # [V2G2-860] - Если никаких ошибок нет, то SECC должен замкнуть силовые контакты
            # в течении 3 секунд

            # if self.comm_session.selected_charging_type_is_ac:
            #     # OCPP code start #
            #     # EVEREST_CTX.publish('AC_Close_Contactor', None)
            #     # OCPP code end #
            #     if not await self.comm_session.evse_controller.is_contactor_closed():
            #         self.stop_state_machine(
            #             "Contactor didnt close",
            #             message,
            #             ResponseCode.FAILED_CONTACTOR_ERROR,
            #         )
            #         return
            #     next_state = ChargingStatus
            # else:
            next_state = CurrentDemand
            self.comm_session.selected_schedule = (
                power_delivery_req.sa_schedule_tuple_id
            )
            self.comm_session.ev_session_context.sa_schedule_tuple_id = power_delivery_req.sa_schedule_tuple_id
            self.comm_session.charge_progress_started = True
        elif power_delivery_req.charge_progress == ChargeProgress.STOP:
            next_state = None
            if self.comm_session.selected_charging_type_is_ac:
                next_state = SessionStop

            # OCPP code start #
            ocpp_temp.v2g_setup_finished = False
            self.v2GSetupFinishedReached = False
            # OCPP code end #

            # В соответствии с главой 8.7.4 ISO 15118-2, снимаем флаг зарядки HLC-C
            await self.comm_session.evse_controller.set_hlc_charging(False)

            # Контролируемая остановка зарядки
            await self.comm_session.evse_controller.stop_charger()
            # Размыкание силовых контактов

            # if self.comm_session.selected_charging_type_is_ac:
            #     # OCPP code start #
            #     # EVEREST_CTX.publish('AC_Open_Contactor', None)
            #     # OCPP code end #
            #     if not await self.comm_session.evse_controller.is_contactor_opened():
            #         self.stop_state_machine(
            #             "Contactor didnt open",
            #             message,
            #             ResponseCode.FAILED_CONTACTOR_ERROR,
            #         )
            #         return

            # else:
            # OCPP code start #
            ocpp_temp.current_demand_finished = True
            ocpp_temp.dc_open_contactor = True
            # OCPP code end #

        else:
            # Случай пересогласования параметров
            if self.comm_session.charge_progress_started:
                next_state = ChargeParameterDiscovery
            else:
                # TODO Изучить вопрос, нужно ли завершать сессию в данном месте?
                self.stop_state_machine(
                    "EVCC wants to renegotiate, but charge "
                    "progress has not yet started",
                    message,
                    ResponseCode.FAILED,
                )
                return

        ac_evse_status: Optional[ACEVSEStatus] = None
        dc_evse_status: Optional[DCEVSEStatus] = None
        evse_controller = self.comm_session.evse_controller
        if self.comm_session.selected_charging_type_is_ac:
            ac_evse_status = await evse_controller.get_ac_evse_status()
        else:
            dc_evse_status = await evse_controller.get_dc_evse_status()

        power_delivery_res = PowerDeliveryRes(
            response_code=ResponseCode.OK,
            ac_evse_status=ac_evse_status,
            dc_evse_status=dc_evse_status,
        )

        self.create_next_message(
            next_state,
            power_delivery_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_power_delivery_req = False

    async def wait_for_state_c_or_d(self) -> bool:
        """ Ожидание состояния C или D на линии CP """
        STATE_C_TIMEOUT = 0.25

        async def check_state():
            while await self.comm_session.evse_controller.get_cp_state() not in [
                CpState.C2,
                CpState.D2,
            ]:
                await asyncio.sleep(0.05)
            logger.debug(
                f"State is " f"{await self.comm_session.evse_controller.get_cp_state()}"
            )
            return True

        try:
            return await asyncio.wait_for(
                check_state(),
                timeout=STATE_C_TIMEOUT,
            )
        except asyncio.TimeoutError:
            # Попробовать еще раз
            return await self.comm_session.evse_controller.get_cp_state() in [
                CpState.C2,
                CpState.D2,
            ]

    def _is_charging_profile_valid(self, power_delivery_req: PowerDeliveryReq) -> bool:
        """ Проверка входящего расписания """
        for schedule in self.comm_session.offered_schedules:
            if schedule.sa_schedule_tuple_id == power_delivery_req.sa_schedule_tuple_id:
                schedule_entries = schedule.p_max_schedule.schedule_entries

                ev_profile = power_delivery_req.charging_profile
                ev_profile_entries = ev_profile.profile_entries
                cached_start_idx_ev: int = 0
                last_ev_running_idx: int = 0

                for idx, sa_profile_entry in enumerate(schedule_entries):
                    sa_profile_entry_start = sa_profile_entry.time_interval.start

                    sa_entry_pmax = (
                        sa_profile_entry.p_max.value
                        * 10**sa_profile_entry.p_max.multiplier
                    )

                    try:
                        next_sa_profile_entry = schedule_entries[idx + 1]
                        sa_profile_entry_end = next_sa_profile_entry.time_interval.start

                    except IndexError:
                        # Если вызывается данное исключение, значит это последний элемент в расписании
                        sa_profile_entry_end = (
                            sa_profile_entry_start
                            + sa_profile_entry.time_interval.duration
                        )
                   
                    cached_start_idx_ev += last_ev_running_idx
                    last_ev_running_idx = 0
                    # fmt: off
                    for (ev_profile_idx, ev_profile_entry) in enumerate(
                        ev_profile_entries[cached_start_idx_ev:]
                    ):
                        _is_last_ev_profile = (
                            ev_profile_entry.start == ev_profile_entries[-1].start
                        )

                        if (ev_profile_entry.start < sa_profile_entry_end or _is_last_ev_profile ): # noqa
                            ev_entry_pmax = (ev_profile_entry.max_power.value * 10 ** ev_profile_entry.max_power.multiplier)  # noqa
                            if ev_entry_pmax > sa_entry_pmax:
                                logger.error(
                                    f"EV Profile start {ev_profile_entry.start}s"
                                    f"is out of power range: "
                                    f"EV Max {ev_entry_pmax} W > EVSE Max "
                                    f"{sa_entry_pmax} W \n"
                                )
                                return False

                            if not _is_last_ev_profile:
                                ev_profile_entry_end = ev_profile_entries[
                                    ev_profile_idx + 1
                                ].start
                                if ev_profile_entry_end <= sa_profile_entry_end:
                                    last_ev_running_idx = ev_profile_idx + 1
                            else:
                                logger.debug(
                                    f"EV last Profile start "
                                    f"{ev_profile_entry.start}s is "
                                    f"within time range [{sa_profile_entry_start}; "
                                    f"{sa_profile_entry_end}[ and power range: "
                                    f"EV Max {ev_entry_pmax} W <= EVSE Max "
                                    f"{sa_entry_pmax} W \n"
                                )
                        else:
                            break
                    # fmt: on
        return True

# class MeteringReceipt(StateSECC):
#     """
#     The ISO 15118-2 state in which the SECC processes a
#     MeteringReceiptReq message from the EVCC.

#     The EVCC may send one of the following requests in this state:
#     1. a MeteringReceiptReq
#     2. a ChargingStatusReq
#     3. a CurrentDemandReq
#     4. a PowerDeliveryReq

#     Upon first initialisation of this state, we expect a MeteringReceiptReq, but
#     after that, the next possible request could be either a PowerDeliveryReq,
#     ChargingStatusReq, or a CurrentDemandReq. So we remain in this
#     state until we know which is the following request from the EVCC and then
#     transition to the appropriate state (or terminate if the incoming message
#     doesn't fit any of the expected requests).

#     As a result, the create_next_message() method will be called with
#     next_state = None.
#     """

#     def __init__(self, comm_session: SECCCommunicationSession):
#         super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
#         self.expecting_metering_receipt_req = True

#     async def process_message(
#         self,
#         message: Union[
#             SupportedAppProtocolReq,
#             SupportedAppProtocolRes,
#             V2GMessageV2,
#         #   V2GMessageV20,
#         #   V2GMessageDINSPEC,
#         ],
#         message_exi: bytes = None,
#     ):
#         msg = self.check_msg_v2(
#             message,
#             [MeteringReceiptReq, ChargingStatusReq, CurrentDemandReq, PowerDeliveryReq],
#             self.expecting_metering_receipt_req,
#         )
#         if not msg:
#             return

#         if msg.body.power_delivery_req:
#             await PowerDelivery(self.comm_session).process_message(message, message_exi)
#             return

#         if msg.body.charging_status_req:
#             await ChargingStatus(self.comm_session).process_message(
#                 message, message_exi
#             )
#             return

#         if msg.body.current_demand_req:
#             await CurrentDemand(self.comm_session).process_message(message, message_exi)
#             return

#         metering_receipt_req: MeteringReceiptReq = msg.body.metering_receipt_req

#         if not self.comm_session.contract_cert_chain:
#             stop_reason = (
#                 "No contract certificate chain available to verify "
#                 "signature of MeteringReceiptReq"
#             )
#         elif not verify_signature(
#             msg.header.signature,
#             [
#                 (
#                     metering_receipt_req.id,
#                     EXI().to_exi(metering_receipt_req, Namespace.ISO_V2_MSG_DEF),
#                 )
#             ],
#             self.comm_session.contract_cert_chain.certificate,
#         ):
#             stop_reason = "Unable to verify signature of MeteringReceiptReq"
#         elif not metering_receipt_req.meter_info.meter_reading or (
#             self.comm_session.sent_meter_info
#             and self.comm_session.sent_meter_info.meter_reading
#             and metering_receipt_req.meter_info.meter_reading
#             != self.comm_session.sent_meter_info.meter_reading
#         ):
#             stop_reason = (
#                 "EVCC's meter info is not a copy of the SECC's meter info "
#                 "sent in CharginStatusRes/CurrentDemandRes"
#             )
#         else:
#             stop_reason = None

#         if stop_reason:
#             self.stop_state_machine(
#                 stop_reason, message, ResponseCode.FAILED_METERING_SIGNATURE_NOT_VALID
#             )
#             return

#         evse_controller = self.comm_session.evse_controller
#         if (
#             self.comm_session.selected_energy_mode
#             and self.comm_session.selected_charging_type_is_ac
#         ):
#             metering_receipt_res = MeteringReceiptRes(
#                 response_code=ResponseCode.OK,
#                 ac_evse_status=await evse_controller.get_ac_evse_status(),
#             )
#         else:
#             metering_receipt_res = MeteringReceiptRes(
#                 response_code=ResponseCode.OK,
#                 dc_evse_status=await evse_controller.get_dc_evse_status(),
#             )

#         self.create_next_message(
#             None,
#             metering_receipt_res,
#             Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
#             Namespace.ISO_V2_MSG_DEF,
#         )

#         self.expecting_metering_receipt_req = False


class SessionStop(StateSECC):
    """
    Обработка SessionStopReq (ISO 15118-2)
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(message, [SessionStopReq])
        if not msg:
            return

        if msg.body.session_stop_req.charging_session == ChargingSession.PAUSE:
            next_state = Pause
            session_stop_state = SessionStopAction.PAUSE
            # OCPP code start #
            ocpp_temp.dlink_pause = True
            # OCPP code end #
        else:
            next_state = Terminate
            session_stop_state = SessionStopAction.TERMINATE
            # При завершении сессии, контекст удаляется
            self.comm_session.ev_session_context = EVSessionContext()
            # OCPP code start #
            ocpp_temp.dlink_terminate = True
            # OCPP code end #

        self.comm_session.stop_reason = StopNotification(
            True,
            f"EV requested to {session_stop_state.value} the communication session",
            self.comm_session.writer.get_extra_info("peername"),
            session_stop_state,
        )

        self.create_next_message(
            next_state,
            SessionStopRes(response_code=ResponseCode.OK),
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )


# ============================================================================
# |                     Состояния для AC - ISO 15118-2                       |
# ============================================================================


# class ChargingStatus(StateSECC):
#     """
#     The ISO 15118-2 state in which the SECC processes an
#     ChargingStatusReq message from the EVCC.

#     The EVCC may send one of the following requests in this state:
#     1. a ChargingStatusReq
#     2. a PowerDeliveryReq
#     3. a MeteringReceiptReq

#     Upon first initialisation of this state, we expect a
#     ChargingStatusReq, but after that, the next possible request could
#     be either another ChargingStatusReq (ongoing energy flow), or a
#     PowerDeliveryReq (to either renegotiate the charging profile or to stop the
#     power flow), or a MeteringReceiptReq (to exchange metering information).

#     So we remain in this state until we know which is the following request from
#     the EVCC and then transition to the appropriate state (or terminate if the
#     incoming message doesn't fit any of the expected requests).

#     As a result, the create_next_message() method might be called with
#     next_state = None.
#     """

#     def __init__(self, comm_session: SECCCommunicationSession):
#         super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
#         self.expecting_charging_status_req = True

#     async def process_message(
#         self,
#         message: Union[
#             SupportedAppProtocolReq,
#             SupportedAppProtocolRes,
#             V2GMessageV2,
#         #   V2GMessageV20,
#         #   V2GMessageDINSPEC,
#         ],
#         message_exi: bytes = None,
#     ):
#         msg = self.check_msg_v2(
#             message,
#             [ChargingStatusReq, PowerDeliveryReq, MeteringReceiptReq],
#             self.expecting_charging_status_req,
#         )
#         if not msg:
#             return

#         if msg.body.power_delivery_req:
#             await PowerDelivery(self.comm_session).process_message(message, message_exi)
#             return

#         # if msg.body.metering_receipt_req:
#         #     await MeteringReceipt(self.comm_session).process_message(
#         #         message, message_exi
#         #     )
#         #     return

#         # OCPP code start #
#         receipt_required: bool = None
#         if self.comm_session.selected_auth_option == AuthEnum.EIM_V2:
#             receipt_required = False # Always false
#         else:
#             receipt_required = await self.comm_session.evse_controller.get_receipt_required()
#         # OCPP code end #

#         # We don't care about signed meter values from the EVCC, but if you
#         # do, then set receipt_required to True and set the field meter_info
#         evse_controller = self.comm_session.evse_controller

#         evse_max_current = None
#         if self.comm_session.selected_auth_option == AuthEnum.EIM_V2:
#             evse_max_current=await self.comm_session.evse_controller.get_ac_evse_max_current()

#         charging_status_res = ChargingStatusRes(
#             response_code=ResponseCode.OK,
#             evse_id=await evse_controller.get_evse_id(Protocol.ISO_15118_2),
#             sa_schedule_tuple_id=self.comm_session.selected_schedule,
#             # OCPP code start #
#             ac_evse_status=await evse_controller.get_ac_evse_status(),
#             # TODO Could maybe request an OCPP setting that determines
#             #      whether or not a receipt is required and when
#             #      (probably only makes sense at the beginning and end of
#             #      a charging session). If true, set MeterInfo.
#             meter_info=await self.comm_session.evse_controller.get_meter_info_v2(),
#             receipt_required=receipt_required,
#             evse_max_current=evse_max_current,
#             # OCPP code end #
#         )

#         if charging_status_res.meter_info:
#             self.comm_session.sent_meter_info = charging_status_res.meter_info

#         # TODO Check in which case we would set EVSEMaxCurrent and how to
#         #      request it via MQTT. Is optional, so let's leave it out for
#         #      now.

#         # TODO Check if a renegotiation is wanted (would be set in the field
#         #      ac_evse_status). Let's leave that out for now.

#         # Next request could be another ChargingStatusReq or a
#         # PowerDeliveryReq, so we remain in this state for now
#         next_state: Optional[Type[State]] = None
#         # if charging_status_res.receipt_required:
#         #     # But if we set receipt_required to True, we expect a
#         #     # MeteringReceiptReq
#         #     next_state = MeteringReceipt

#         self.create_next_message(
#             next_state,
#             charging_status_res,
#             Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
#             Namespace.ISO_V2_MSG_DEF,
#         )

#         self.expecting_charging_status_req = False


# ============================================================================
# |                     Состояния для DC - ISO 15118-2                       |
# ============================================================================


class CableCheck(StateSECC):
    """
    Обработка CableCheckReq (ISO 15118-2)
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.cable_check_req_was_received = False
        # OCPP code start #
        self.isolation_check_requested = False
        # OCPP code end #

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(message, [CableCheckReq])
        if not msg:
            return

        cable_check_req: CableCheckReq = msg.body.cable_check_req

        # OCPP code start #
        ev_status: dict = dict([
            ("DC_EVReady", cable_check_req.dc_ev_status.ev_ready),
            ("DC_EVErrorCode", cable_check_req.dc_ev_status.ev_error_code),
            ("DC_EVRESSSOC", cable_check_req.dc_ev_status.ev_ress_soc),
        ])
        ocpp_temp.ev_status = ev_status
        # OCPP code end #
                        # В случае проблем с EV, завершение сессии
        if cable_check_req.dc_ev_status.ev_error_code != DCEVErrorCode.NO_ERROR: 
            self.stop_state_machine(
                f"{cable_check_req.dc_ev_status} "
                "has Error"
                f"{cable_check_req.dc_ev_status}",
                message,
                ResponseCode.FAILED,
            )
            return
        
        # OCPP code start #
        if not self.isolation_check_requested:
            ocpp_temp.start_cable_check = True
            self.isolation_check_requested = True
            await self.comm_session.evse_controller.setIsolationMonitoringActive(True)
        # OCPP code end #

        # TODO_SL: Überlegen wie es weiter geht
        # if not self.cable_check_req_was_received:
        #     # Requirement in 6.4.3.106 of the IEC 61851-23
        #     # Any relays in the DC output circuit of the DC station shall
        #     # be closed during the insulation test
        #     contactor_state = await self.comm_session.evse_controller.close_contactor()
        #     if contactor_state != Contactor.CLOSED:
        #         self.stop_state_machine(
        #             "Contactor didnt close for Cable Check",
        #             message,
        #             ResponseCode.FAILED,
        #         )
        #         return
        #     await self.comm_session.evse_controller.start_cable_check()
        #     self.cable_check_req_was_received = True

        self.comm_session.evse_controller.ev_data_context.soc = (
            cable_check_req.dc_ev_status.ev_ress_soc
        )

        dc_charger_state = await self.comm_session.evse_controller.get_dc_evse_status()
        cableCheckFinished = await self.comm_session.evse_controller.isCableCheckFinished()

        evse_processing = EVSEProcessing.ONGOING
        next_state = None
        if cableCheckFinished is True and dc_charger_state.evse_isolation_status in [   # Обработка результатов проверки 
            IsolationLevel.VALID,
            IsolationLevel.WARNING,
        ]:
            if dc_charger_state.evse_isolation_status == IsolationLevel.WARNING:
                logger.warning(
                    "Isolation resistance measured by EVSE is in Warning-Range"
                )
            evse_processing = EVSEProcessing.FINISHED
            next_state = PreCharge
            # OCPP code start #
            await self.comm_session.evse_controller.setIsolationMonitoringActive(False)
            # OCPP code end #
        elif dc_charger_state.evse_isolation_status in [
            IsolationLevel.FAULT,
            IsolationLevel.NO_IMD,
        ]:
            self.stop_state_machine(
                f"Isolation Failure: {dc_charger_state.evse_isolation_status}",
                message,
                ResponseCode.FAILED,
            )
            return
        
        dc_charger_state = await self.comm_session.evse_controller.get_dc_evse_status()

        cable_check_res = CableCheckRes(
            response_code=ResponseCode.OK,
            dc_evse_status=await self.comm_session.evse_controller.get_dc_evse_status(),
            evse_processing=evse_processing,
        )

        self.create_next_message(
            next_state,
            cable_check_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )


class PreCharge(StateSECC):
    """
    Обработка PreChargeReq (ISO 15118-2)

    EVSE корректирует выходное напряжение под запрос EV.
    Разница должна быть менее 20 В (по 61851-23).
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_precharge_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [PreChargeReq, PowerDeliveryReq],
            self.expecting_precharge_req,
        )
        if not msg:
            return
        
            # Обработка power_delivery_req на стороне
        if msg.body.power_delivery_req:
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return
        
            # Обработка PreChargeReq
        precharge_req: PreChargeReq = msg.body.pre_charge_req

        # OCPP code start #
        ev_status: dict = dict([
            ("DC_EVReady", precharge_req.dc_ev_status.ev_ready),
            ("DC_EVErrorCode", precharge_req.dc_ev_status.ev_error_code),
            ("DC_EVRESSSOC", precharge_req.dc_ev_status.ev_ress_soc),
        ])
        ocpp_temp.ev_status = ev_status

        ev_target_voltage = precharge_req.ev_target_voltage.value * pow(10, precharge_req.ev_target_voltage.multiplier)
        if ev_target_voltage < 0: ev_target_voltage = 0
        ev_target_current = precharge_req.ev_target_current.value * pow(10, precharge_req.ev_target_current.multiplier)
        if ev_target_current < 0: ev_target_current = 0
        ev_targetvalues: dict = dict([
            ("DC_EVTargetVoltage", ev_target_voltage),
            ("DC_EVTargetCurrent", ev_target_current),
        ])
        ocpp_temp.ev_targetvalues = ev_targetvalues

        # OCPP code end #

        if precharge_req.dc_ev_status.ev_error_code != DCEVErrorCode.NO_ERROR:  # В случае ошибок
            self.stop_state_machine(
                f"{precharge_req.dc_ev_status} "
                "has Error"
                f"{precharge_req.dc_ev_status}",
                message,
                ResponseCode.FAILED,
            )
            return

        self.comm_session.evse_controller.ev_data_context.soc = (
            precharge_req.dc_ev_status.ev_ress_soc
        )

        # Для фазы PreCharge, рекоммендуемый ток не более 2 A.
        present_current = (
            await self.comm_session.evse_controller.get_evse_present_current(
                Protocol.ISO_15118_2
            )
        )
        present_current_in_a = present_current.value * 10**present_current.multiplier
        target_current = precharge_req.ev_target_current
        target_current_in_a = target_current.value * 10**target_current.multiplier

        if present_current_in_a > 2 or target_current_in_a > 2:
            self.stop_state_machine(
                "Target current or present current too high in state Precharge",
                message,
                ResponseCode.FAILED,
            )
            return

        # Для каждого обработанного сообщения, устанавливаем целевые параметры заново
        await self.comm_session.evse_controller.set_precharge(
            precharge_req.ev_target_voltage, precharge_req.ev_target_current
        )

        dc_charger_state = await self.comm_session.evse_controller.get_dc_evse_status()
        evse_present_voltage = (
            await self.comm_session.evse_controller.get_evse_present_voltage(
                Protocol.ISO_15118_2
            )
        )

        precharge_res = PreChargeRes(
            response_code=ResponseCode.OK,
            dc_evse_status=dc_charger_state,
            evse_present_voltage=evse_present_voltage,
        )

        next_state = None
        self.create_next_message(
            next_state,
            precharge_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_precharge_req = False


class CurrentDemand(StateSECC):
    """
    Обработка CurrentDemandReq (ISO 15118-2)
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_current_demand_req = True
        # OCPP code start #
        self.firstMessage: bool = True
        # OCPP code end #

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [CurrentDemandReq, PowerDeliveryReq],
            self.expecting_current_demand_req,
        )
        if not msg:
            return
            # Обработка power_delivery_req на стороне
        if msg.body.power_delivery_req:
            await PowerDelivery(self.comm_session).process_message(message, message_exi)
            return

            # Обработка CurrentDemandReq
        current_demand_req: CurrentDemandReq = msg.body.current_demand_req

        # OCPP code start #
        if self.firstMessage is True:
            ocpp_temp.current_demand_started = True
            self.firstMessage = False

        ocpp_temp.dc_charging_complete = current_demand_req.charging_complete

        ev_status: dict = dict([
            ("DC_EVReady", current_demand_req.dc_ev_status.ev_ready),
            ("DC_EVErrorCode", current_demand_req.dc_ev_status.ev_error_code),
            ("DC_EVRESSSOC", current_demand_req.dc_ev_status.ev_ress_soc),
        ])
        ocpp_temp.ev_status = ev_status

        ev_target_voltage = current_demand_req.ev_target_voltage.value * pow(10, current_demand_req.ev_target_voltage.multiplier)
        if ev_target_voltage < 0: ev_target_voltage = 0
        ev_target_current = current_demand_req.ev_target_current.value * pow(10, current_demand_req.ev_target_current.multiplier)
        if ev_target_current < 0: ev_target_current = 0
        ev_targetvalues: dict = dict([
            ("DC_EVTargetVoltage", ev_target_voltage),
            ("DC_EVTargetCurrent", ev_target_current),
        ])
        ocpp_temp.ev_targetvalues = ev_targetvalues

        ocpp_temp.dc_bulk_charging_complete = current_demand_req.bulk_charging_complete

        ev_maxvalues: dict = dict()
                
        if current_demand_req.ev_max_current_limit: 
            ev_max_current_limit: float = current_demand_req.ev_max_current_limit.value * pow(
                10, current_demand_req.ev_max_current_limit.multiplier
            )
            if ev_max_current_limit < 0: ev_max_current_limit = 0
            ev_maxvalues.update({"DC_EVMaximumCurrentLimit": ev_max_current_limit})

        if current_demand_req.ev_max_voltage_limit:
            ev_max_voltage_limit: float = current_demand_req.ev_max_voltage_limit.value * pow(
                10, current_demand_req.ev_max_voltage_limit.multiplier
            )
            if ev_max_voltage_limit < 0: ev_max_voltage_limit = 0
            ev_maxvalues.update({"DC_EVMaximumVoltageLimit": ev_max_voltage_limit})

        if current_demand_req.ev_max_power_limit:
            ev_max_power_limit: float = current_demand_req.ev_max_power_limit.value * pow(
                10, current_demand_req.ev_max_power_limit.multiplier
            )
            if ev_max_power_limit < 0: ev_max_power_limit = 0
            ev_maxvalues.update({"DC_EVMaximumPowerLimit": ev_max_power_limit})
        
        if ev_maxvalues:
            ocpp_temp.ev_maxvalues = ev_maxvalues

        format = "%Y-%m-%dT%H:%M:%SZ" #"yyyy-MM-dd'T'HH:mm:ss'Z'"
        datetime_now_utc = datetime.utcnow()

        ev_reamingTime: dict = dict()

        if current_demand_req.remaining_time_to_bulk_soc:
            seconds_bulk_soc: float = current_demand_req.remaining_time_to_bulk_soc.value * pow(
                10, current_demand_req.remaining_time_to_bulk_soc.multiplier
            )
            re_bulk_soc_time = datetime_now_utc + timedelta(seconds=seconds_bulk_soc)
            ev_reamingTime.update({"EV_RemainingTimeToBulkSoC": re_bulk_soc_time.strftime(format)})
            
        if current_demand_req.remaining_time_to_full_soc:
            seconds_full_soc: float = current_demand_req.remaining_time_to_full_soc.value * pow(
                10, current_demand_req.remaining_time_to_full_soc.multiplier
            )
            re_full_soc_time = datetime_now_utc + timedelta(seconds=seconds_full_soc)
            ev_reamingTime.update({"EV_RemainingTimeToFullSoC": re_full_soc_time.strftime(format)})
        
        ocpp_temp.ev_reamingTime = ev_reamingTime
        # OCPP code end #

        self.comm_session.evse_controller.ev_data_context.soc = (
            current_demand_req.dc_ev_status.ev_ress_soc
        )
        await self.comm_session.evse_controller.send_charging_command(
            current_demand_req.ev_target_voltage, current_demand_req.ev_target_current
        )

        # OCPP code start #
        receipt_required: bool = None
        if self.comm_session.selected_auth_option == AuthEnum.EIM_V2:
            receipt_required = False # Always false
        else:
            receipt_required = await self.comm_session.evse_controller.get_receipt_required()
        # OCPP code end #


        evse_controller = self.comm_session.evse_controller

        dc_evse_status = await evse_controller.get_dc_evse_status()

        current_demand_res = CurrentDemandRes(
            response_code=ResponseCode.OK,
            dc_evse_status=await evse_controller.get_dc_evse_status(),
            evse_present_voltage=await evse_controller.get_evse_present_voltage(Protocol.ISO_15118_2),
            evse_present_current=await evse_controller.get_evse_present_current(Protocol.ISO_15118_2),
            evse_current_limit_achieved=(
                await evse_controller.is_evse_current_limit_achieved()
            ),
            evse_voltage_limit_achieved=(
                await evse_controller.is_evse_voltage_limit_achieved()
            ),
            evse_power_limit_achieved=await evse_controller.is_evse_power_limit_achieved(),  # noqa
            evse_max_voltage_limit=await evse_controller.get_evse_max_voltage_limit(),
            evse_max_current_limit=await evse_controller.get_evse_max_current_limit(),
            evse_max_power_limit=await evse_controller.get_evse_max_power_limit(),
            evse_id=await evse_controller.get_evse_id(Protocol.ISO_15118_2),
            sa_schedule_tuple_id=self.comm_session.selected_schedule,
            # OCPP code start #
            meter_info=await self.comm_session.evse_controller.get_meter_info_v2(),
            receipt_required=receipt_required,
            # OCPP code end #
        )

        if dc_evse_status.evse_status_code is DCEVSEStatusCode.EVSE_SHUTDOWN:
            ocpp_temp.current_demand_finished = True

        if current_demand_res.meter_info:
            self.comm_session.sent_meter_info = current_demand_res.meter_info

        next_state: Optional[Type[State]] = None
        # if current_demand_res.receipt_required:
        #     # Если все же требуются показания счетчиков, то переходим в другое состояние
        #     next_state = MeteringReceipt

        self.create_next_message(
            next_state,
            current_demand_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_current_demand_req = False


class WeldingDetection(StateSECC):
    """
    Обработка WeldingDetectionReq (ISO 15118-2)
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_SECC_SEQUENCE_TIMEOUT)
        self.expecting_welding_detection_req = True

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            SupportedAppProtocolRes,
            V2GMessageV2,
        #   V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg_v2(
            message,
            [
                WeldingDetectionReq,
                SessionStopReq,
            ],
            self.expecting_welding_detection_req,
        )
        if not msg:
            return
            # Обработка session_stop_req на стороне
        if msg.body.session_stop_req:
            await SessionStop(self.comm_session).process_message(message, message_exi)
            return
        
            # Обработка WeldingDetectionReq на стороне
        # OCPP code start #
        welding_detection_req: WeldingDetectionReq = msg.body.welding_detection_req

        ev_status: dict = dict([
            ("DC_EVReady", welding_detection_req.dc_ev_status.ev_ready),
            ("DC_EVErrorCode", welding_detection_req.dc_ev_status.ev_error_code),
            ("DC_EVRESSSOC", welding_detection_req.dc_ev_status.ev_ress_soc),
        ])
        ocpp_temp.ev_status = ev_status
        # OCPP code end #

        welding_detection_res = WeldingDetectionRes(
            response_code=ResponseCode.OK,
            dc_evse_status=await self.comm_session.evse_controller.get_dc_evse_status(),
            evse_present_voltage=(
                await self.comm_session.evse_controller.get_evse_present_voltage(
                    Protocol.ISO_15118_2
                )
            ),
        )

        next_state = None
        self.create_next_message(
            next_state,
            welding_detection_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.ISO_V2_MSG_DEF,
        )

        self.expecting_welding_detection_req = False


def get_state_by_msg_type(message_type: Type[BodyBase]) -> Optional[Type[State]]:
    states_dict = {
        SessionSetupReq: SessionSetup,
        ServiceDiscoveryReq: ServiceDiscovery,
        ServiceDetailReq: ServiceDetail,
        PaymentServiceSelectionReq: PaymentServiceSelection,
        # CertificateInstallationReq: CertificateInstallation,
        # CertificateUpdateReq: CertificateUpdate,
        # PaymentDetailsReq: PaymentDetails,
        AuthorizationReq: Authorization,
        CableCheckReq: CableCheck,
        PreChargeReq: PreCharge,
        ChargeParameterDiscoveryReq: ChargeParameterDiscovery,
        PowerDeliveryReq: PowerDelivery,
        CurrentDemandReq: CurrentDemand,
        # MeteringReceiptReq: MeteringReceipt,
        WeldingDetectionReq: WeldingDetection,
        SessionStopReq: SessionStop,
    }

    return states_dict.get(message_type, None)
