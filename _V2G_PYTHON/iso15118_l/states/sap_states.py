import logging
from typing import Type, Union

from comm_session_handler import SECCCommunicationSession
# from din_spec_states import SessionSetup as SessionSetupDINSPEC
from .iso15118_2_states import SessionSetup as SessionSetupV2
from .secc_state import StateSECC
from ..shared.messages.app_protocol import (
    ResponseCodeSAP,
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
# from ..shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from ..shared.messages.enums import Namespace, Protocol
from ..shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from ..shared.messages.timeouts import Timeouts
from ..shared.states import State, Terminate
from ..OCPP.ocpp_template import ocpp_temp

logger = logging.getLogger(__name__)


class SupportedAppProtocol(StateSECC):
    """
    Состояния для обработки SupportedAppProtocolReq от EVCC,
    согласно взаимно поддерживаемой версии ISO 15118.
    """

    def __init__(self, comm_session: SECCCommunicationSession):
        super().__init__(comm_session, Timeouts.V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT)

    async def process_message(
        self,
        message: Union[
            SupportedAppProtocolReq,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        message_exi: bytes = None,
    ):
        msg = self.check_msg(           # Проверка сообщения
            message, SupportedAppProtocolReq, [SupportedAppProtocolReq]
        )
        if not msg:
            return

        sap_req: SupportedAppProtocolReq = msg
                        # Составление и сортировка списка поддерживаемых протоколов из запроса
        sap_req.app_protocol.sort(key=lambda proto: proto.priority)
        sap_res: Union[SupportedAppProtocolRes, None] = None
        supported_ns_list = [
            protocol.ns.value                       
            for protocol in self.comm_session.config.supported_protocols            
        ]
        next_state: Type[State] = Terminate  # Значение по умолчанию

        p_AppProtocols: list = []

        selected_protocol = Protocol.UNKNOWN
        for protocol in sap_req.app_protocol:       # В первую очередь рассматриваются протоколы с наибольшим приоритетом

            obj = dict([                # Извлечение параметров протокола в словари
                ("ProtocolNamespace",protocol.protocol_ns),
                ("VersionNumberMajor", protocol.major_version),
                ("VersionNumberMinor", protocol.minor_version),
                ("SchemaID", protocol.schema_id),
                ("Priority", protocol.priority)
            ])
            p_AppProtocols.append(obj)

            if protocol.protocol_ns in supported_ns_list:   # Если протокол поддерживается SECC
                if (
                    protocol.protocol_ns == Protocol.ISO_15118_2.ns.value
                    and protocol.major_version == 2
                ):
                    selected_protocol = Protocol.get_by_ns(protocol.protocol_ns)
                    next_state = SessionSetupV2

                    if protocol.minor_version == 0:
                        res = ResponseCodeSAP.NEGOTIATION_OK
                    else:
                        res = ResponseCodeSAP.MINOR_DEVIATION

                    sap_res = SupportedAppProtocolRes(
                        response_code=res, schema_id=protocol.schema_id
                    )
                    break      # Если major_version протокола совпадает с SECC, то используется выбранный протокол

                # if (
                #     protocol.protocol_ns == Protocol.DIN_SPEC_70121.ns.value
                #     and protocol.major_version == 2
                # ):
                #     selected_protocol = Protocol.get_by_ns(protocol.protocol_ns)

                #     # This is the earliest point where we realize
                #     # that we are dealing with DINSPEC.
                #     self.comm_session.selected_charging_type_is_ac = False
                #     next_state = SessionSetupDINSPEC

                #     if protocol.minor_version == 0:
                #         res = ResponseCodeSAP.NEGOTIATION_OK
                #     else:
                #         res = ResponseCodeSAP.MINOR_DEVIATION

                #     sap_res = SupportedAppProtocolRes(
                #         response_code=res, schema_id=protocol.schema_id
                #     )
                #     break

        ocpp_temp.ev_app_protocol = selected_protocol


        if not sap_res:             # Нет совпадающих протоколов
            self.stop_state_machine(
                "SupportedAppProtocol negotiation failed. ",
                message,
                ResponseCodeSAP.NEGOTIATION_FAILED,
            )
            return

        self.create_next_message(       # Создание сообщения для ответа
            next_state,
            sap_res,
            Timeouts.V2G_SECC_SEQUENCE_TIMEOUT,
            Namespace.SAP,
        )
        self.comm_session.protocol = selected_protocol
        self.comm_session.evse_controller.set_selected_protocol(selected_protocol)
        logger.info(f"Chosen protocol: {self.comm_session.protocol}")
