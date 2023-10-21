import logging
from abc import ABC
from typing import List, Optional, Type, TypeVar, Union

from comm_session_handler import SECCCommunicationSession
from ..shared.messages.app_protocol import (
    ResponseCodeSAP,
    SupportedAppProtocolReq,
    SupportedAppProtocolRes,
)
# from ..shared.messages.din_spec.body import BodyBase as BodyBaseDINSPEC
# from ..shared.messages.din_spec.body import (
#     SessionSetupReq as SessionSetupReqDINSPEC,
# )
# from ..shared.messages.din_spec.body import get_msg_type as get_msg_type_dinspec
# from ..shared.messages.din_spec.datatypes import (
#     ResponseCode as ResponseCodeDINSPEC,
# )
# from ..shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from ..shared.messages.enums import Namespace
from ..shared.messages.iso15118_2.body import BodyBase as BodyBaseV2
from ..shared.messages.iso15118_2.body import (
    SessionSetupReq as SessionSetupReqV2,
)
from ..shared.messages.iso15118_2.body import get_msg_type
from ..shared.messages.iso15118_2.datatypes import ResponseCode as ResponseCodeV2
from ..shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from ..shared.notifications import StopNotification
from ..shared.states import State, Terminate

logger = logging.getLogger(__name__)


class StateSECC(State, ABC):
    """
    Расширяет функционал для SECC FSM

    """

    # Код возврата, по умолчанию 'Ok'
    # response_code: Union[
    #     ResponseCodeDINSPEC, ResponseCodeV2
    # ] = ResponseCodeV2.OK
    response_code: ResponseCodeV2 = ResponseCodeV2.OK

    def __init__(
        self, comm_session: "SECCCommunicationSession", timeout: Union[float, int] = 0
    ):
        """
        Каждое состояние, наследуемое от State, должно реализовать __init__ 
        и вызывать super().__init__() с соответствующим состоянию таймаутом.
        """
        super().__init__(comm_session, timeout)
        self.comm_session: "SECCCommunicationSession" = comm_session

    T = TypeVar("T")

    # def check_msg_dinspec(
    #     self,
    #     message: Union[
    #         SupportedAppProtocolReq,
    #         SupportedAppProtocolRes,
    #         V2GMessageV2,
    #         # V2GMessageV20,
    #         # V2GMessageDINSPEC,
    #     ],
    #     expected_msg_types: List[
    #         Union[
    #             Type[SupportedAppProtocolReq],
    #             # Type[BodyBaseDINSPEC],
    #             # Type[V2GRequestV20],
    #             Type[BodyBaseV2],
    #         ]
    #     ],
    #     expect_first: bool = True,
    # ) -> V2GMessageDINSPEC:
    #     return self.check_msg(
    #         message, V2GMessageDINSPEC, expected_msg_types, expect_first
    #     )

    def check_msg_v2(                   # Выполняет проверку сообщений, содержащихся в протоколе ISO 15118-2
        self,
        message: Union[
            SupportedAppProtocolReq,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        expected_msg_types: List[
            Union[
                Type[SupportedAppProtocolReq],
                Type[BodyBaseV2],
                # Type[BodyBaseDINSPEC],
            ]
        ],
        expect_first: bool = True,
    ) -> V2GMessageV2:
        return self.check_msg(message, V2GMessageV2, expected_msg_types, expect_first)
    
    def check_msg(
        self,
        message: Union[
            SupportedAppProtocolReq,
            V2GMessageV2,
            # V2GMessageDINSPEC,
        ],
        expected_return_type: Type[T],
        expected_msg_types: List[
            Union[
                Type[SupportedAppProtocolReq],
                Type[BodyBaseV2],
                # Type[BodyBaseDINSPEC],
            ]
        ],
        expect_first: bool = True,
    ) -> Optional[T]:
        """
        Уменьшает кол-во кода в функциях process_message().
        Выполняются следующие проверка:
        1. Ожидается ли входящее сообщение в данном состоянии.
        2. Действителен ли идентификатор сессии (для сообщений после SessionSetupRes)

        В случае успешной проверки - возвращается проверенное сообщение, в случае ошибки - None.
        При этом машина состояний будет остановлена, и будет послано уведомление об остановке сессии.
        """
        if not isinstance(message, expected_return_type):       # Сообщение соответствует ожидаемому типу
            self.stop_state_machine(
                f"{type(message)}' not a valid message type " f"in state {str(self)}",
                message,
                ResponseCodeV2.FAILED_SEQUENCE_ERROR,
            )
            return None

        msg_body: Union[
            SupportedAppProtocolReq, BodyBaseV2#, BodyBaseDINSPEC
        ]
        if isinstance(message, V2GMessageV2): #or isinstance(message, V2GMessageDINSPEC):   
            # ISO 15118-2
            msg_body = message.body.get_message()           # Извлечение тела сообщения
        else:
            # SupportedAppProtocolReq
            msg_body = message

        match = False
        for idx, expected_msg_type in enumerate(expected_msg_types):
            if (
                idx == 0
                and expect_first
                and not isinstance(msg_body, expected_msg_type)
            ):
                self.stop_state_machine(        # Если пришло сообщение иного типа, чем ожидалось 
                    f"{str(message)}' not accepted in state " f"{str(self)}",
                    message,
                    ResponseCodeV2.FAILED_SEQUENCE_ERROR,
                )
                return None

            if isinstance(msg_body, expected_msg_type):
                match = True
                break

        if not match:       # Если тип сообщения не входит в список ожидаемых
            self.stop_state_machine(
                f"{str(message)}' not accepted in state " f"{str(self)}",
                message,
                ResponseCodeV2.FAILED_SEQUENCE_ERROR,
            )
            return None

        if (                                                # Если сообщение "битое"
            not isinstance( 
                msg_body,
                (SessionSetupReqV2)#  SessionSetupReqDINSPEC),
            )
            and not isinstance(message, SupportedAppProtocolReq)
            and not message.header.session_id == self.comm_session.session_id
        ):
            self.stop_state_machine(
                f"{str(message)}'s session ID "
                f"{message.header.session_id} does not match "
                f"session ID {self.comm_session.session_id}",
                message,
                ResponseCodeV2.FAILED_UNKNOWN_SESSION,
            )
            return None

        return message

    def stop_state_machine(
        self,
        reason: str,
        faulty_request: Union[
            SupportedAppProtocolReq,
            V2GMessageV2,
            # V2GMessageDINSPEC,
            None,
        ],
        response_code: Union[
            ResponseCodeSAP, ResponseCodeV2#, ResponseCodeDINSPEC
        ],
        message_body_type: Optional[type] = None,
        namespace: Optional[Namespace] = None,
    ):
        """
        В случае ошибки в работе машины состояний, перед завершением сессии общения,
        необходимо отправить ответ содержащий минимальный набор данных.
        Подробнее в [V2G2-736] и [V2G2-538]

        SECC всегда должен иметь возможность ответить ошибкой на входящее сообщение, 
        даже если оно пришло вне очереди
        """
        self.comm_session.stop_reason = StopNotification(
            False, reason, self.comm_session.writer.get_extra_info("peername")
        )

        if isinstance(faulty_request, V2GMessageV2):            # Получение типа и пространства имен не валидного сообщения
            msg_type = get_msg_type(str(faulty_request))
            msg_namespace = Namespace.ISO_V2_MSG_DEF
        # elif isinstance(faulty_request, V2GMessageDINSPEC):
        #     msg_type = get_msg_type_dinspec(str(faulty_request))
        #     msg_namespace = Namespace.DIN_MSG_DEF
        elif isinstance(faulty_request, SupportedAppProtocolReq):
            msg_namespace = Namespace.SAP
            msg_type = faulty_request
        else:
            msg_type = message_body_type
            msg_namespace = namespace

        if msg_namespace == Namespace.ISO_V2_MSG_DEF:  # Извлечение заранее подготовленного сообщения с ошибкой
            error_res = self.comm_session.failed_responses_isov2.get(msg_type)
            error_res.response_code = response_code
            self.create_next_message(Terminate, error_res, 0, Namespace.ISO_V2_MSG_DEF)
        # elif msg_namespace == Namespace.DIN_MSG_DEF:
        #     error_res = self.comm_session.failed_responses_din_spec.get(msg_type)
        #     error_res.response_code = response_code
        #     self.create_next_message(Terminate, error_res, 0, Namespace.DIN_MSG_DEF)
        elif msg_namespace == Namespace.SAP:
            error_res = SupportedAppProtocolRes(response_code=response_code)
            self.create_next_message(Terminate, error_res, 0, Namespace.SAP)
        else:
            # Никогда не должно быть выполнено 
            logger.error(
                "Something's off here: the faulty_request and response_code "
                "are not of the expected type"
            )
