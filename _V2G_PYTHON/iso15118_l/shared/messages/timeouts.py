from enum import Enum


class Timeouts(float, Enum):
    """
    Таймауты для 15118-2 and ISO 15118-20.
    В секундах.
    """

    SDP_REQ = 0.25
    SUPPORTED_APP_PROTOCOL_REQ = 2.0
    V2G_EVCC_COMMUNICATION_SETUP_TIMEOUT = 20.0
    V2G_SECC_SEQUENCE_TIMEOUT = 60
    V2G_EVCC_ONGOING_TIMEOUT = 60
