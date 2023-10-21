from enum import Enum

class Timeouts(float, Enum):
    """
    Ограничения по таймауту для пар сообщений "запрос/ответ" в соответствии с ISO 15118-2. 
    В секундах.
    """

    # Специфичные тайминги
    V2G_EVCC_CABLE_CHECK_TIMEOUT    = 40
    V2G_EVCC_PRE_CHARGE_TIMEOUT     = 7

    # Тайминги сообщений
    SESSION_SETUP_REQ               = 2
    SERVICE_DISCOVERY_REQ           = 2
    SERVICE_DETAIL_REQ              = 5
    PAYMENT_SERVICE_SELECTION_REQ   = 2
    CERTIFICATE_INSTALLATION_REQ    = 5
    CERTIFICATE_UPDATE_REQ          = 5
    PAYMENT_DETAILS_REQ             = 5
    AUTHORIZATION_REQ               = 2
    CHARGE_PARAMETER_DISCOVERY_REQ  = 2
    CHARGING_STATUS_REQ             = 2
    METERING_RECEIPT_REQ            = 2
    POWER_DELIVERY_REQ              = 5
    CABLE_CHECK_REQ                 = 2
    PRE_CHARGE_REQ                  = 2
    CURRENT_DEMAND_REQ              = 0.25
    WELDING_DETECTION_REQ           = 2
    SESSION_STOP_REQ                = 2
