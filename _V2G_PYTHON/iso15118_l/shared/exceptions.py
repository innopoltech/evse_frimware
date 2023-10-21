from typing import Any

from ..shared.messages.iso15118_2.datatypes import ResponseCode


class InvalidInterfaceError(Exception):
    """
    Не верно указан локальный интерфейс
    """


class NoLinkLocalAddressError(Exception):
    """
    Не найдет локальный адрес IPv6
    """


class MACAddressNotFound(Exception):
    """
    Не удалось получить MAC адрес
    """


class InvalidMessageError(Exception):
    """
    Сообщение неизвестного формата
    """


class InvalidV2GTPMessageError(Exception):
    """ Ошибка создания V2GTP сообщения """


class InvalidSDPRequestError(Exception):
    """ Ошибка создания SDP запроса """


class InvalidSDPResponseError(Exception):
    """ Ошибка создания SDP ответа """

class SDPFailedError(Exception):
    """
    Ошибка в работе SDP
    """


class MessageProcessingError(Exception):
    """
    Не удалось правильно обработать входящее сообщение
    """

    def __init__(self, message_name: str):
        Exception.__init__(self)
        self.message_name = message_name


class FaultyStateImplementationError(Exception):
    """
    Не было предоставлено следующее состояние
    """


class InvalidPayloadTypeError(Exception):
    """
    Неизвестная или поврежденная нагрузка
    """


class InvalidProtocolError(Exception):
    """
    Неизвестный протокол
    """


class EXIEncodingError(Exception):
    """ Ошибка кодирования EXI """


class EXIDecodingError(Exception):
    """ Ошибка декодирования EXI """


class InvalidSettingsValueError(Exception):
    """
    Не корректные настройки
    """

    def __init__(self, entity: str, setting: str, invalid_value: Any):
        Exception.__init__(self)
        self.entity = entity
        self.setting = setting
        self.invalid_value = invalid_value


class CertSignatureError(Exception):
    """
    Не удалось проверить подпись
    """

    def __init__(self, subject: str, issuer: str, extra_info: str = ""):
        Exception.__init__(self)
        self.subject = subject
        self.issuer = issuer
        self.extra_info = extra_info


class CertNotYetValidError(Exception):
    """
    Сертификат более не достоверен
    """

    def __init__(self, subject: str):
        Exception.__init__(self)
        self.subject = subject


class CertExpiredError(Exception):
    """
    Срок действия сертификата истек
    """

    def __init__(self, subject: str):
        Exception.__init__(self)
        self.subject = subject


class CertRevokedError(Exception):
    """
    Сертификат был отозван
    """

    def __init__(self, subject: str):
        Exception.__init__(self)
        self.subject = subject


class CertAttributeError(Exception):
    """
    Неожиданный атрибут сертификата
    """

    def __init__(self, subject: str, attr: str, invalid_value: str):
        Exception.__init__(self)
        self.subject = subject
        self.attr = attr
        self.invalid_value = invalid_value


class CertChainLengthError(Exception):
    """ Слишком много сертификатов в цепочке"""

    def __init__(self, allowed_num_sub_cas: int, num_sub_cas: int):
        Exception.__init__(self)
        self.allowed_num_sub_cas = allowed_num_sub_cas
        self.num_sub_cas = num_sub_cas


class EncryptionError(Exception):
    """ Ошибка кодирования приватного ключа"""


class DecryptionError(Exception):
    """ Ошибка декодирования приватного ключа"""


class KeyTypeError(Exception):
    """ Неизвестный тип приватного ключа """


class PrivateKeyReadError(Exception):
    """ Не удалось прочитать приватный ключ"""


class NoSupportedProtocols(Exception):
    """ Не поддерживаемый протокол"""


class NoSupportedEnergyServices(Exception):
    """ Не поддерживаемый тип зарядки"""


class NoSupportedAuthenticationModes(Exception):
    """ Не поддерживаемый тип аутентификации"""


class OCSPServerNotFoundError(Exception):
    """
    Не удалось найти OCSP сервер
    """

    def __init__(self):
        Exception.__init__(
            self,
            "No OCSP server entry in Authority Information Access extension field.",
        )


class V2GMessageValidationError(Exception):
    """ Поврежденное V2G сообщение"""

    def __init__(self, reason: str, response_code: ResponseCode, message: Any):
        Exception.__init__(self)
        self.reason = reason
        self.response_code = response_code
        self.message = message
