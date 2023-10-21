from typing import Optional
from pydantic import Field, validator

from ....shared.messages import BaseModel
from ....shared.messages.iso15118_2.datatypes import Notification
from ....shared.messages.xmldsig import Signature


class MessageHeader(BaseModel):
    """Подробнее в ISO 15118-2, глава 8.3.3 """

    # XSD тип hexBinary в котором 8 байт закодированы как 16 шестнадцатеричных символа
    session_id: str = Field(..., max_length=16, alias="SessionID")
    notification: Optional[Notification] = Field(None, alias="Notification")
    signature: Optional[Signature] = Field(None, alias="Signature")

    @validator("session_id")
    def check_sessionid_is_hexbinary(cls, value):
        """
        Проверка, поле session_id действительно 16 шестнадцатеричных символов эквивалентных 8 байтам
        """
        # pylint: disable=no-self-argument
        # pylint: disable=no-self-use
        try:
            int(value, 16)
            return value
        except ValueError as exc:
            raise ValueError(
                f"Invalid value '{value}' for SessionID (must be "
                f"hexadecimal representation of max 8 bytes)"
            ) from exc
