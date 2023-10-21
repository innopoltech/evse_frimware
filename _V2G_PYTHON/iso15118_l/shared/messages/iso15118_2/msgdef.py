from pydantic import Field

from ....shared.messages import BaseModel
from ....shared.messages.iso15118_2.body import Body
from ....shared.messages.iso15118_2.header import MessageHeader


class V2GMessage(BaseModel):
    """ Подробнее в ISO 15118-2, глава 8.3.2 """

    header: MessageHeader = Field(..., alias="Header")
    body: Body = Field(..., alias="Body")

    def __str__(self):
        return str(self.body.get_message_name())
