import json
import logging
import xmlrpc.client

from ..shared.iexi_codec import IEXICodec

logger = logging.getLogger(__name__)



def compare_messages(json_to_encode, decoded_json):
    json_obj = json.loads(json_to_encode)
    decoded_json_obj = json.loads(decoded_json)
    return sorted(json_obj.items()) == sorted(decoded_json_obj.items())


class ExificientEXICodec(IEXICodec):
    """Связующий класс между python и java. Является базовым НЕ абстрактным классом"""
    def __init__(self):

        self.client  = xmlrpc.client.ServerProxy("http://192.168.0.201:8005/EXI", use_builtin_types=True, verbose=False)
        _ = self.client.check()

    def encode(self, message: str, namespace: str) -> bytes:
        """
       Вызывает функцию кодирования сообщения в EXI
        """
        namespace = f"{namespace}"
        a = self.client.encode(message, namespace)
        if(type(a) != bytes):
            a = a.data
        return a

    def decode(self, stream: bytes, namespace: str) -> str:
        """
       Вызывает функцию декодирования сообщения из EXI
        """
        namespace = f"{namespace}"
        a = self.client.decode(stream, namespace)
        return a


    def get_version(self) -> str:
        """
        Версия кодека
        """
        return "0.01"
