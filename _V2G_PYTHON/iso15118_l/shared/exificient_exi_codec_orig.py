import json
import logging
from builtins import Exception

from ..shared.iexi_codec import IEXICodec
from ..shared.settings import JAR_FILE_PATH

logger = logging.getLogger(__name__)



def compare_messages(json_to_encode, decoded_json):
    json_obj = json.loads(json_to_encode)
    decoded_json_obj = json.loads(decoded_json)
    return sorted(json_obj.items()) == sorted(decoded_json_obj.items())


class ExificientEXICodec(IEXICodec):
    """Связующий класс между python и java. Является базовым НЕ абстрактным классом"""
    def __init__(self):
        from py4j.java_gateway import JavaGateway

        logging.getLogger("py4j").setLevel(logging.CRITICAL)
        self.gateway = JavaGateway.launch_gateway(
            classpath=JAR_FILE_PATH,
            die_on_exit=True,
            # javaopts=["--add-opens", "java.base/java.lang=ALL-UNNAMED"],
            # use_shell=True
        )

        self.exi_codec = self.gateway.jvm.com.siemens.ct.exi.main.cmd.EXICodec()

    def encode(self, message: str, namespace: str) -> bytes:
        """
       Вызывает функцию кодирования сообщения в EXI
        """
        exi = self.exi_codec.encode(message, namespace)

        if exi is None:
            raise Exception(self.exi_codec.get_last_encoding_error())
        return exi

    def decode(self, stream: bytes, namespace: str) -> str:
        """
       Вызывает функцию декодирования сообщения из EXI
        """
        decoded_message = self.exi_codec.decode(stream, namespace)

        if decoded_message is None:
            raise Exception(self.exi_codec.get_last_decoding_error())
        return decoded_message

    def get_version(self) -> str:
        """
        Версия кодека
        """
        return self.exi_codec.get_version()
