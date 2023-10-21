import json
import logging
from base64 import b64decode, b64encode
from typing import Union

from pydantic import ValidationError

from ..shared.exceptions import (
    EXIDecodingError,
    EXIEncodingError,
    V2GMessageValidationError,
)
from ..shared.exificient_exi_codec import ExificientEXICodec
from ..shared.iexi_codec import IEXICodec
from ..shared.messages import BaseModel
from ..shared.messages.app_protocol import (
    SupportedAppProtocolReq,
)
# from ..shared.messages.din_spec.body import get_msg_type as get_msg_type_dinspec
# from ..shared.messages.din_spec.msgdef import V2GMessage as V2GMessageDINSPEC
from ..shared.messages.enums import Namespace
from ..shared.messages.iso15118_2.body import get_msg_type
from ..shared.messages.iso15118_2.datatypes import ResponseCode
from ..shared.messages.iso15118_2.msgdef import V2GMessage as V2GMessageV2
from ..shared.settings import MESSAGE_LOG_EXI, MESSAGE_LOG_JSON

logger = logging.getLogger(__name__)


class CustomJSONEncoder(json.JSONEncoder):
    """
    Пользовательский JSON-кодер, позволяющий кодировать байтовые массивы в Base64
    в соответствии с XSD-типом base64Binary.
    """

    # pylint: disable=method-hidden
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


class CustomJSONDecoder(json.JSONDecoder):
    """
    Пользовательский JSON-кодер, позволяющий декодировать Base64 в байтовые массивы 

    object_hook() используется, чтобы сопоставить соответствующие поля сообщения и типа данных ISO 15118, 
    к полям  Base64 (base64_encoded_fields_set)
    """

    base64_encoded_fields_set = {
        "Certificate",
        "DHPublicKey",
        "GenChallenge",
        "MeterSignature",
        "OEMProvisioningCert",
        "SECP521_EncryptedPrivateKey",
        "SigMeterReading",
        "TPM_EncryptedPrivateKey",
        "Value",
        "value",
        "X448_EncryptedPrivateKey",
        "DigestValue",
    }

    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, dct) -> dict:
        for field in self.base64_encoded_fields_set.intersection(set(dct)):
            if field in ("Value", "value") and isinstance(dct[field], int):
                continue

            if field in ("Value", "value") and isinstance(dct[field], str):
                if len(dct[field]) <= 15:
                    continue

            if field == "Certificate" and isinstance(dct[field], list):
                certificate_list = [b64decode(value) for value in dct[field]]
                dct[field] = certificate_list
                continue

            dct[field] = b64decode(dct[field])
        return dct


class EXI:
    """
    Singleton выбранного кодека EXI.
    Используется во время операций кодирования и декодирования.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EXI, cls).__new__(cls)
            cls._instance.exi_codec = None
        return cls._instance

    def set_exi_codec(self, codec: IEXICodec):
        logger.info(f"EXI Codec version: {codec.get_version()}")
        self.exi_codec = codec

    def get_exi_codec(self) -> IEXICodec:
        """
        Если exi_codec не был установлен, то возвращается кодек по умолчанию
        """
        if self.exi_codec is None:
            self.exi_codec = ExificientEXICodec()
        return self.exi_codec

    def to_exi(self, msg_element: BaseModel, protocol_ns: str) -> bytes:
        """
        Кодировка сообщения в массив байт
        """
        msg_to_dct: dict = msg_element.model_dump(by_alias=True, exclude_none=True)
        try:
            # Pydantic не экспортирует имя самой модели, нужно добавить его вручную
            # if (
            #     str(msg_element) == "CertificateChain"
            #     and protocol_ns == Namespace.ISO_V2_MSG_DEF
            # ):
            #     # TOD: If we add `ContractSignatureCertChain` as the return of __str__
            #     #       for the CertificateChain class, do we still need this if clause?
            #     # In case of CertificateInstallationRes and CertificateUpdateRes,
            #     # str(message) would not be 'ContractSignatureCertChain' but
            #     # 'CertificateChain' (the type of ContractSignatureCertChain)
            #     message_dict = {"ContractSignatureCertChain": msg_to_dct}
            # elif str(msg_element) == "SignedCertificateChain":
            #     # TOD: If we add `OEMProvisioningCertificateChain` as the
            #     #  return of __str__ for the SignedCertificateChain class, do we still
            #     #  need this if clause?
            #     # In case of CertificateInstallationReq,
            #     # str(message) would not be 'OEMProvisioningCertificateChain' but
            #     # 'SignedCertificateChain' (the type of OEMProvisioningCertificateChain)
            #     message_dict = {"OEMProvisioningCertificateChain": msg_to_dct}
            if isinstance(msg_element, V2GMessageV2): #or isinstance(msg_element, V2GMessageDINSPEC):
                message_dict = {"V2G_Message": msg_to_dct}
            else:
                message_dict = {str(msg_element): msg_to_dct}

            msg_content = json.dumps(message_dict, cls=CustomJSONEncoder)
        except Exception as exc:
            raise EXIEncodingError(
                f"EXIEncodingError for {str(msg_element)}: \
                                   {exc}"
            ) from exc

        if MESSAGE_LOG_JSON:
            logger.info(f"Message to encode (ns={protocol_ns}): {msg_content}")

        try:
            exi_stream = self.exi_codec.encode(msg_content, protocol_ns)
        except Exception as exc:
            logger.error(f"EXIEncodingError for {str(msg_element)}: {exc}")
            raise EXIEncodingError(
                f"EXIEncodingError for {str(msg_element)}: " f"{exc}"
            ) from exc

        if MESSAGE_LOG_EXI:
            logger.debug(f"EXI-encoded message: {exi_stream.hex()}")

        return exi_stream

    def from_exi(
        self, exi_message: bytes, namespace: str
    ) -> Union[
        SupportedAppProtocolReq,
        V2GMessageV2,
        # V2GMessageDINSPEC,
    ]:
        """
        Декодирует EXI-кодированный массив байтов в сообщение в соответствии с указанным типом полезной нагрузки
        """
        if MESSAGE_LOG_EXI:
            logger.debug(f"EXI-encoded message (ns={namespace}): {exi_message.hex()}")

        try:
            exi_decoded = self.exi_codec.decode(exi_message, namespace)
        except Exception as exc:
            raise EXIDecodingError(
                f"EXIDecodingError ({exc.__class__.__name__}): " f"{exc}"
            ) from exc
        try:
            decoded_dict = json.loads(exi_decoded, cls=CustomJSONDecoder)
        except json.JSONDecodeError as exc:
            raise EXIDecodingError(
                f"JSON decoding error ({exc.__class__.__name__}) while "
                f"processing decoded EXI: {exc}"
            ) from exc

        if MESSAGE_LOG_JSON:
            logger.info(f"Decoded message (ns={namespace}): {exi_decoded}")

        try:
            if namespace == Namespace.SAP and "supportedAppProtocolReq" in decoded_dict:
                return SupportedAppProtocolReq.model_validate(
                    decoded_dict["supportedAppProtocolReq"]
                )
            if namespace == Namespace.ISO_V2_MSG_DEF:
                return V2GMessageV2.model_validate(decoded_dict["V2G_Message"])
            
            # if namespace == Namespace.DIN_MSG_DEF:
            #     return V2GMessageDINSPEC.parse_obj(decoded_dict["V2G_Message"])
            # if namespace == Namespace.SAP and "supportedAppProtocolRes" in decoded_dict:
            #     return SupportedAppProtocolRes.parse_obj(
            #         decoded_dict["supportedAppProtocolRes"]
            #     )

            raise EXIDecodingError("Can't identify protocol to use for decoding")
        except ValidationError as exc:
            if namespace == Namespace.ISO_V2_MSG_DEF:
                msg_name = next(iter(decoded_dict["V2G_Message"]["Body"]))
                msg_type = get_msg_type(msg_name)
            # elif namespace == Namespace.DIN_MSG_DEF:
            #     msg_name = next(iter(decoded_dict["V2G_Message"]["Body"]))
            #     msg_type = get_msg_type_dinspec(msg_name)
            elif namespace == Namespace.SAP:
                if "supportedAppProtocolReq" in decoded_dict:
                    msg_type = SupportedAppProtocolReq

            raise V2GMessageValidationError(
                f"Validation error: {exc}. \n\nDecoded dict: " f"{decoded_dict}",
                ResponseCode.FAILED,
                msg_type,
            ) from exc

        except V2GMessageValidationError as exc:
            raise exc
        except EXIDecodingError as exc:
            raise EXIDecodingError(
                f"EXI decoding error: {exc}. \n\nDecoded dict: " f"{decoded_dict}"
            ) from exc
