from typing import List

from pydantic import Field, HttpUrl

from ...shared.messages import BaseModel


class Transform(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class Transforms(BaseModel):
    """
    По [V2G2-767], максимальное кол-во преобразований равно единице
    """

    transform: List[Transform] = Field(..., max_items=1, alias="Transform")


class DigestMethod(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class SignatureMethod(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class CanonicalizationMethod(BaseModel):
    algorithm: HttpUrl = Field(..., alias="Algorithm")


class Reference(BaseModel):
    """
    Объект XML подписи.

    V2G body element contains Id="ID1"

    <v2gci_b:AuthorizationReq v2gci_b:Id="ID1">
        <v2gci_b:GenChallenge>U29tZSBSYW5kb20gRGF0YQ==</v2gci_b:GenChallenge>
    </v2gci_b:AuthorizationReq>

    <xmlsig:Signature>
        <xmlsig:SignedInfo>
            <xmlsig:CanonicalizationMethod Algorithm="http://www.w3.org/TR/canonical-exi/"/>
            <xmlsig:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/> # noqa: E501
            <xmlsig:Reference URI="#ID1">
                <xmlsig:Transforms>
                    <xmlsig:Transform Algorithm="http://www.w3.org/TR/canonical-exi/"/>
                </xmlsig:Transforms>
                <xmlsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <xmlsig:DigestValue>0bXgPQBlvuVrMXmERTBR61TKGPwOCRYXT4s8d6mPSqk=</xmlsig:DigestValue> # noqa: E501
            </xmlsig:Reference>
        </xmlsig:SignedInfo>
        <xmlsig:SignatureValue></xmlsig:SignatureValue>
    </xmlsig:Signature>

    """

    transforms: Transforms = Field(..., alias="Transforms")
    digest_method: DigestMethod = Field(..., alias="DigestMethod")
    digest_value: bytes = Field(..., alias="DigestValue")
    id: str = Field(None, alias="Id")
    uri: str = Field(None, alias="URI")


class SignedInfo(BaseModel):
    """
    Относится к Signature, ISO 15118-2.

    В соответствии с [V2G2-909] - не более 4 подписанных элементов.
    """
    canonicalization_method: CanonicalizationMethod = Field(
        ..., alias="CanonicalizationMethod"
    )
    signature_method: SignatureMethod = Field(..., alias="SignatureMethod")
    reference: List[Reference] = Field(..., max_items=4, alias="Reference")

    def __str__(self):
        return type(self).__name__


class SignatureValue(BaseModel):
    value: bytes = Field(..., alias="value")


class Signature(BaseModel):
    signed_info: SignedInfo = Field(..., alias="SignedInfo")
    signature_value: SignatureValue = Field(..., alias="SignatureValue")


class X509IssuerSerial(BaseModel):
    x509_issuer_name: str = Field(..., alias="X509IssuerName")
    x509_serial_number: int = Field(..., alias="X509SerialNumber")


class SignedElement(BaseModel):
    """
    Элемент, который должен быть подписан.

    Например:
    Для AuthorizationReq это полное сообщение.
    Для CertificateInstallationRes, это 4 элемента сообщения, но не все сообщение целиком.
    """
