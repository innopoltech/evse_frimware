
import secrets
def get_random_bytes(nbytes: int) -> bytes:
    """
    Создание рандомного массива байт, заданной длинны
    """
    return secrets.token_bytes(nbytes)

""" Не используется"""
# import logging
# import os

# import ssl
# from base64 import urlsafe_b64encode
# from datetime import datetime
# from enum import Enum, auto
# from ssl import DER_cert_to_PEM_cert, SSLContext, SSLError, VerifyMode
# from typing import Dict, List, Optional, Tuple, Union

# from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
# from cryptography.hazmat.backends.openssl.backend import Backend
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives.asymmetric.ec import (
#     SECP256R1,
#     EllipticCurvePrivateKey,
#     EllipticCurvePublicKey,
#     derive_private_key,
# )
# from cryptography.hazmat.primitives.asymmetric.utils import (
#     decode_dss_signature,
#     encode_dss_signature,
# )
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives.hashes import SHA256, Hash, HashAlgorithm
# from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
# from cryptography.hazmat.primitives.serialization import (
#     Encoding,
#     PublicFormat,
#     load_der_private_key,
#     load_pem_private_key,
# )
# from cryptography.x509 import (
#     AuthorityInformationAccessOID,
#     Certificate,
#     ExtensionNotFound,
#     ExtensionOID,
#     NameOID,
#     load_der_x509_certificate,
# )
# from cryptography.x509.ocsp import OCSPRequestBuilder

# from iso15118.shared.exceptions import (
#     CertAttributeError,
#     CertChainLengthError,
#     CertExpiredError,
#     CertNotYetValidError,
#     CertRevokedError,
#     CertSignatureError,
#     DecryptionError,
#     EncryptionError,
#     InvalidProtocolError,
#     KeyTypeError,
#     OCSPServerNotFoundError,
#     PrivateKeyReadError,
# )
# from iso15118.shared.exi_codec import EXI
# from iso15118.shared.messages.enums import Namespace, Protocol
# from iso15118.shared.messages.iso15118_2.datatypes import (
#     CertificateChain as CertificateChainV2,
# )
# from iso15118.shared.messages.iso15118_2.datatypes import (
#     SubCertificates as SubCertificatesV2,
# )
# from iso15118.shared.messages.iso15118_20.common_messages import (
#     CertificateChain as CertificateChainV20,
# )
# from iso15118.shared.messages.iso15118_20.common_messages import SignedCertificateChain
# from iso15118.shared.messages.iso15118_20.common_messages import (
#     SubCertificates as SubCertificatesV20,
# )
# from iso15118.shared.messages.xmldsig import (
#     CanonicalizationMethod,
#     DigestMethod,
#     Reference,
#     Signature,
#     SignatureMethod,
#     SignatureValue,
#     SignedInfo,
#     Transform,
#     Transforms,
# )
# from iso15118.shared.settings import ENABLE_TLS_1_3, get_PKI_PATH

# logger = logging.getLogger(__name__)


# class KeyEncoding(str, Enum):
#     PEM = auto()
#     DER = auto()




# def get_ssl_context(server_side: bool, ciphersuites: str = None) -> Optional[SSLContext]:
#     """
#     Creates an SSLContext object for the TCP client or TCP server.
#     An SSL context holds various data longer-lived than single SSL
#     connections, such as SSL configuration options, certificate(s) and
#     private key(s). It also manages a cache of SSL sessions for
#     server-side sockets, in order to speed up repeated connections from
#     the same clients.

#     The IANA cipher suite names
#     - TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 and
#     - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
#     (as given in ISO 15118-2) map to the OpenSSL cipher suite names
#     - ECDH-ECDSA-AES128-SHA256 and
#     - ECDHE-ECDSA-AES128-SHA256,
#     respectively. See https://testssl.sh/openssl-iana.mapping.html
#     TODO More/other cipher suites are allowed in ISO 15118-20

#     Args:
#         server_side: Whether this SSLContext object is for the TLS server (True)
#                      or TLS client (False)

#     Returns:
#         An SSLContext object

#     TODO We use the test PKI provided for the CharIN Testival Europe 2021.
#          Need to figure out a way to securely store those certs and keys
#          as well as read the password.
#     """

#     if ENABLE_TLS_1_3:
#         ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
#     else:
#         # Specifying protocol as `PROTOCOL_TLS` does best effort.
#         # TLSv1.3 will be attempted and would fallback to 1.2 if not possible.
#         # However, there may be TLS clients that can't perform
#         # 1.2 fallback, here we explicitly set the TLS version
#         # to 1.2, to be sure we won't fall into connection issues
#         ssl_context = SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)

#     if server_side:
#         try:
#             ssl_context.load_cert_chain(
#                 certfile=os.path.join(get_PKI_PATH(), CertPath.SECC_LEAF_PEM),
#                 keyfile=os.path.join(get_PKI_PATH(), KeyPath.SECC_LEAF_PEM),
#                 password=load_priv_key_pass(os.path.join(
#                     get_PKI_PATH(), KeyPasswordPath.SECC_LEAF_KEY_PASSWORD)),
#             )
#             ssl_context.load_verify_locations(os.path.join(get_PKI_PATH(), CertPath.CPO_SUB_CA1_PEM))
#             ssl_context.load_verify_locations(os.path.join(get_PKI_PATH(), CertPath.CPO_SUB_CA2_PEM))
#         except SSLError:
#             logger.exception(
#                 "SSLError, can't load SECC certificate chain for SSL "
#                 "context. Private key (keyfile) probably doesn't "
#                 "match certificate (certfile) or password for "
#                 "private is key invalid. Returning None instead."
#             )
#             return None
#         except FileNotFoundError:
#             logger.exception("Can't find certfile or keyfile for SSL context")
#             return None
#         except Exception as exc:
#             logger.exception(exc)
#             return None

#         if ENABLE_TLS_1_3:
#             # In 15118-20 we should also verify EVCC's certificate chain.
#             # The spec however says TLS 1.3 should also support 15118-2
#             # (Table 5 in V2G20 specification)
#             # Marc/André - this suggests we will need mutual auth 15118-2 if
#             # TLS1.3 is enabled.
#             ssl_context.load_verify_locations(
#                 cafile=os.path.join(get_PKI_PATH(), CertPath.OEM_ROOT_PEM))
#             ssl_context.verify_mode = VerifyMode.CERT_REQUIRED
#         else:
#             # In ISO 15118-2, we only verify the SECC's certificates
#             ssl_context.verify_mode = VerifyMode.CERT_NONE
#         ssl_context.set_ciphers(ciphersuites)
#     else:
#         # Load the V2G Root CA certificate(s) to validate the SECC's leaf and
#         # Sub-CA CPO certificates. The cafile string is the path to a file of
#         # concatenated (if several exist) V2G Root CA certificates in PEM format
#         ssl_context.load_verify_locations(
#             cafile=os.path.join(get_PKI_PATH(), CertPath.V2G_ROOT_PEM))
#         ssl_context.check_hostname = False
#         ssl_context.verify_mode = VerifyMode.CERT_REQUIRED
#         ssl_context.set_ciphers(ciphersuites)

#         if ENABLE_TLS_1_3:
#             try:
#                 ssl_context.load_cert_chain(
#                     certfile=os.path.join(get_PKI_PATH(), CertPath.OEM_CERT_CHAIN_PEM),
#                     keyfile=os.path.join(get_PKI_PATH(), KeyPath.OEM_LEAF_PEM),
#                     password=load_priv_key_pass(os.path.join(
#                         get_PKI_PATH(), KeyPasswordPath.OEM_LEAF_KEY_PASSWORD)),
#                 )
#             except SSLError:
#                 logger.exception(
#                     "SSLError, can't load OEM certificate chain for SSL "
#                     "context. Private key (keyfile) probably doesn't "
#                     "match certificate (certfile) or password for "
#                     "private is key invalid. Returning None instead."
#                 )
#                 return None
#             except FileNotFoundError:
#                 logger.exception("Can't find OEM certfile or keyfile for SSL context")
#                 return None
#             except Exception as exc:
#                 logger.exception(exc)
#                 return None

#     # The OpenSSL name for ECDH curve secp256r1 is prime256v1
#     ssl_context.set_ecdh_curve("prime256v1")

#     return ssl_context


# def load_priv_key_pass(
#     password_path: str,
# ) -> bytes:
#     """
#     Reads the password for the encrypted private key.

#     TODO This is obviously not a secure way of storing and reading a password
#          for a private key. Need to engage with security experts on how this
#          would be implemented in a secure production environment
#     Args:
#         password_path: The file path to the password TXT file

#     Returns:
#         The password as a str object

#     Raises:
#         FileNotFoundError, IOError
#     """
#     if password_path:
#         try:
#             with open(password_path, "r") as password_file:
#                 password = password_file.readline().rstrip().encode(encoding="utf-8")
#                 if password == b"":
#                     # TODO: Check if it is possible to have a private key with empty
#                     #  password. Not without a password - but a password like this: ""
#                     # Returning None to represent cases where there is no
#                     # passphrase set.
#                     return None
#                 else:
#                     return password

#         except (FileNotFoundError, IOError) as exc:
#             raise exc
#     else:
#         # This must be the same password as used for creating the private keys
#         # and certificates. See create_certs.sh or request the password from
#         # the providers of another test PKI (e.g. CharIN Testivals).
#         return "12345".encode(encoding="utf-8")


# def load_priv_key(
#     key_path: str, key_encoding: KeyEncoding, key_password_file_path: str
# ) -> EllipticCurvePrivateKey:
#     """
#     Loads a PEM or DER encoded private key given the provided key_path and
#     returns the key as an EllipticCurvePrivateKey object.

#     Args:
#         key_path: The file path to the DER encoded private key
#         key_encoding: The encoding format (KeyEncoding) of the private key
#                       (PEM or DER).
#         key_password_file_path: Path to the file where password is stored for the
#          private key. The file must exist even if there is no password to the private
#          key. The file maybe empty if there is no password.


#     Returns:
#         An EllipticCurvePrivateKey object corresponding to the private key read

#     Raises:
#         FileNotFoundError, IOError
#     """
#     try:
#         with open(key_path, "rb") as key_file:
#             try:
#                 if key_encoding == KeyEncoding.PEM:
#                     priv_key = load_pem_private_key(
#                         key_file.read(), load_priv_key_pass(key_password_file_path)
#                     )
#                 else:
#                     priv_key = load_der_private_key(
#                         key_file.read(), load_priv_key_pass(key_password_file_path)
#                     )
#                 if isinstance(priv_key, EllipticCurvePrivateKey):
#                     return priv_key

#                 # TODO Add support for other keys used in ISO 15118-20
#                 raise PrivateKeyReadError(
#                     f"Unknown key type at location {key_path}. "
#                     "Expected key of type EllipticCurvePrivateKey"
#                 )
#             except ValueError as exc:
#                 raise PrivateKeyReadError(
#                     "The PEM data could not be decrypted or its "
#                     "structure could not be decoded "
#                     "successfully."
#                 ) from exc
#             except TypeError as exc:
#                 raise PrivateKeyReadError(
#                     "Either password was given and private key "
#                     "was not encrypted or key was encrypted "
#                     "but no password was supplied."
#                 ) from exc
#             except UnsupportedAlgorithm as exc:
#                 raise PrivateKeyReadError(
#                     "Serialized key is of a type not supported "
#                     "by the crypto library."
#                 ) from exc
#     except (FileNotFoundError, IOError) as exc:
#         raise PrivateKeyReadError(f"Key file not found at location {key_path}") from exc


# def to_ec_pub_key(public_key_bytes: bytes) -> EllipticCurvePublicKey:
#     """
#     Takes a public key in bytes for the named elliptic curve secp256R1, as used
#     ISO 15118-2, and returns it as an instance of EllipticCurvePublicKey.

#     Args:
#         public_key_bytes: The elliptic curve public key, serialised as bytes.

#     Returns:
#         An instance of EllipticCurvePublicKey corresponding to the provided
#         bytes object.

#     Raises:
#         ValueError, TypeError
#     TODO Need to make more flexible for other elliptic curves used in
#          ISO 15118-20
#     """
#     try:
#         ec_pub_key = EllipticCurvePublicKey.from_encoded_point(
#             curve=SECP256R1(), data=public_key_bytes
#         )
#         return ec_pub_key
#     except ValueError as exc:
#         logging.exception(
#             "An invalid point is supplied, can't convert "
#             "bytes to EllipticCurvePublicKey instance"
#         )
#         raise exc
#     except TypeError as exc:
#         logging.exception(
#             "Curve provided is not an EllipticCurve, can't "
#             "convert byets to EllipticCurvePublicKey instance"
#         )
#         raise exc

# def to_ec_priv_key(private_key_bytes: bytes) -> EllipticCurvePrivateKey:
#     """
#     Takes a private key in bytes for the named elliptic curve secp256R1, as used
#     ISO 15118-2, and returns it as an instance of EllipticCurvePrivateKey.

#     Args:
#         private_key_bytes: The elliptic curve private key, serialised as bytes.

#     Returns:
#         An instance of EllipticCurvePrivateKey corresponding to the provided
#         bytes object.

#     Raises:
#         ValueError, TypeError
#     """

#     try:
#         priv_key_value = int.from_bytes(private_key_bytes, "big")
#         ec_priv_key = derive_private_key(priv_key_value, SECP256R1())
#         return ec_priv_key
#     except ValueError as exc:
#         logging.exception(
#             "An invalid point is supplied, can't convert "
#             "bytes to EllipticCurvePublicKey instance"
#         )
#         raise exc
#     except TypeError as exc:
#         logging.exception(
#             "Curve provided is not an EllipticCurve, can't "
#             "convert byets to EllipticCurvePublicKey instance"
#         )
#         raise exc



# def load_cert(cert_path: str) -> bytes:
#     """
#     Loads a DER encoded certificate given the provided cert_path and returns
#     the read bytes.

#     See https://docs.python.org/3/library/ssl.html#ssl-certificates for more
#     information on how certificates work.

#     Args:
#         cert_path: The file path to the DER encoded certificate

#     Returns:
#         The DER encoded certificate, given as a bytes object

#     Raises:
#         FileNotFoundError, IOError
#     """
#     with open(cert_path, "rb") as cert_file:
#         return cert_file.read()


# def load_cert_chain(
#     protocol: Protocol,
#     leaf_path: str,
#     sub_ca2_path: str,
#     sub_ca1_path: str = None,
#     id: str = None,
# ) -> Union[CertificateChainV2, CertificateChainV20, SignedCertificateChain]:
#     """
#     Reads the leaf and sub-CA certificate(s) from file and returns a
#     CertificateChain object corresponding to the protocol provided.

#     See https://docs.python.org/3/library/ssl.html#certificate-chains for more
#     information on how certificate chains work.

#     Args:
#         protocol: The ISO 15118 protocol version (-2 or -20)
#         leaf_path: Path to the leaf certificate (e.g. contract certificate,
#                    EVSE/SECC certificate, OEM provisioning certificate)
#         sub_ca2_path: Path to the Sub-CA 2 certificate, whose public key is
#                       used to verify the signature of the leaf certificate.
#         sub_ca1_path: Path to the optional Sub-CA 1 certificate, whose public
#                       key is used to verify the signature of the Sub-CA 1
#                       certificate, in case two Sub-CA certificates are used.
#                       If a Sub-CA 1 certificate is used, then this certificate
#                       has been issued by the root CA certificate. If not, then
#                       the Sub-CA 2 certificate has been issued by the root CA
#                       certificate.
#         id: The optional ID attribute, in case the certificate chain is part of
#             the header's signature, in which case this function returns a
#             SignedCertificateChain instead of a CertificateChain
#             (ISO 15118-20 only).

#     Returns:
#         A CertificateChain instance, either for ISO 15118-2 or -20.

#     Raises:
#         InvalidProtocolError
#     """
#     leaf_cert = load_cert(leaf_path)
#     sub_ca2_cert = load_cert(sub_ca2_path)
#     sub_ca1_cert = load_cert(sub_ca1_path) if sub_ca1_path else None

#     if protocol == Protocol.ISO_15118_2:
#         sub_ca_certs_v2: SubCertificatesV2 = SubCertificatesV2(
#             certificates=[sub_ca2_cert]
#         )
#         if sub_ca1_cert:
#             sub_ca_certs_v2.certificates.append(sub_ca1_cert)
#         return CertificateChainV2(
#             certificate=leaf_cert, sub_certificates=sub_ca_certs_v2
#         )

#     if protocol.ns.startswith(Namespace.ISO_V20_BASE):
#         sub_ca_certs_v20: SubCertificatesV20 = SubCertificatesV20(
#             certificates=[sub_ca2_cert]
#         )
#         if sub_ca1_cert:
#             sub_ca_certs_v20.certificates.append(sub_ca1_cert)

#         if id:
#             # In ISO 15118-20, there's a distinction between a CertificateChain
#             # and a SignedCertificateChain (which includes the id attribute).
#             return SignedCertificateChain(
#                 id=id, certificate=leaf_cert, sub_certificates=sub_ca_certs_v20
#             )

#         return CertificateChainV20(
#             certificate=leaf_cert, sub_certificates=sub_ca_certs_v20
#         )

#     raise InvalidProtocolError(f"'{protocol}' is not a valid Protocol enum")


# def log_certs_details(certs: List[bytes]):
#     for cert in certs:
#         der_cert = load_der_x509_certificate(cert)
#         logger.debug(f"Subject: {der_cert.subject}")
#         logger.debug(f"Issuer: {der_cert.issuer}")
#         logger.debug(f"Serial number: {der_cert.serial_number}")
#         logger.debug(
#             f"Validity: {der_cert.not_valid_before} - {der_cert.not_valid_after}"
#         )
#         logger.debug(
#             f"Fingerprint: {der_cert.fingerprint(der_cert.signature_hash_algorithm).hex(':')}"  # noqa
#         )
#         logger.debug("===")


# def verify_certs(
#     leaf_cert_bytes: bytes,
#     sub_ca_certs: List[bytes],
#     root_ca_cert: bytes,
#     private_environment: bool = False,
# ):
#     """
#     Verifies a certificate chain according to the following criteria:
#     1. Verify the signature of each certificate contained in the cert chain
#        (throws CertSignatureError if not)
#        1.a) Get the sub_ca_certs in order: leaf -> sub_ca_2 -> sub_ca_1 -> root
#             (if two sub-CAs are in use, otherwise: leaf -> sub_ca_2 -> root)
#        2.b) Do the actual signature verification from leaf to root
#     2. Check that the current date is within the time span provided by the
#        certificate's notBefore and notAfter attributes
#     3. Checks that none of the certificates has been revoked.

#     Args:
#         leaf_cert_bytes: The DER encoded leaf certificate
#         sub_ca_certs: One or more DER encoded sub-CA certificates, which are
#                       needed to verify the chain of signatures from the leaf
#                       certificate all the way to the root CA certificate.
#                       The order of the sub-CA certificates doesn't matter,
#                       verify_certs will try to work with either a sub-CA 1 or
#                       a sub-CA 2 certificate as first list entry, íf two sub-CA
#                       certificates are present.
#                       No more than two sub-CA certificates are allowed.
#         root_ca_cert: The root CA (certificate authority) certificate, which is used
#                       to verify the signature of the top-level sub-CA certificate
#         private_environment: Whether or not the certificate chain to check is
#                              that of a private environment (PE). In a PE, there
#                              are no sub-CA certificates.

#     Raises:
#         CertSignatureError, CertNotYetValidError, CertExpiredError,
#         CertRevokedError, CertAttributeError, CertChainLengthError, KeyTypeError
#     """
#     leaf_cert = load_der_x509_certificate(leaf_cert_bytes)
#     sub_ca2_cert = None
#     sub_ca1_cert = None
#     root_ca_cert = load_der_x509_certificate(root_ca_cert)

#     sub_ca_der_certs: List[Certificate] = [
#         load_der_x509_certificate(cert) for cert in sub_ca_certs
#     ]

#     # Step 1.a: Categorize the sub-CA certificates into sub-CA 1 and sub-CA 2.
#     #           A sub-CA 2 certificate's profile has its PathLength extension
#     #           attribute set to 0, whereas a sub-CA 1 certificate's profile has
#     #           its PathLength extension attribute set to 0.
#     #           Only a sub-CA 2 can issue a leaf certificate. If a sub-CA 1 is
#     #           used, then it issues the certificate for a sub-CA 2 and has its
#     #           certificate issued by the root CA. If no sub-CA 1 is used, then
#     #           the root CA issues the sub-CA 2's certificate directly.
#     # TODO We also need to check each certificate's attributes for
#     #      compliance with the corresponding certificate profile
#     for cert in sub_ca_der_certs:
#         path_len = cert.extensions.get_extension_for_oid(
#             ExtensionOID.BASIC_CONSTRAINTS
#         ).value.path_length
#         if path_len == 0:
#             if sub_ca2_cert:
#                 logger.error(
#                     f"Sub-CA cert {sub_ca2_cert.subject.__str__()} "
#                     "already has PathLength attribute set to 0. "
#                     "A certificate chain must not contain two "
#                     "certificates with the same path length"
#                 )
#                 raise CertAttributeError(
#                     subject=cert.subject.__str__(), attr="PathLength", invalid_value="0"
#                 )
#             sub_ca2_cert = cert
#         elif path_len == 1:
#             if sub_ca1_cert:
#                 logger.error(
#                     f"Sub-CA cert {sub_ca1_cert.subject.__str__()} "
#                     f"already has PathLength attribute set to 1. "
#                     "A certificate chain must not contain two "
#                     "certificates with the same path length"
#                 )
#                 raise CertAttributeError(
#                     subject=cert.subject.__str__(), attr="PathLength", invalid_value="1"
#                 )
#             sub_ca1_cert = cert
#         else:
#             raise CertChainLengthError(allowed_num_sub_cas=2, num_sub_cas=path_len)

#     if not sub_ca2_cert and not private_environment:
#         raise CertChainLengthError(allowed_num_sub_cas=2, num_sub_cas=0)

#     if (sub_ca2_cert or sub_ca1_cert) and private_environment:
#         raise CertChainLengthError(allowed_num_sub_cas=0, num_sub_cas=1)

#     # Step 1.b: Now that we have established the right order of sub-CA
#     #           certificates we can start verifying the signatures from leaf
#     #           certificate to root CA certificate
#     cert_to_check = leaf_cert
#     try:
#         if private_environment:
#             if isinstance(pub_key := root_ca_cert.public_key(), EllipticCurvePublicKey):
#                 pub_key.verify(
#                     leaf_cert.signature,
#                     leaf_cert.tbs_certificate_bytes,
#                     ec.ECDSA(SHA256()),
#                 )
#             else:
#                 # TODO Add support for ISO 15118-20 public key types
#                 raise KeyTypeError(
#                     f"Unexpected public key type " f"{type(root_ca_cert.public_key())}"
#                 )
#         elif not sub_ca2_cert:
#             logger.error("Sub-CA 2 certificate missing in public cert chain")
#             raise CertChainLengthError(allowed_num_sub_cas=2, num_sub_cas=0)
#         else:
#             if isinstance(pub_key := sub_ca2_cert.public_key(), EllipticCurvePublicKey):
#                 pub_key.verify(
#                     leaf_cert.signature,
#                     leaf_cert.tbs_certificate_bytes,
#                     # TODO Find a way to read id dynamically from the certificate
#                     ec.ECDSA(SHA256()),
#                 )
#             else:
#                 # TODO Add support for ISO 15118-20 public key types
#                 raise KeyTypeError(
#                     f"Unexpected public key type " f"{type(sub_ca2_cert.public_key())}"
#                 )

#             if sub_ca1_cert:
#                 cert_to_check = sub_ca2_cert

#                 if isinstance(
#                     pub_key := sub_ca1_cert.public_key(), EllipticCurvePublicKey
#                 ):
#                     pub_key.verify(
#                         sub_ca2_cert.signature,
#                         sub_ca2_cert.tbs_certificate_bytes,
#                         ec.ECDSA(SHA256()),
#                     )
#                 else:
#                     # TODO Add support for ISO 15118-20 public key types
#                     raise KeyTypeError(
#                         f"Unexpected public key type "
#                         f"{type(sub_ca1_cert.public_key())}"
#                     )

#                 cert_to_check = sub_ca1_cert

#                 if isinstance(
#                     pub_key := root_ca_cert.public_key(), EllipticCurvePublicKey
#                 ):
#                     pub_key.verify(
#                         sub_ca1_cert.signature,
#                         sub_ca1_cert.tbs_certificate_bytes,
#                         ec.ECDSA(SHA256()),
#                     )
#                 else:
#                     # TODO Add support for ISO 15118-20 public key types
#                     raise KeyTypeError(
#                         f"Unexpected public key type "
#                         f"{type(root_ca_cert.public_key())}"
#                     )
#             else:
#                 cert_to_check = sub_ca2_cert

#                 if isinstance(
#                     pub_key := root_ca_cert.public_key(), EllipticCurvePublicKey
#                 ):
#                     pub_key.verify(
#                         sub_ca2_cert.signature,
#                         sub_ca2_cert.tbs_certificate_bytes,
#                         ec.ECDSA(SHA256()),
#                     )
#                 else:
#                     # TODO Add support for ISO 15118-20 public key types
#                     raise KeyTypeError(
#                         f"Unexpected public key type "
#                         f"{type(root_ca_cert.public_key())}"
#                     )
#     except InvalidSignature as exc:
#         raise CertSignatureError(
#             subject=cert_to_check.subject.__str__(),
#             issuer=cert_to_check.issuer.__str__(),
#         ) from exc
#     except UnsupportedAlgorithm as exc:
#         cert_hash_algorithm: HashAlgorithm = cert_to_check.signature_hash_algorithm
#         raise CertSignatureError(
#             subject=cert_to_check.subject.__str__(),
#             issuer=cert_to_check.issuer.__str__(),
#             extra_info=f"UnsupportedAlgorithm for certificate "
#             f"{cert_to_check.subject.__str__()}. "
#             f"\nSignature hash algorithm: "
#             f"{cert_hash_algorithm.name if cert_hash_algorithm else 'None'}"
#             f"\nSignature algorithm: "
#             f"{cert_to_check.signature_algorithm_oid}"
#             # TODO This OpenSSL version may not be the complied one
#             #      that is actually used, need to check
#             f"\nOpenSSL version: {Backend().openssl_version_text()}",
#         ) from exc
#     except Exception as exc:
#         logger.exception(
#             f"{exc.__class__.__name__} while verifying signature"
#             f"of certificate {cert_to_check.subject}"
#         )

#     # Step 2: Check that each certificate is valid, i.e. the current time is
#     #         between the notBefore and notAfter timestamps of the certificate
#     try:
#         certs_to_check: List[Certificate] = [leaf_cert]
#         if sub_ca2_cert:
#             certs_to_check.append(sub_ca2_cert)
#         if sub_ca1_cert:
#             certs_to_check.append(sub_ca1_cert)
#         certs_to_check.append(root_ca_cert)
#         check_validity(certs_to_check)
#     except (CertNotYetValidError, CertExpiredError) as exc:
#         raise exc

#     # Step 3: Check the OCSP (Online Certificate Status Protocol) response to
#     #         see whether or not a certificate has been revoked
#     # TODO As OCSP is not supported for the CharIN Testival Europe 2021, we'll
#     #      postpone that step a bit


# def check_validity(certs: List[Certificate]):
#     """
#     Checks that the current time is between the notBefore and notAfter
#     timestamps of each certificate provided in the list.

#     Args:
#         certs: A list of DER encoded certificates, given as Certificate
#                instances (from the cryptography library)

#     Raises:
#         CertNotYetValidError, CertExpiredError
#     """
#     now = datetime.utcnow()
#     for cert in certs:
#         if cert.not_valid_before > now:
#             raise CertNotYetValidError(cert.subject.__str__())
#         if cert.not_valid_after < now:
#             raise CertExpiredError(cert.subject.__str__())


# def get_cert_cn(der_cert: bytes) -> str:
#     """
#     Retrieves the 'CN' (Common Name) attribute of the 'Subject' attribute of a
#     DER encoded certificate and returns it as a string.

#     Args:
#         der_cert: A DER encoded certificate

#     Returns:
#         The Common Name attribute of the DER encoded certificate
#     """
#     cert = load_der_x509_certificate(der_cert)
#     cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME).pop()
#     return cn.value


# def get_cert_issuer_serial(cert_path: str) -> Tuple[str, int]:
#     """
#     Retrieves the issuer attribute and serial number (both together uniquely
#     identify a certificate) of an X.509 certificate

#     Args:
#         cert_path: The path to the DER encoded certificate

#     Returns:
#         A tuple with the first tuple entry being the issuer name and the
#         second tuple entry being the issuer's serial number for that certificate
#     """
#     cert = load_cert(cert_path)
#     der_cert = load_der_x509_certificate(cert)
#     return der_cert.issuer.__str__(), der_cert.serial_number


# def create_signature(
#     elements_to_sign: List[Tuple[str, bytes]], signature_key: EllipticCurvePrivateKey
# ) -> Signature:
#     """
#     Creates a Signature element that is placed in the header of a V2GMessage.
#     This process is divided into two steps:
#     1. Create the Reference element(s) that go into the SignedInfo element.
#     2. Compute the SignatureValue based on EXI encoding the SignedInfo element
#        and then applying ECDSA (Elliptic Curve Digital Signature Algorithm) to
#        it, encrypting with the private key provided.

#     (Check Annex J, section J.2 in ISO 15118-2, for a reference of how to
#     generate a signature)

#     Args:
#         elements_to_sign: A list of tuples [str, bytes], where the first entry
#                           of each tuple is the Id field (XML attribute) and the
#                           second entry is the EXI encoded bytes representation
#                           of the element for which a Reference element in the
#                           SignedInfo element of the V2GMessage header needs to
#                           be created, as part of creating a digital signature.
#         signature_key: The private key used to encrypt the EXI encoded and
#                        hashed SignedInfo element (using ECDSA), which represents
#                        in the end the SignatureValue of the Signature element of
#                        the V2GMessage header.

#     Returns:
#         A Signature instance, containing the SignedInfo and SignatureValue
#         elements that need to be placed in the header of a V2GMessage

#     TODO We need to determine between ISO 15118-2 and -20 signatures. Probably
#          need a 'protocol' parameter
#     """
#     # 1. Step: Reference generation
#     reference_list: List[Reference] = []

#     for id_attr, exi_encoded in elements_to_sign:
#         reference = Reference(
#             uri="#" + id_attr,
#             transforms=Transforms(
#                 transform=[Transform(algorithm="http://www.w3.org/TR/canonical-exi/")]
#             ),
#             digest_method=DigestMethod(
#                 algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
#             ),
#             digest_value=create_digest(exi_encoded),
#         )

#         reference_list.append(reference)

#     signed_info = SignedInfo(
#         canonicalization_method=CanonicalizationMethod(
#             algorithm="http://www.w3.org/TR/canonical-exi/"
#         ),
#         signature_method=SignatureMethod(
#             algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
#         ),
#         reference=reference_list,
#     )

#     # 2. Step: Signature generation
#     exi_encoded_signed_info = EXI().to_exi(signed_info, Namespace.XML_DSIG)
#     der_encoded_signature_value = signature_key.sign(
#         data=exi_encoded_signed_info, signature_algorithm=ec.ECDSA(SHA256())
#     )
#     # The sign method from the cryptography library automatically DER encodes
#     # the signature. However, in ISO 15118 DER encoding of the signature
#     # is not expected. Thus, in the next lines we extract the r and s points
#     # from the DER encoding, which correspond to the coordinates of the signature
#     # value on the Elliptic Curve.
#     # Each of these coordinates have a 32 byte length number.
#     # The `decode_dss_signature` returns the r and s points as integer
#     # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature  # noqa
#     (ec_r, ec_s) = decode_dss_signature(der_encoded_signature_value)
#     # As the signature value is sent as a full 64 bytes raw value, we need
#     # to convert each point to bytes in big endian format and concatenate both
#     raw_signature_value = bytearray(ec_r.to_bytes(32, "big") + ec_s.to_bytes(32, "big"))
#     signature = Signature(
#         signed_info=signed_info,
#         signature_value=SignatureValue(value=raw_signature_value),
#     )

#     return signature


# def verify_signature(
#     signature: Signature,
#     elements_to_sign: List[Tuple[str, bytes]],
#     leaf_cert: bytes,
#     sub_ca_certs: List[bytes] = None,
#     root_ca_cert: bytes = None,
# ) -> bool:
#     """
#     Verifies the signature contained in the Signature element of the V2GMessage
#     header. The following steps are required:

#     1. Iterate over all element IDs of the message which should have been signed
#        and find the respective Reference element in the SignedInfo element of
#        the message header. Calculate the message digest for each element and
#        compare with the received message digest in the SignedInfo's Reference
#        element. If the received and the calculated digests are equal, we can
#        continue with step 2.
#     2. Verify the signature by decrypting the signature value (using the public
#        key stored in the verify_cert parameter) and comparing its value with
#        the EXI encoded and hashed SignedInfo element. If the values match, then
#        the signature is verified with the public key certificate.
#     3. The final step is to verify that all signatures in the chain of
#        certificates from leaf to root are valid. In the case of the
#        AuthorizationReq message, for example, we can skip this step if the
#        contract certificate chain from leaf to root was already checked when
#        receiving the PaymentDetailsReq message (which contains the contract
#        certificate and sub-CA certificate(s)).

#     Args:
#         signature: The Signature instance containing the Reference elements and
#                    the SignatureValue needed to verify the signature.
#         elements_to_sign: A list of tuples [int, bytes], where the first entry
#                           of each tuple is the Id field (XML attribute) and the
#                           second entry is the EXI encoded bytes representation
#                           of the element for which a Reference element in the
#                           SignedInfo element of the V2GMessage header exists.
#         leaf_cert: The certificate whose public key is used to verify the
#                           signature, i.e. to decrypt the encrypted SignatureValue
#                           element and check the result with the EXI encoded and
#                           hashed SignedInfo element.
#         sub_ca_certs: The sub-CA certificate(s) belonging to the verify_leaf_cert
#                       If provided, then the root_cert_path must also be provided.
#         root_ca_cert: Root CA certificate used to verify the signature of (one of)
#                            the sub-CA certificate(s). If provided, then the
#                            sub_ca_certs must also be provided.

#     Returns:
#         True, if the signature can be successfully verified, False otherwise.
#     """
#     # 1. Step: Digest value check for each reference element
#     for id_attr, exi_encoded in elements_to_sign:
#         logger.debug(f"Verifying digest for element with ID '{id_attr}'")
#         calculated_digest = create_digest(exi_encoded)
#         message_digests_equal = False

#         for reference in signature.signed_info.reference:
#             if not reference.uri:
#                 logger.error("Reference without URI element")
#                 continue

#             if reference.uri == "#" + id_attr:
#                 if calculated_digest == reference.digest_value:
#                     message_digests_equal = True

#                 logger.debug(
#                     f"\nReceived digest of reference with ID {id_attr}: "
#                     f"{reference.digest_value.hex().upper()}"
#                     f"\nCalculated digest for reference: "
#                     f"{calculated_digest.hex().upper()}"
#                     f"\n=> Match: {message_digests_equal}"
#                 )

#         if not message_digests_equal:
#             logger.error(f"Digest mismatch for element with ID '{id_attr}'")
#             return False

#     # 2. Step: Checking signature value
#     logger.debug("Verifying signature value for SignedInfo element")
#     pub_key = load_der_x509_certificate(leaf_cert).public_key()

#     # The signature value element corresponds to the encryption of the EXI encoded
#     # and then hashed signed_info element.
#     # Signed Info -> EXI encoding -> Hashing -> Encryption with private key => Signature Value # noqa: E501
#     # ATTENTION: The hashing and encryption operation is part of the
#     # ECDSA (Elliptic Curve Digital Signature Algorithm) operation.
#     # That is why we do NOT additionally hash the EXI encoded signed info element
#     # before we inject it to the `data` field of the `verify` method.
#     exi_encoded_signed_info = EXI().to_exi(signature.signed_info, Namespace.XML_DSIG)

#     # The verify method from cryptography expects the signature to be in DER encoded
#     # format. Please check: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey.verify  # noqa: E501
#     # However, in ISO 15118 the signature value is exchanged in raw format.
#     # In order to convert the signature value to DER format, it is possible to use the
#     # encode_dss_signature from cryptography, but we need to provide the
#     # r and s values of the signature as ints.
#     # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/utils/#cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature  # noqa: E501
#     # The `r` and `s` values are both 32 bytes values that correspond to the
#     # coordinates in the Elliptic curve from where the public and private key
#     # are extracted

#     ec_r = int.from_bytes(signature.signature_value.value[:32], "big")
#     ec_s = int.from_bytes(signature.signature_value.value[32:], "big")
#     der_encoded_signature = encode_dss_signature(r=ec_r, s=ec_s)

#     try:
#         if isinstance(pub_key, EllipticCurvePublicKey):
#             pub_key.verify(
#                 signature=der_encoded_signature,
#                 data=exi_encoded_signed_info,
#                 signature_algorithm=ec.ECDSA(SHA256()),
#             )
#         else:
#             # TODO Add support for ISO 15118-20 public key types
#             raise KeyTypeError(f"Unexpected public key type " f"{type(pub_key)}")
#     except InvalidSignature as e:
#         pub_key_bytes = pub_key.public_bytes(
#             encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
#         )
#         logger.error(
#             f"Signature verification failed for signature value "
#             f"\n{signature.signature_value.value.hex().upper()} \n"
#             f"Pub Key from Leaf Certificate: {pub_key_bytes.hex().upper()}"
#             f"\n Error: {e} "
#         )
#         return False

#     # 3. Step: Verify signatures along the certificate chain, if provided
#     if sub_ca_certs and root_ca_cert:
#         try:
#             verify_certs(leaf_cert, sub_ca_certs, root_ca_cert)
#         except (
#             CertSignatureError,
#             CertNotYetValidError,
#             CertExpiredError,
#             CertRevokedError,
#             CertAttributeError,
#             CertChainLengthError,
#         ) as exc:
#             logger.error(
#                 f"{exc.__class__.__name__}: Signature verification "
#                 f"failed while checking certificate chain"
#             )
#             return False
#     else:
#         logger.warning(
#             "Sub-CA and root CA certificates were not used to "
#             "verify signatures along the certificate chain"
#         )

#     logger.debug("Signature verified successfully")
#     return True


# def create_digest(exi_encoded_element) -> bytes:
#     digest = Hash(SHA256())
#     digest.update(exi_encoded_element)
#     return digest.finalize()


# def encrypt_priv_key(
#     oem_prov_cert: bytes, priv_key_to_encrypt: EllipticCurvePrivateKey
# ) -> Tuple[bytes, bytes]:
#     """
#     Encrypts the provided private key priv_key_to_encrypt by following these
#     steps:

#     1. Generate the shared secret with ECDH (Elliptic Curve Diffie-Hellman),
#        using the public key from oem_prov_cert (which, in the ISO 15118
#        world, is the public key of the OEM provisioning certificate) and the
#        private key from a freshly generated (i.e. ephemeral) ECDH (aka ECDHE)
#        private-public key pair. We use the named elliptic curve 'SECP256R1' as
#        specified in ISO 15118 to do ECDHE. 'Ephemeral' means that the key pair
#        is generated each time anew and not reused, which facilitates perfect
#        forward secrecy, a security paradigm to always strive for.

#        In the realm of ISO 15118, the mobility operator (MO) would generate that
#        key pair and encrypt the private key associated with the contract
#        certificate so it can then be sent to the EV and installed with the
#        CertificateInstallationRes message. This function allows to 'mock' this
#        functionality directly on the charging station, for testing purposes.

#        Diffie-Hellman key exchange (DH) is a method that allows two parties to
#        jointly agree on a shared secret using an insecure channel. For security
#        and performance reasons it's better to use ECDH (Elliptic Curve-based DH)
#        instead of DH, which is also what ISO 15118 demands.
#     2. Generate the symmetric key used to encrypt the priv_key_to_encrypt with
#        the symmetric cipher AES (Advanced Encryption Standard), using 128 bit
#        keys and the cipher mode CBC (Cipher Block Chaining), aka AES-128-CBC.
#        We do so by applying the key derivation function (KDF) named ConcatKDF
#        (as specified in ISO 15118-2) to the shared secret created in step 1.

#        A KDF allows mixing of additional information into the key, derivation of
#        multiple keys, and destroys any structure that may be present to
#        increase the security of the symmetric key.
#     3. Encrypt the priv_key_to_encrypt using the symmetric key created in step 2
#        and the AES-128-CBC cipher with an initialisation vector of 16 random
#        bytes.

#        The resulting encrypted private key consists of the initialisation vector
#        as the 16 MSB (most significant bytes) plus the encrypted key from
#        AES-128-CBC.
#        # TODO Be flexible with other ciphers (needed for implementing
#        #      ISO 15118-20)

#     Args:
#         priv_key_to_encrypt: The private key to encrypt. In the ISO 15118 realm,
#                              that's the private key associated with the contract
#                              certificate.
#         oem_prov_cert: The certificate whose public key is used to create
#                            the shared common secret. In the ISO 15118 realm,
#                            that's the OEM provisioning (or leaf) certificate.

#     Returns:
#         A tuple containing the ephemeral Elliptic Curve Diffie-Hellman (ECDHE)
#         public key (aka DHPublicKey) and the encrypted private key, both given
#         as bytes.

#         The EVCC needs the DHPublicKey to derive the same shared secret and then
#         the symmetric key, to decrypt the encrypted private key.
#     """
#     # 1. Step: Generate shared secret
#     # 1.1: Generate the private key ECDHE key using the named elliptic curve
#     #      secp256r1 (aka prime256v1 in OpenSSL)
#     ephemeral_ecdh_priv_key = ec.generate_private_key(ec.SECP256R1())
#     # 1.2: Derive the public key from the private key (needed for the
#     #      counterpart to generate the same shared secret and decrypt the key).
#     #      We need the uncompressed public key starting with 0x04 (as the
#     #      indicator for the uncompressed format), followed by the x and y
#     #      coordinates of the public key on the elliptic curve, each 32 bytes
#     #      long. As a result, the ECDHE public key is 65 bytes long.

#     # Formerly, the public key in bytes would be obtained as:
#     # public_key().public_numbers().encode_point()
#     # but this is deprecated in recent versions of Cryptography, so instead
#     # public_bytes is used
#     # ephemeral_ecdh_pub_key = (
#     #    ephemeral_ecdh_priv_key.public_key().public_numbers().encode_point()
#     # )  # noqa
#     ephemeral_ecdh_pub_key = ephemeral_ecdh_priv_key.public_key().public_bytes(
#         encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
#     )
#     # 1.3: Generate shared secret using the new ECDH private key and the public
#     #      key of the counterpart (OEM provisioning certificate's public key)
#     oem_prov_cert_pub_key = load_der_x509_certificate(oem_prov_cert).public_key()
#     shared_secret: Optional[bytes] = None
#     if isinstance(oem_prov_cert_pub_key, EllipticCurvePublicKey):
#         shared_secret = ephemeral_ecdh_priv_key.exchange(
#             ec.ECDH(), oem_prov_cert_pub_key
#         )

#     if shared_secret:
#         # 2. Step: Generate symmetric key using a key derivation function (KDF)
#         # See [V2G2-818] of ISO 15118-2 for more info about the KDF
#         algorithm_id = 0x01
#         sender_party_u = 0x55
#         receiver_party_v = 0x56
#         symmetric_key_length_in_bytes = 16
#         other_info = bytes(
#             algorithm_id.to_bytes(1, "big")
#             + sender_party_u.to_bytes(1, "big")
#             + receiver_party_v.to_bytes(1, "big")
#         )

#         concat_kdf = ConcatKDFHash(
#             algorithm=SHA256(),
#             length=symmetric_key_length_in_bytes,
#             otherinfo=other_info,
#         )

#         symmetric_key = concat_kdf.derive(shared_secret)

#         # 3. Step: Encrypt the private key
#         # See https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/?highlight=AES#cryptography.hazmat.primitives.ciphers.Cipher  # noqa
#         init_vector = get_random_bytes(16)
#         cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(init_vector))

#         try:
#             priv_key_value = priv_key_to_encrypt.private_numbers().private_value
#             priv_key_value_bytes = priv_key_value.to_bytes(32, "big")
#             encryptor = cipher.encryptor()
#             encrypted_priv_key = (
#                 encryptor.update(priv_key_value_bytes) + encryptor.finalize()
#             )
#         except Exception as exc:
#             logger.exception(exc)
#             raise EncryptionError from exc

#         # The initialization vector (init_vector, used in the CBC mode of AES)
#         # must be transmitted in the 16 most significant bytes of the
#         # encrypted private key
#         encrypted_priv_key_with_iv = init_vector + encrypted_priv_key

#         return ephemeral_ecdh_pub_key, encrypted_priv_key_with_iv

#     logger.error("Shared secret could not be generated")
#     raise EncryptionError()


# def decrypt_priv_key(
#     encrypted_priv_key_with_iv: bytes,
#     ecdh_priv_key: EllipticCurvePrivateKey,
#     ecdh_pub_key: EllipticCurvePublicKey,
# ) -> bytes:
#     """
#     Decrypts the private key associated with the contract certificate.

#     Args:
#         encrypted_priv_key_with_iv: The encrypted private key, which is
#                                     associated with the contract certificate.
#                                     The first 16 bytes represents the
#                                     initialisation vector (IV) used for the
#                                     symmetric cipher AES-128, which have been
#                                     prepended to the encrypted key.
#         ecdh_priv_key: The (static) private key used on the EVCC side for the
#                        ECDH procedure. This is the private key associated with
#                        the OEM provisioning certificate stored in the EVCC.
#         ecdh_pub_key: The public key coming from the mobility operator (MO),
#                       which is used for the ECDH procedure. This is an
#                       ephemeral public key the MO created.

#     Returns:
#         The decrypted private key (associated with the contract certificate),
#         given in bytes.
#     """
#     init_vector = encrypted_priv_key_with_iv[:16]
#     encrypted_priv_key = encrypted_priv_key_with_iv[16:]

#     # Create the symmetric key
#     # TODO Need to create a separate function for this to follow DRY principle
#     shared_secret = ecdh_priv_key.exchange(ec.ECDH(), ecdh_pub_key)

#     if shared_secret:
#         # 2. Step: Generate symmetric key using a key derivation function (KDF)
#         # See [V2G2-818] of ISO 15118-2 for more info about the KDF
#         algorithm_id = 0x01
#         sender_party_u = 0x55
#         receiver_party_v = 0x56
#         symmetric_key_length_in_bytes = 16
#         other_info = bytes(
#             algorithm_id.to_bytes(1, "big")
#             + sender_party_u.to_bytes(1, "big")
#             + receiver_party_v.to_bytes(1, "big")
#         )

#         concat_kdf = ConcatKDFHash(
#             algorithm=SHA256(),
#             length=symmetric_key_length_in_bytes,
#             otherinfo=other_info,
#         )

#         symmetric_key = concat_kdf.derive(shared_secret)

#         cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(init_vector))
#         decryptor = cipher.decryptor()
#         decrypted_priv_key = decryptor.update(encrypted_priv_key) + decryptor.finalize()

#         return decrypted_priv_key

#     logger.error("Shared secret could not be generated")
#     raise DecryptionError()


# def derive_certificate_hash_data(
#     certificate: bytes, issuer_certificate: bytes
# ) -> Dict[str, str]:
#     """Extract certificate hash data to be used in an OCPP AuthorizeRequest.

#     Args:
#         certificate: A certificate in binary (DER) form.
#         issuer_certificate: The certificate used for signing `certificate`,
#             in binary (DER) form.
#             For a self-signed certificate, these will be the same.

#     Returns:
#         A dictionary with all information required for an OCSPRequestDataType
#         (2.36. OCSPRequestDataType, p. 382, OCPP 2.0.1 Part 2)

#     Raises:
#         CertAttributeError: if a certificate is provided with a hash algorithm
#             that OCPP doesn't accept.
#             Only SHA256, SHA384, and SHA512 are allowed.
#             (3.42 HashAlgorithmEnumType, p. 403, OCPP 2.0.1 Part 2)
#     """
#     certificate: Certificate = load_der_x509_certificate(certificate)
#     issuer_certificate = load_der_x509_certificate(issuer_certificate)
#     builder = OCSPRequestBuilder().add_certificate(
#         certificate, issuer_certificate, certificate.signature_hash_algorithm
#     )

#     ocsp_request = builder.build()

#     # For the hash algorithm, convert to the naming used in OCPP.
#     # Only SHA256, SHA384, and SHA512 are allowed in OCPP 2.0.1.
#     hash_algorithm_for_ocpp = certificate.signature_hash_algorithm.name.upper()
#     if hash_algorithm_for_ocpp not in {"SHA256", "SHA384", "SHA512"}:
#         raise CertAttributeError(
#             subject=certificate.subject.__str__(),
#             attr="HashAlgorithm",
#             invalid_value=hash_algorithm_for_ocpp,
#         )

#     try:
#         responder_url = get_ocsp_url_for_certificate(certificate)
#     except (ExtensionNotFound, OCSPServerNotFoundError) as e:
#         raise e

#     # Some further details on distinguished names,
#     # per https://www.ibm.com/docs/en/i/7.2?topic=concepts-distinguished-name :
#     # Distinguished name (DN) is a term that describes the identifying information
#     # in a certificate and is part of the certificate itself.
#     # A certificate contains DN information for both the owner or requestor
#     # of the certificate (called the Subject DN) and the CA that issues the certificate
#     # (called the Issuer DN). Depending on the identification policy of the CA
#     # that issues a certificate, the DN can include a variety of information.
#     #
#     # Each CA has a policy to determine what identifying information the CA requires
#     # to issue a certificate. Some public Internet Certificate Authorities may require
#     # little information, such as a name and e-mail address.
#     # Other public CAs may require more information and require stricter proof of that
#     # identifying information before issuing a certificate.
#     #
#     # https://www.ibm.com/docs/en/ibm-mq/7.5?topic=certificates-distinguished-names
#     # provides more information about the attributes which may be included in a DN.
#     #
#     # In this case, a certificate will have a name like:
#     # 'DC=MO,C=DE,O=Keysight Technologies,CN=PKI-1_CRT_MO_SUB2_VALID'
#     # It will be hashed by the OCSP request builder.

#     return {
#         "hash_algorithm": hash_algorithm_for_ocpp,
#         "issuer_name_hash": urlsafe_b64encode(ocsp_request.issuer_name_hash).decode(),
#         "issuer_key_hash": urlsafe_b64encode(ocsp_request.issuer_key_hash).decode(),
#         "serial_number": str(ocsp_request.serial_number),
#         "responder_url": responder_url,
#     }


# def certificate_to_pem_string(certificate: bytes) -> str:
#     """Convert a certificate from a DER bytestring to a PEM string.

#     This conversion is done because OCPP requires that the certificate chain
#     be PEM-encoded.

#     Args:
#         certificate: The certificate in binary (DER) form.

#     Returns:
#         The same certificate expressed as a PEM-format string.
#     """
#     return DER_cert_to_PEM_cert(certificate)


# def get_ocsp_url_for_certificate(certificate: Certificate) -> str:
#     """Get the OCSP URL for a certificate.

#     Args:
#         certificate: A certificate object.

#     Returns:
#         The URL for a server to verify the certificate.

#     Raises:
#         ExtensionNotFound: if Authority Information Access extension is absent
#         OCSPServerNotFoundError: if OCSP server entry is not found
#     """
#     try:
#         auth_inf_access = certificate.extensions.get_extension_for_oid(
#             ExtensionOID.AUTHORITY_INFORMATION_ACCESS
#         ).value
#     except ExtensionNotFound:
#         logger.warning(
#             f"Authority Information Access extension not "
#             f"found for {certificate.subject.__str__()}."
#         )
#         raise

#     ocsps = [
#         access_descriptor
#         for access_descriptor in auth_inf_access
#         # If this is OCSP, the access location will be where to obtain
#         # OCSP information for the certificate.
#         if access_descriptor.access_method == AuthorityInformationAccessOID.OCSP
#     ]

#     if not ocsps:
#         raise OCSPServerNotFoundError

#     return ocsps[0].access_location.value


# def all_certificates_from_chain(
#     certificate_chain: CertificateChainV2, root_cert: Optional[bytes]
# ) -> List[bytes]:
#     """Return all certificates from a certificate chain as a list.

#     The order should be: leaf certificate, sub-CA 2, sub-CA 1, root,
#     if all are present.

#     Args:
#         certificate_chain: The certificate chain object.
#             Contains contract and sub-CA certificates.
#         root_cert: The certificate used to sign the top sub-CA certificate.

#     Returns:
#         A list of certificates, in order.
#     """
#     chain = [
#         certificate_chain.certificate
#     ] + certificate_chain.sub_certificates.certificates
#     if root_cert is not None:
#         chain.append(root_cert)
#     return chain


# def get_certificate_hash_data(
#     certificate_chain: Optional[CertificateChainV2],
#     root_cert: Optional[bytes],
# ) -> Optional[List[Dict[str, str]]]:
#     """Return a list of hash data for a contract certificate chain.

#     Args:
#         certificate_chain: The certificate chain object.
#             Contains contract and sub-CA certificates.
#         root_cert: The certificate used to sign the top sub-CA certificate.

#     Returns:
#         A list of hash data objects for each certificate, or None if either
#         the chain or root certificate is not present.

#         Without the root certificate, or any other one within the chain, the
#         chain cannot be verified.
#     """
#     # If we do not have all certificates, we cannot create all the hash data.
#     # This is because the hash data requires the public key of a certificate's
#     # issuer.  Thus, lacking the root certificate makes it impossible to construct
#     # the hash data.
#     #
#     # In this case, we will ultimately send the certificates we do have -- the
#     # CSMS may be able to obtain the corresponding root certificate from a
#     # root certificate pool.
#     if certificate_chain is None or root_cert is None:
#         return None

#     all_certificates = all_certificates_from_chain(certificate_chain, root_cert)
#     # The `all_certificates` list will have the following line-up
#     # [leaf, subca2, subca1, root]
#     # Thus, each certificate is followed by its issuer, except for the root,
#     # which is self-signed.
#     hash_data: List[Dict[str, str]] = []
#     try:
#         for idx, certificate in enumerate(all_certificates):
#             if idx < len(all_certificates) - 1:
#                 hash_data.append(
#                     derive_certificate_hash_data(certificate, all_certificates[idx + 1])
#                 )
#             else:
#                 # the last entry of the list contains the root_cert, which
#                 # is a self-signed certificate
#                 hash_data.append(derive_certificate_hash_data(root_cert, root_cert))
#     except (ExtensionNotFound, OCSPServerNotFoundError):
#         # if we cant extract the OCSP from one of the certificates,
#         # then there is no point of building the hash data
#         return None
#     return hash_data


# def build_pem_certificate_chain(
#     certificate_chain: Optional[CertificateChainV2], root_cert: Optional[bytes]
# ) -> Optional[str]:
#     """Return a string of certificates in PEM form concatenated together."""
#     if certificate_chain is None:
#         return None

#     # If we do not have the root certificate, we can still include all the
#     # certificates we do have.

#     return "".join(
#         [
#             certificate_to_pem_string(certificate)
#             for certificate in all_certificates_from_chain(
#                 certificate_chain,
#                 root_cert,
#             )
#         ]
#     )


# class CertPath(str, Enum):
#     """
#     Provides the path to certificates used for Plug & Charge. The encoding
#     format is indicated by the latter part of the enum name (_DER or _PEM)

#     TODO: Make filepath flexible, so we can choose between -2 and -20 certificates

#     NOTE: For a productive environment, the access to certificate should be
#           managed in a secure way (e.g. through a hardware security module).
#     """

#     # Mobility operator (MO)
#     CONTRACT_LEAF_DER = "client/mo/MO_LEAF.der"
#     MO_SUB_CA2_DER = "ca/mo/MO_SUB_CA2.der"
#     MO_SUB_CA1_DER = "ca/mo/MO_SUB_CA1.der"
#     MO_ROOT_DER = "ca/mo/MO_ROOT_CA.der"

#     # Charge point operator (CPO)
#     SECC_LEAF_DER = "client/cso/SECC_LEAF.der"
#     SECC_LEAF_PEM = "client/cso/SECC_LEAF.pem"
#     CPO_SUB_CA2_DER = "ca/cso/CPO_SUB_CA2.der"
#     CPO_SUB_CA1_DER = "ca/cso/CPO_SUB_CA1.der"
#     CPO_SUB_CA1_PEM = "ca/cso/CPO_SUB_CA1.pem"
#     CPO_SUB_CA2_PEM = "ca/cso/CPO_SUB_CA2.pem"
#     V2G_ROOT_DER = "ca/v2g/V2G_ROOT_CA.der"
#     V2G_ROOT_PEM = "ca/v2g/V2G_ROOT_CA.pem"

#     # Certificate provisioning service (CPS)
#     CPS_LEAF_DER = "client/cps/CPS_LEAF.der"
#     CPS_SUB_CA2_DER = "ca/cps/CPS_SUB_CA2.der"
#     CPS_SUB_CA1_DER = "ca/cps/CPS_SUB_CA1.der"
#     # The root is the V2G_ROOT

#     # EV manufacturer (OEM)
#     OEM_LEAF_DER = "client/oem/OEM_LEAF.der"
#     OEM_SUB_CA2_DER = "ca/oem/OEM_SUB_CA2.der"
#     OEM_SUB_CA1_DER = "ca/oem/OEM_SUB_CA1.der"
#     OEM_ROOT_DER = "ca/oem/OEM_ROOT_CA.der"
#     OEM_ROOT_PEM = "ca/oem/OEM_ROOT_CA.pem"
#     OEM_CERT_CHAIN_PEM = "client/oem/OEM_CERT_CHAIN.pem"


# class KeyPath(str, Enum):
#     """
#     Provides the path to private keys used for Plug & Charge. The encoding
#     format is indicated by the latter part of the enum name (_DER or _PEM)

#     NOTE: For a productive environment, the access to a private key should be
#           managed in a secure way (e.g. through a hardware security module).
#     """

#     # Mobility operator (MO)
#     CONTRACT_LEAF_PEM = "client/mo/MO_LEAF.key"
#     MO_SUB_CA2_PEM = "client/mo/MO_SUB_CA2.key"
#     MO_SUB_CA1_PEM = "client/mo/MO_SUB_CA1.key"
#     MO_ROOT_PEM = "client/mo/MO_ROOT_CA.key"

#     # Charge point operator (CPO)
#     SECC_LEAF_PEM = "client/cso/SECC_LEAF.key"
#     CPO_SUB_CA2_PEM = "client/cso/CPO_SUB_CA2.key"
#     CPO_SUB_CA1_PEM = "client/cso/CPO_SUB_CA1.key"
#     V2G_ROOT_PEM = "client/v2g/V2G_ROOT_CA.key"

#     # Certificate provisioning service (CPS)
#     CPS_LEAF_PEM = "client/cps/CPS_LEAF.key"
#     CPS_SUB_CA2_PEM = "client/cps/CPS_SUB_CA2.key"
#     CPS_SUB_CA1_PEM = "client/cps/CPS_SUB_CA1.key"
#     # The root is the V2G_ROOT

#     # EV manufacturer (OEM)
#     OEM_LEAF_PEM = "client/oem/OEM_LEAF.key"
#     OEM_SUB_CA2_PEM = "client/oem/OEM_SUB_CA2.key"
#     OEM_SUB_CA1_PEM = "client/oem/OEM_SUB_CA1.key"
#     OEM_ROOT_PEM = "client/oem/OEM_ROOT_CA.key"


# class KeyPasswordPath(str, Enum):
#     """
#     Provides the path to private key passwords used for Plug & Charge.

#     NOTE: In a production environment, the access to a private key passwords should be
#           managed in a secure way (e.g. through a hardware security module).
#     """

#     # Private key password paths
#     SECC_LEAF_KEY_PASSWORD = "client/cso/SECC_LEAF_PASSWORD.txt"
#     OEM_LEAF_KEY_PASSWORD = "client/oem/OEM_LEAF_PASSWORD.txt"
#     CONTRACT_LEAF_KEY_PASSWORD = "client/mo/MO_LEAF_PASSWORD.txt"
#     CPS_LEAF_KEY_PASSWORD = "client/cps/CPS_LEAF_PASSWORD.txt"
#     MO_SUB_CA2_PASSWORD = "client/cso/CPO_SUB_CA2_PASSWORD.txt"