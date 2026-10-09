"""Ephemeral HTTPS interception certificates, never installed on the host."""

from __future__ import annotations

import datetime
import ipaddress
import os
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CertificateAuthority:
    def __init__(self):
        self._key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sandbox execution ephemeral proxy CA")])
        self._certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                        content_commitment=False, data_encipherment=False,
                                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                                        encipher_only=False, decipher_only=False), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    @property
    def pem(self) -> str:
        return self._certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def server_context(self, hostname: str) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            alternative = x509.IPAddress(ipaddress.ip_address(hostname))
        except ValueError:
            alternative = x509.DNSName(hostname)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname[:64])]))
            .issuer_name(self._certificate.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(self._certificate.not_valid_after_utc)
            .add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                        content_commitment=False, data_encipherment=False,
                                        key_agreement=False, key_cert_sign=False, crl_sign=False,
                                        encipher_only=False, decipher_only=False), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        # Python's SSL API loads certificates by filename. Only this short-lived
        # leaf key touches disk, inside a private directory with mode-0600 files.
        # The CA signing key stays in memory. Files disappear before accepting TLS.
        with tempfile.TemporaryDirectory(prefix="sandbox-proxy-tls-") as directory:
            cert_path = os.path.join(directory, "leaf.pem")
            key_path = os.path.join(directory, "leaf.key")
            for path, data in (
                (cert_path, certificate.public_bytes(serialization.Encoding.PEM)
                 + self._certificate.public_bytes(serialization.Encoding.PEM)),
                (key_path, key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption())),
            ):
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
            context.load_cert_chain(cert_path, key_path)
        return context
