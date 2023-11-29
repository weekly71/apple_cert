import contextlib
from datetime import datetime
from typing import Self

import aiohttp
from anyio import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import Certificate, ocsp


class InvalidPassword(Exception):
    def __init__(self):
        super().__init__("Wrong p12 password given")


class AppleCert:
    def __init__(self, p12_path: Path, p12_pass: str, prov_path: Path | None, p12_cert: Certificate, name: str,
                 expiration: datetime) -> None:
        self.p12_path = p12_path
        self._password = p12_pass
        self.prov_path = prov_path
        self._p12_cert = p12_cert
        self.name = name
        self.expiration = expiration

    @classmethod
    async def load(cls, p12_path: Path, prov_path: Path | None, password: str) -> Self:
        if not await p12_path.exists() or (not await prov_path.exists() if prov_path else False):
            raise FileNotFoundError

        async with await p12_path.open('rb') as p12_file:
            try:
                p12_cert = pkcs12.load_pkcs12(await p12_file.read(), password.encode() or None).cert.certificate
            except ValueError:
                raise InvalidPassword

        subject = p12_cert.subject.rdns[3].rfc4514_string().removeprefix("O=").replace("\\", "")
        expiration = p12_cert.not_valid_after

        return cls(p12_path, password, prov_path, p12_cert, subject, expiration)

    def _get_ocsp_url(self) -> str | None:
        with contextlib.suppress(x509.ExtensionNotFound):
            aia = self._p12_cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in aia.value:
                if desc.access_method == x509.OID_OCSP:
                    return desc.access_location.value

    async def _ocsp_check(self, ca_cert: Certificate) -> ocsp.OCSPResponse:
        ocsp_url = self._get_ocsp_url()

        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(self._p12_cert, ca_cert, self._p12_cert.signature_hash_algorithm)
        req = builder.build()

        ocsp_req_data = req.public_bytes(serialization.Encoding.DER)
        async with aiohttp.ClientSession() as client:
            async with client.post(ocsp_url, data=ocsp_req_data,
                                   headers={'Content-Type': 'application/ocsp-request'}) as response:
                return ocsp.load_der_ocsp_response(await response.content.read())

    @property
    def password(self) -> str | None:
        return self._password or None

    @password.setter
    def password(self, value: str):
        # TODO: cert password setter
        raise NotImplemented

    @property
    async def signed(self):
        ca_certs = ["AppleWWDRCA", "AppleWWDRCAG2", "AppleWWDRCAG3", "AppleWWDRCAG4", "AppleWWDRCAG5", "AppleWWDRCAG6"]

        for cert in ca_certs:
            async with aiohttp.ClientSession() as client:
                async with client.get(
                        "https://developer.apple.com/certificationauthority/AppleWWDRCA.cer"
                        if cert.endswith("A") else
                        f"https://www.apple.com/certificateauthority/{cert}.cer"
                ) as response:
                    ca_cert = x509.load_der_x509_certificate(await response.content.read())

            ocsp_resp = await self._ocsp_check(ca_cert)

            if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                signed = ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD
                break
        else:
            signed = False

        return signed
