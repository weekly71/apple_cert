import contextlib
import plistlib
import re
from datetime import datetime
from typing import Self

import aiohttp
from anyio import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12KeyAndCertificates
from cryptography.x509 import Certificate, ocsp


class InvalidPassword(Exception):
    def __init__(self):
        super().__init__("Wrong p12 password given")


class NotRelatedCert(Exception):
    def __init__(self):
        super().__init__("Mobileprovision and P12 are not related to each other")


class AppleP12:
    def __init__(self, p12: PKCS12KeyAndCertificates, path: Path, password: str) -> None:
        self._cert = p12.cert.certificate
        self._key = p12.key
        self._cas = p12.additional_certs

        self.name = self._cert.subject.rdns[3].rfc4514_string().removeprefix("O=").replace("\\", "")
        self.uid = self._cert.subject.rdns[0].rfc4514_string().removeprefix("UID=")
        self.expiration: datetime = self._cert.not_valid_after
        self.path = path
        self.password = password

    async def set_password(self, value: str) -> None:
        new_p12 = pkcs12.serialize_key_and_certificates(
            self.name.encode(),
            self._key,
            self._cert,
            self._cas,
            BestAvailableEncryption(value.encode())
        )
        self._cert = pkcs12.load_pkcs12(
            new_p12,
            value.encode()
        )
        await self.path.write_bytes(new_p12)

        self.password = value

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

    def _get_ocsp_url(self) -> str | None:
        with contextlib.suppress(x509.ExtensionNotFound):
            aia = self._cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in aia.value:
                if desc.access_method == x509.OID_OCSP:
                    return desc.access_location.value

    async def _ocsp_check(self, ca_cert: Certificate) -> ocsp.OCSPResponse:
        ocsp_url = self._get_ocsp_url()

        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(self._cert, ca_cert, self._cert.signature_hash_algorithm)
        req = builder.build()

        ocsp_req_data = req.public_bytes(serialization.Encoding.DER)
        async with aiohttp.ClientSession() as client:
            async with client.post(ocsp_url, data=ocsp_req_data,
                                   headers={'Content-Type': 'application/ocsp-request'}) as response:
                return ocsp.load_der_ocsp_response(await response.content.read())

    @classmethod
    async def load(cls, path: Path, password: str | None) -> Self:
        return cls(
            pkcs12.load_pkcs12(
                await path.read_bytes(), password.encode() or None
            ),
            path, password
        )


class MobileProvision:
    def __init__(self, contents: bytes, path: Path) -> None:
        self._plist = plistlib.loads(re.search(rb"<?xml.+</plist>",
                                               contents, re.DOTALL).group())
        self.path = path
        self.name = self._plist["TeamName"]
        self.uid = self._plist["TeamIdentifier"][0]
        self.enterprise = self._plist.get("ProvisionsAllDevices")
        self.devices = self._plist.get("ProvisionedDevices")
        self.entitlements = self._plist["Entitlements"]

    @classmethod
    async def load(cls, path: Path) -> Self:
        return cls(
            await path.read_bytes(),
            path
        )


class AppleCert:
    def __init__(self, p12: AppleP12, prov: MobileProvision) -> None:
        self.p12 = p12
        self.provision = prov

    @classmethod
    async def load(cls, p12_path: Path, prov_path: Path | None, password: str) -> Self:
        if not await p12_path.exists() or (not await prov_path.exists() if prov_path else False):
            raise FileNotFoundError

        p12 = await AppleP12.load(p12_path, password)
        prov = await MobileProvision.load(prov_path)
        if p12.uid != prov.uid:
            raise NotRelatedCert

        return cls(p12, prov)
