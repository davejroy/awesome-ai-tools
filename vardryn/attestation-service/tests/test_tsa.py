"""
Tests for service/tsa.py.

`build_timestamp_request()` is checked by round-tripping through
asn1crypto's own `tsp.TimeStampReq.load()`.

`verify_timestamp_token()` is checked against a SYNTHETIC RFC 3161
TimeStampResp built here with the same asn1crypto/cryptography primitives
(RSA-PSS-SHA256 signature, signedAttrs with content-type + message-digest,
embedded self-signed certificate, matched via IssuerAndSerialNumber). This
exercises the CMS parsing + signature-verification logic but does NOT
confirm wire-compatibility with any specific real-world TSA — see the
ENGINEERING-CONFIDENCE NOTE in service/tsa.py.

Run directly: `python3 tests/test_tsa.py`
"""

from __future__ import annotations

import datetime as dt
import hashlib
import sys
from pathlib import Path

from asn1crypto import algos, cms, tsp
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from service.tsa import (  # noqa: E402
    TsaVerificationError,
    build_timestamp_request,
    verify_timestamp_token,
)


def _build_synthetic_token(
    entry_hash: bytes,
    *,
    tamper_message_imprint: bool = False,
    tamper_signature: bool = False,
) -> bytes:
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test TSA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2020, 1, 1))
        .not_valid_after(dt.datetime(2040, 1, 1))
        .sign(tsa_key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    asn1_cert = asn1_x509.Certificate.load(cert_der)

    message_imprint = b"\x00" * 64 if tamper_message_imprint else entry_hash

    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.5.6.7",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha512"}),
            "hashed_message": message_imprint,
        }),
        "serial_number": 1,
        "gen_time": dt.datetime.now(dt.timezone.utc),
        "ordering": False,
    })
    tst_info_der = tst_info.dump()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": cms.SetOfContentType(["tst_info"]),
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": cms.SetOfOctetString([hashlib.sha256(tst_info_der).digest()]),
        }),
    ])

    signed_bytes = signed_attrs.untag().dump()
    signature = tsa_key.sign(
        signed_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    if tamper_signature:
        signature = bytes([signature[0] ^ 0xFF]) + signature[1:]

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": asn1_cert.issuer,
                "serial_number": asn1_cert.serial_number,
            }),
        }),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({
            "algorithm": "rsassa_pss",
            "parameters": algos.RSASSAPSSParams({
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                "mask_gen_algorithm": algos.MaskGenAlgorithm({
                    "algorithm": "mgf1",
                    "parameters": algos.DigestAlgorithm({"algorithm": "sha256"}),
                }),
                "salt_length": 32,
            }),
        }),
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": cms.DigestAlgorithms([algos.DigestAlgorithm({"algorithm": "sha256"})]),
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": tst_info,
        }),
        "certificates": cms.CertificateSet([
            cms.CertificateChoices({"certificate": asn1_cert}),
        ]),
        "signer_infos": cms.SignerInfos([signer_info]),
    })

    content_info = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })

    resp = tsp.TimeStampResp({
        "status": tsp.PKIStatusInfo({"status": "granted"}),
        "time_stamp_token": content_info,
    })

    return resp.dump()


def test_build_timestamp_request_round_trips() -> None:
    entry_hash = hashlib.sha512(b"some entry").digest()
    request_der = build_timestamp_request(entry_hash, hash_algorithm="sha512")

    req = tsp.TimeStampReq.load(request_der)
    assert req["message_imprint"]["hashed_message"].native == entry_hash
    assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha512"
    assert req["cert_req"].native is True
    print("PASS: build_timestamp_request round-trips through asn1crypto")


def test_verify_synthetic_token_happy_path() -> None:
    entry_hash = hashlib.sha512(b"ledger entry bytes").digest()
    token = _build_synthetic_token(entry_hash)

    result = verify_timestamp_token(token, entry_hash, expected_hash_algorithm="sha512")

    assert result.digest_algorithm == "sha512"
    assert result.signing_cert_der is not None
    assert result.serial_number == 1
    print("PASS: synthetic token verifies")


def test_message_imprint_mismatch_rejected() -> None:
    entry_hash = hashlib.sha512(b"ledger entry bytes").digest()
    token = _build_synthetic_token(entry_hash, tamper_message_imprint=True)

    try:
        verify_timestamp_token(token, entry_hash, expected_hash_algorithm="sha512")
    except TsaVerificationError as exc:
        assert "messageImprint" in str(exc)
        print("PASS: messageImprint mismatch rejected")
        return
    raise AssertionError("expected TsaVerificationError")


def test_tampered_signature_rejected() -> None:
    entry_hash = hashlib.sha512(b"ledger entry bytes").digest()
    token = _build_synthetic_token(entry_hash, tamper_signature=True)

    try:
        verify_timestamp_token(token, entry_hash, expected_hash_algorithm="sha512")
    except TsaVerificationError as exc:
        assert "signature" in str(exc)
        print("PASS: tampered CMS signature rejected")
        return
    raise AssertionError("expected TsaVerificationError")


if __name__ == "__main__":
    test_build_timestamp_request_round_trips()
    test_verify_synthetic_token_happy_path()
    test_message_imprint_mismatch_rejected()
    test_tampered_signature_rejected()
    print("\nOK: all tsa tests passed")
