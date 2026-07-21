"""Tests for the certificate authority, certificates, and PEM handling."""
import pytest

from secure_chat.crypto.ecc import N, PrivateKey
from secure_chat.crypto.rng import randint
from secure_chat.pki.certificate_authority import (
    Certificate,
    CertificateAuthority,
    PEMFormatter,
    PEMLabel,
    PrivateKeyWrapper,
)


@pytest.fixture
def ca() -> CertificateAuthority:
    return CertificateAuthority()


@pytest.fixture
def subject_key() -> PrivateKey:
    return PrivateKey(randint(1, N - 1))


def test_signed_certificate_verifies(ca, subject_key):
    cert = ca.sign_certificate("Alice", subject_key.point)
    assert cert.verify(ca.public_key)


def test_certificate_survives_dict_roundtrip(ca, subject_key):
    cert = ca.sign_certificate("Alice", subject_key.point)
    restored = Certificate.from_dict(cert.to_dict())
    assert restored.verify(ca.public_key)


def test_certificate_carries_the_subject_public_key(ca, subject_key):
    cert = ca.sign_certificate("Alice", subject_key.point)
    recovered = cert.public_key()
    assert recovered.x.num == subject_key.point.x.num
    assert recovered.y.num == subject_key.point.y.num


def test_certificate_from_another_ca_is_rejected(subject_key):
    issuer = CertificateAuthority()
    attacker = CertificateAuthority()
    cert = issuer.sign_certificate("Alice", subject_key.point)
    assert not cert.verify(attacker.public_key)


def test_tampered_subject_breaks_verification(ca, subject_key):
    cert = ca.sign_certificate("Alice", subject_key.point)
    cert.cert_data["subject"] = "Mallory"
    assert not cert.verify(ca.public_key)


def test_private_key_pem_roundtrip(tmp_path, subject_key):
    path = tmp_path / "key.pem"
    PrivateKeyWrapper(subject_key).save(str(path))
    loaded = PrivateKeyWrapper.load(str(path))
    assert loaded.private_key.secret == subject_key.secret


def test_certificate_pem_roundtrip(tmp_path, ca, subject_key):
    path = tmp_path / "cert.pem"
    cert = ca.sign_certificate("Alice", subject_key.point)
    cert.save(str(path))
    assert Certificate.load(str(path)).verify(ca.public_key)


def test_pem_formatter_roundtrip():
    data = b"some bytes to wrap in PEM"
    pem = PEMFormatter.encode(data, PEMLabel.CERTIFICATE)
    assert PEMFormatter.decode(pem, PEMLabel.CERTIFICATE) == data
