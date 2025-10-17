import hashlib
import json
import base64
from random import randint
from enum import Enum
from ecc import *


class PEMLabel(Enum):
    PRIVATE_KEY = "PRIVATE KEY"
    CERTIFICATE = "CERTIFICATE"


class PEMFormatter:
    @staticmethod
    def encode(data: bytes, label: PEMLabel) -> str:
        base64_encoded = base64.b64encode(data).decode()
        lines = [base64_encoded[i:i+64]
                 for i in range(0, len(base64_encoded), 64)]
        return f"-----BEGIN {label.value}-----\n" + "\n".join(lines) + f"\n-----END {label.value}-----\n"

    @staticmethod
    def decode(pem_data: str, label: PEMLabel) -> bytes:
        clean_data = pem_data.strip().replace(
            f"-----BEGIN {label.value}-----", "").replace(f"-----END {label.value}-----", "").replace('\n', "")
        return base64.b64decode(clean_data)


class PEMHandler:
    @staticmethod
    def load(filename: str, label: PEMLabel) -> bytes:
        with open(filename, 'r') as f:
            pem_data = f.read()
        return PEMFormatter.decode(pem_data, label)

    @staticmethod
    def save(data: bytes, filename: str, label: PEMLabel):
        pem = PEMFormatter.encode(data, label)
        with open(filename, 'w') as f:
            f.write(pem)
        print(f"Saved {label.value} to {filename}")


class PrivateKeyWrapper:
    def __init__(self, private_key):
        self.private_key = private_key

    def save(self, filename):
        private_key_bytes = self.private_key.secret.to_bytes(32, 'big')
        PEMHandler.save(private_key_bytes, filename, PEMLabel.PRIVATE_KEY)

    @staticmethod
    def load(filename):
        return PrivateKey(int.from_bytes(PEMHandler.load(filename, PEMLabel.PRIVATE_KEY)))


class Certificate:
    def __init__(self, cert_data, signature):
        self.cert_data = cert_data
        self.signature = signature

    def cert_bytes(self) -> str:
        cert_json = {
            "cert_data": self.cert_data,
            "signature": {
                "r": hex(self.signature.r),
                "s": hex(self.signature.s)
            }
        }
        cert_bytes = json.dumps(cert_json, sort_keys=True).encode()
        return cert_bytes

    def save(self, filename):
        cert_bytes = self.cert_bytes()
        PEMHandler.save(cert_bytes, filename, PEMLabel.CERTIFICATE)

    @staticmethod
    def load(filename):
        server_certificate = json.loads(
            PEMHandler.load(filename, PEMLabel.CERTIFICATE).decode())

        return Certificate(server_certificate['cert_data'], Signature(
            r=eval(server_certificate['signature']['r']),
            s=eval(server_certificate['signature']['s'])
        ))

    def verify(self, ca_public_key):
        cert_bytes = json.dumps(self.cert_data, sort_keys=True).encode()
        cert_hash = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big')
        return ca_public_key.verify(cert_hash, self.signature)


class CertificateAuthority:
    def __init__(self, private_key=None):
        self.private_key = private_key or PrivateKey(randint(1, N-1))
        self.public_key = self.private_key.point

    def sign_certificate(self, subject_name, subject_public_key):
        cert_data = {
            "subject": subject_name,
            "public_key_x": hex(subject_public_key.x.num),
            "public_key_y": hex(subject_public_key.y.num)
        }
        cert_bytes = json.dumps(cert_data, sort_keys=True).encode()
        cert_hash = int.from_bytes(hashlib.sha256(cert_bytes).digest(), 'big')
        signature = self.private_key.sign(cert_hash)
        return Certificate(cert_data, signature)

    def get_private_key_wrapper(self):
        return PrivateKeyWrapper(self.private_key)


# pk = PrivateKey(randint(1, N-1))
# public_key = pk.point
# print(pk.secret)

# ca_pk = PrivateKeyWrapper.load('ca_private.pem')
# ca = CertificateAuthority(ca_pk)
# cert = ca.sign_certificate("User", public_key)
# cert.save('client2_certificate.pem')