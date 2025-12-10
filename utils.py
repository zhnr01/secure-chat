"""
Shared utilities to follow DRY and keep server/client consistent.
"""
import hashlib
from typing import Union

from ecc import PrivateKey, Signature, S256Point
import json


def parse_certificate_bytes(cert_bytes: bytes) -> dict:
    return json.loads(cert_bytes.decode())


def extract_public_key(cert_data: dict):
    from ecc import S256Point
    return S256Point(
        int(cert_data['public_key_x'], 16),
        int(cert_data['public_key_y'], 16)
    )


def reconstruct_certificate(cert_dict: dict):
    from certificate_authority import Certificate
    sig = Signature(r=int(cert_dict['signature']['r'], 16), s=int(cert_dict['signature']['s'], 16))
    return Certificate(cert_dict['cert_data'], sig)


def xor_encrypt_decrypt(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])


def hash_message(msg: Union[int, str]) -> int:
    if isinstance(msg, int):
        msg_bytes = msg.to_bytes(32, 'big')
    elif isinstance(msg, str):
        msg_bytes = msg.encode()
    else:
        raise TypeError("Message must be int or str")
    return int.from_bytes(hashlib.sha256(msg_bytes).digest(), 'big')


def create_signed_message(private_key: PrivateKey, message: Union[str, int]) -> dict:
    z = hash_message(message)
    signature = private_key.sign(z)
    # Normalize message to str for transport
    msg_str = str(message)
    return {'message': msg_str, 'r': signature.r, 's': signature.s}


def verify_message(pub_key: S256Point, message_data: dict) -> bool:
    z = hash_message(message_data['message'])
    sig = Signature(message_data['r'], message_data['s'])
    return pub_key.verify(z, sig)
