"""
Shared utilities to follow DRY and keep server/client consistent.
"""
import hashlib
from typing import Union

from ecc import PrivateKey, Signature, S256Point


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
    return {'message': message, 'r': signature.r, 's': signature.s}


def verify_message(pub_key: S256Point, message_data: dict) -> bool:
    z = hash_message(message_data['message'])
    sig = Signature(message_data['r'], message_data['s'])
    return pub_key.verify(z, sig)
