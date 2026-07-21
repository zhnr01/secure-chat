"""Tests for JSON framing and signed-message envelopes."""
import socket

import pytest

from secure_chat.crypto.ecc import N, PrivateKey
from secure_chat.crypto.rng import randint
from secure_chat.transport.messaging import create_signed_message, verify_message
from secure_chat.transport.protocol import (
    MAX_FRAME_BYTES,
    recv_json,
    send_json,
)


@pytest.fixture
def socket_pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_single_message_roundtrips(socket_pair):
    sender, receiver = socket_pair
    payload = {"message": "hello", "n": 42}
    send_json(sender, payload)
    assert recv_json(receiver) == payload


def test_multiple_messages_keep_their_boundaries(socket_pair):
    sender, receiver = socket_pair
    first = {"seq": 1, "body": "a" * 500}
    second = {"seq": 2, "body": "b"}
    send_json(sender, first)
    send_json(sender, second)
    assert recv_json(receiver) == first
    assert recv_json(receiver) == second


def test_closed_connection_returns_none(socket_pair):
    sender, receiver = socket_pair
    sender.close()
    assert recv_json(receiver) is None


def test_oversized_frame_is_rejected(socket_pair):
    sender, receiver = socket_pair
    # Forge a header claiming a frame larger than the allowed maximum.
    sender.sendall((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    with pytest.raises(ValueError):
        recv_json(receiver)


def _key() -> PrivateKey:
    return PrivateKey(randint(1, N - 1))


def test_signed_message_verifies_with_matching_key():
    key = _key()
    envelope = create_signed_message(key, "the message")
    assert verify_message(key.point, envelope)


def test_signed_integer_is_normalized_to_string():
    key = _key()
    envelope = create_signed_message(key, 12345)
    assert envelope["message"] == "12345"
    assert verify_message(key.point, envelope)


def test_tampered_message_body_fails_verification():
    key = _key()
    envelope = create_signed_message(key, "original")
    envelope["message"] = "forged"
    assert not verify_message(key.point, envelope)


def test_message_from_another_key_fails_verification():
    signer, other = _key(), _key()
    envelope = create_signed_message(signer, "hi")
    assert not verify_message(other.point, envelope)
