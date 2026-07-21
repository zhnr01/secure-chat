"""End-to-end test: a real server relays an encrypted message between clients.

This exercises the whole stack together — TCP framing, certificate exchange and
verification, signed Diffie-Hellman, session-key derivation, and the
authenticated cipher — against a server bound to an ephemeral port.
"""
import socket
import threading
import time

import pytest

from secure_chat.crypto.cipher import SessionKeys, open_text, seal_text
from secure_chat.crypto.ecc import N, PrivateKey
from secure_chat.crypto.key_exchange import KeyExchange
from secure_chat.crypto.rng import randint
from secure_chat.pki.certificate_authority import Certificate, CertificateAuthority
from secure_chat.server.app import Server
from secure_chat.transport.messaging import create_signed_message, verify_message
from secure_chat.transport.protocol import recv_json, send_json


@pytest.fixture
def running_server(tmp_path, monkeypatch):
    """Boot a server with a fresh CA/keys wired through config env vars."""
    ca = CertificateAuthority()
    ca_key_path = tmp_path / "ca.pem"
    ca.get_private_key_wrapper().save(str(ca_key_path))

    def issue(subject: str, key_name: str, cert_name: str):
        from secure_chat.pki.certificate_authority import PrivateKeyWrapper

        key = PrivateKey(randint(1, N - 1))
        key_path = tmp_path / key_name
        cert_path = tmp_path / cert_name
        PrivateKeyWrapper(key).save(str(key_path))
        ca.sign_certificate(subject, key.point).save(str(cert_path))
        return str(key_path), str(cert_path)

    server_key, server_cert = issue("Server", "server_key.pem", "server_cert.pem")
    client_key, client_cert = issue("Client", "client_key.pem", "client_cert.pem")

    monkeypatch.setenv("SECURE_CHAT_CA_KEY", str(ca_key_path))
    monkeypatch.setenv("SECURE_CHAT_SERVER_KEY", server_key)
    monkeypatch.setenv("SECURE_CHAT_SERVER_CERT", server_cert)
    monkeypatch.setenv("SECURE_CHAT_CLIENT_KEY", client_key)
    monkeypatch.setenv("SECURE_CHAT_CLIENT_CERT", client_cert)

    # Reload config and server modules so they pick up the patched env vars.
    import importlib

    from secure_chat import config
    from secure_chat.pki import identity
    from secure_chat.server import app

    importlib.reload(config)
    importlib.reload(identity)
    importlib.reload(app)

    server = app.Server(host="127.0.0.1", port=0)
    port = server._server_socket.getsockname()[1]
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    _wait_until_listening("127.0.0.1", port)

    yield port, config

    importlib.reload(config)


def _wait_until_listening(host: str, port: int, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError("server did not start listening in time")


def _handshake_as_client(host: str, port: int, config):
    from secure_chat.pki.identity import Identity

    identity = Identity.load(
        config.CLIENT_PRIVATE_KEY_PATH,
        config.CLIENT_CERT_PATH,
        config.CA_PRIVATE_KEY_PATH,
    )
    conn = socket.create_connection((host, port))

    server_cert = Certificate.from_dict(recv_json(conn))
    assert server_cert.verify(identity.ca_public_key)
    server_pub = server_cert.public_key()

    send_json(conn, identity.certificate.to_dict())
    server_dh = recv_json(conn)
    assert verify_message(server_pub, server_dh)

    exchange = KeyExchange()
    send_json(conn, create_signed_message(identity.signing_key, exchange.public_component()))
    keys = SessionKeys.derive(exchange.derive_shared(int(server_dh["message"])))
    return conn, identity, server_pub, keys


def test_message_is_relayed_between_two_clients(running_server):
    port, config = running_server
    sender_conn, sender_id, _, sender_keys = _handshake_as_client("127.0.0.1", port, config)
    recv_conn, _, recv_server_pub, recv_keys = _handshake_as_client("127.0.0.1", port, config)
    time.sleep(0.2)

    plaintext = "meet at the bridge"
    send_json(
        sender_conn,
        create_signed_message(sender_id.signing_key, seal_text(sender_keys, plaintext)),
    )

    recv_conn.settimeout(3)
    relayed = recv_json(recv_conn)
    assert verify_message(recv_server_pub, relayed)
    assert plaintext in open_text(recv_keys, relayed["message"])

    sender_conn.close()
    recv_conn.close()
