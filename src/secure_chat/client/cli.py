"""Secure chat command-line client.

Connects to the server, verifies the server's certificate against the CA,
presents its own certificate, runs a Diffie-Hellman exchange, and then sends
and receives signed, encrypted messages over the established session.
"""
import argparse
import socket
import threading

from ..config import (
    CA_PRIVATE_KEY_PATH,
    CLIENT_CERT_PATH,
    CLIENT_PRIVATE_KEY_PATH,
    HOST,
    PORT,
)
from ..crypto.cipher import AuthenticationError, SessionKeys, open_text, seal_text
from ..crypto.key_exchange import KeyExchange
from ..observability import setup_logger
from ..pki.certificate_authority import Certificate
from ..pki.identity import Identity
from ..transport.messaging import create_signed_message, verify_message
from ..transport.protocol import recv_json, send_json

_QUIT_COMMAND = "exit"
_PROMPT = "> "


class HandshakeError(Exception):
    """Raised when the server cannot be authenticated or the handshake fails."""


class Client:
    """Interactive client that maintains one authenticated session."""

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.logger = setup_logger("client")
        self.identity = Identity.load(
            private_key_path=CLIENT_PRIVATE_KEY_PATH,
            certificate_path=CLIENT_CERT_PATH,
            ca_key_path=CA_PRIVATE_KEY_PATH,
        )
        self._connection: socket.socket | None = None
        self._server_public_key = None
        self._session_keys: SessionKeys | None = None

    def start(self) -> None:
        try:
            self._connect()
            self._handshake()
        except HandshakeError as error:
            self.logger.error(str(error))
            self._close()
            return
        self._chat_loop()

    def _connect(self) -> None:
        self._connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._connection.connect((self.host, self.port))
        self.logger.info(f"Connected to {self.host}:{self.port}")

    def _handshake(self) -> None:
        """Verify the server, present our certificate, and derive session keys."""
        server_cert_data = recv_json(self._connection)
        if server_cert_data is None:
            raise HandshakeError("Server closed the connection during handshake")

        server_certificate = Certificate.from_dict(server_cert_data)
        self._server_public_key = server_certificate.public_key()
        if not server_certificate.verify(self.identity.ca_public_key):
            raise HandshakeError("Server certificate verification failed")
        self.logger.info("Server certificate verified.")

        send_json(self._connection, self.identity.certificate.to_dict())
        self._session_keys = self._exchange_session_key()
        self.logger.info("Secure session established.")

    def _exchange_session_key(self) -> SessionKeys:
        server_dh = recv_json(self._connection)
        if server_dh is None:
            raise HandshakeError("Server closed the connection during key exchange")
        if not verify_message(self._server_public_key, server_dh):
            raise HandshakeError("Server key-exchange message failed verification")

        exchange = KeyExchange()
        send_json(
            self._connection,
            create_signed_message(self.identity.signing_key, exchange.public_component()),
        )
        shared_secret = exchange.derive_shared(int(server_dh["message"]))
        return SessionKeys.derive(shared_secret)

    def _chat_loop(self) -> None:
        threading.Thread(target=self._receive_loop, daemon=True).start()
        try:
            while True:
                message = input(_PROMPT)
                if message.lower() == _QUIT_COMMAND:
                    break
                self._send(message)
        except (EOFError, KeyboardInterrupt):
            pass
        finally:
            self._close()

    def _send(self, message: str) -> None:
        token = seal_text(self._session_keys, message)
        send_json(self._connection, create_signed_message(self.identity.signing_key, token))

    def _receive_loop(self) -> None:
        try:
            while True:
                envelope = recv_json(self._connection)
                if envelope is None:
                    break
                if not verify_message(self._server_public_key, envelope):
                    self.logger.warning("Dropping message with an invalid signature.")
                    continue
                try:
                    self.logger.info(open_text(self._session_keys, envelope["message"]))
                except AuthenticationError:
                    self.logger.warning("Dropping unauthentic message.")
        except (ConnectionError, OSError):
            self.logger.info("Connection to server closed.")

    def _close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self.logger.info("Disconnected.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--host", default=HOST, help="Server host")
    parser.add_argument("--port", type=int, default=PORT, help="Server port")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    Client(host=args.host, port=args.port).start()


if __name__ == "__main__":
    main()
