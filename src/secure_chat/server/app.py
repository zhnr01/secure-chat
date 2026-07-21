"""Secure chat server: an authenticated message relay.

The server presents its CA-signed certificate, verifies each client's
certificate, runs a Diffie-Hellman exchange to establish a per-client session
key, then relays signed, encrypted messages between connected clients.

The relay is trusted to route messages but not to read them undetected: every
message is signed by its sender, so a tampered or forged relay is caught by the
recipient's signature check.
"""
import argparse
import socket
import threading

from ..config import (
    BACKLOG,
    CA_PRIVATE_KEY_PATH,
    HOST,
    PORT,
    SERVER_CERT_PATH,
    SERVER_PRIVATE_KEY_PATH,
)
from ..crypto.cipher import AuthenticationError, SessionKeys, open_text, seal_text
from ..crypto.key_exchange import KeyExchange
from ..observability import setup_logger
from ..pki.certificate_authority import Certificate
from ..pki.identity import Identity
from ..transport.messaging import create_signed_message, verify_message
from ..transport.protocol import recv_json, send_json
from .session import ClientSession, SessionRegistry


class Server:
    """Threaded TCP relay that authenticates clients and forwards messages."""

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.logger = setup_logger("server")
        self.sessions = SessionRegistry()
        self.identity = Identity.load(
            private_key_path=SERVER_PRIVATE_KEY_PATH,
            certificate_path=SERVER_CERT_PATH,
            ca_key_path=CA_PRIVATE_KEY_PATH,
        )
        self._server_socket = self._create_listening_socket()
        self.logger.info(f"Server listening on {self.host}:{self.port}")

    def _create_listening_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(BACKLOG)
        return sock

    def start(self) -> None:
        """Accept connections and hand each off to its own daemon thread."""
        try:
            while True:
                connection, address = self._server_socket.accept()
                threading.Thread(
                    target=self._serve_client,
                    args=(connection, address),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            self.logger.info("Shutting down.")
        finally:
            self._server_socket.close()

    def _serve_client(self, connection: socket.socket, address: tuple) -> None:
        self.logger.info(f"Connection from {address[0]}:{address[1]}")
        session = None
        try:
            session = self._handshake(connection, address)
            if session is None:
                return
            self.sessions.add(session)
            self._relay_loop(session)
        except (ConnectionError, OSError):
            self.logger.info(f"Connection lost: {address[0]}:{address[1]}")
        except Exception:
            self.logger.exception(f"Unexpected error handling {address[0]}:{address[1]}")
        finally:
            if session is not None:
                self.sessions.remove(session)
            connection.close()
            self.logger.info(f"Disconnected: {address[0]}:{address[1]}")

    def _handshake(self, connection: socket.socket, address: tuple) -> ClientSession | None:
        """Authenticate the client and establish a session key.

        Returns the ready ``ClientSession`` on success, or ``None`` if the
        client failed verification or disconnected mid-handshake.
        """
        send_json(connection, self.identity.certificate.to_dict())

        client_cert_data = recv_json(connection)
        if client_cert_data is None:
            return None
        client_certificate = Certificate.from_dict(client_cert_data)
        if not client_certificate.verify(self.identity.ca_public_key):
            self.logger.warning(f"Certificate rejected for {address[0]}:{address[1]}")
            return None
        self.logger.info(f"Certificate verified for {address[0]}:{address[1]}")

        client_public_key = client_certificate.public_key()
        keys = self._exchange_session_key(connection, client_public_key)
        if keys is None:
            return None

        self.logger.info(f"Session established with {address[0]}:{address[1]}")
        return ClientSession(connection, address, client_public_key, keys)

    def _exchange_session_key(self, connection, client_public_key) -> SessionKeys | None:
        """Run the signed Diffie-Hellman exchange and derive the session keys."""
        exchange = KeyExchange()
        send_json(
            connection,
            create_signed_message(self.identity.signing_key, exchange.public_component()),
        )

        client_dh = recv_json(connection)
        if client_dh is None:
            return None
        if not verify_message(client_public_key, client_dh):
            self.logger.warning("Client DH message failed signature verification")
            return None

        shared_secret = exchange.derive_shared(int(client_dh["message"]))
        return SessionKeys.derive(shared_secret)

    def _relay_loop(self, session: ClientSession) -> None:
        """Read authenticated messages from one client and fan them out."""
        while True:
            envelope = recv_json(session.connection)
            if envelope is None:
                break
            if not verify_message(session.public_key, envelope):
                self.logger.warning(f"Dropping unsigned message from {session.label}")
                break
            try:
                plaintext = open_text(session.keys, envelope["message"])
            except AuthenticationError:
                self.logger.warning(f"Dropping unauthentic message from {session.label}")
                break

            self.logger.info(f"[{session.label}] {plaintext}")
            self._broadcast(session, f"[{session.label}] {plaintext}")

    def _broadcast(self, sender: ClientSession, message: str) -> None:
        """Deliver ``message`` to every connected client except the sender.

        Each recipient has its own session key, so the message is re-encrypted
        and re-signed per recipient.
        """
        for recipient in self.sessions.others(exclude=sender):
            try:
                token = seal_text(recipient.keys, message)
                signed = create_signed_message(self.identity.signing_key, token)
                send_json(recipient.connection, signed)
            except OSError:
                self.logger.warning(f"Failed to deliver to {recipient.label}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure Chat Server")
    parser.add_argument("--host", default=HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=PORT, help="Port to listen on")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    Server(host=args.host, port=args.port).start()


if __name__ == "__main__":
    main()
