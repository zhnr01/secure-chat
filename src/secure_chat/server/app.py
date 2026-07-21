"""Secure chat server — an authenticated relay.

The server presents a CA-signed certificate, verifies each client's
certificate, performs a Diffie-Hellman key exchange, and then relays signed,
encrypted messages between connected clients.
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
from ..crypto.cipher import xor_encrypt_decrypt
from ..crypto.key_exchange import KeyExchange
from ..observability import setup_logger
from ..pki.certificate_authority import Certificate, PrivateKeyWrapper
from ..transport.messaging import create_signed_message, verify_message
from ..transport.protocol import recv_json, send_json


class Server:
    """Threaded TCP chat server."""

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.logger = setup_logger("server")
        self.connected_clients: list = []

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(BACKLOG)

        # Load the server's own signing key and its CA-signed certificate.
        self.server_key = PrivateKeyWrapper.load(SERVER_PRIVATE_KEY_PATH).private_key
        self.server_certificate = Certificate.load(SERVER_CERT_PATH)
        # The CA public key is used to verify every client certificate. We only
        # need the public point, so load it once at startup.
        self.ca_public_key = PrivateKeyWrapper.load(CA_PRIVATE_KEY_PATH).point

        self.logger.info(f"Server started on {self.host}:{self.port}")

    def broadcast(self, sender_socket, message: str) -> None:
        for client_socket, _, client_shared_secret in list(self.connected_clients):
            if client_socket is sender_socket:
                continue
            try:
                encrypted_bytes = xor_encrypt_decrypt(message, str(client_shared_secret))
                encrypted_message = encrypted_bytes.decode(errors="ignore")
                signed = create_signed_message(self.server_key, encrypted_message)
                send_json(client_socket, signed)
            except Exception:
                self.logger.warning("Failed to deliver message to a client")

    def handle_client(self, client_socket, client_address) -> None:
        self.logger.info(f"New connection from {client_address}")
        try:
            send_json(client_socket, self.server_certificate.to_dict())

            client_cert_data = recv_json(client_socket)
            client_certificate = Certificate.from_dict(client_cert_data)

            if not client_certificate.verify(self.ca_public_key):
                self.logger.warning(f"Certificate verification failed for {client_address}")
                return

            client_public_key = client_certificate.public_key()
            self.logger.info(f"Client {client_address} certificate verified.")

            kx = KeyExchange()
            key_generated = kx.public_component()
            send_json(client_socket, create_signed_message(self.server_key, key_generated))

            data = recv_json(client_socket)
            if not verify_message(client_public_key, data):
                self.logger.warning("Client message verification failed!")
                return

            shared_secret = kx.derive_shared(int(data["message"]))
            self.logger.info(f"Shared secret established with {client_address}")

            self.connected_clients.append((client_socket, client_address, shared_secret))

            while True:
                encrypted_message = recv_json(client_socket)
                if not encrypted_message:
                    break

                if not verify_message(client_public_key, encrypted_message):
                    self.logger.warning(f"Client {client_address} message verification failed!")
                    return

                decrypted_bytes = xor_encrypt_decrypt(encrypted_message["message"], str(shared_secret))
                decrypted_message = decrypted_bytes.decode(errors="ignore")
                self.logger.info(f"[{client_address}] {decrypted_message}")

                self.broadcast(client_socket, f"[{client_address}] {decrypted_message}")

        except Exception as e:
            self.logger.exception(f"Error with {client_address}: {e}")
        finally:
            self.logger.info(f"Disconnected: {client_address}")
            client_socket.close()
            self._remove_client(client_socket, client_address)

    def _remove_client(self, client_socket, client_address) -> None:
        for idx, (sock, addr, _) in enumerate(list(self.connected_clients)):
            if sock is client_socket and addr == client_address:
                self.connected_clients.pop(idx)
                break

    def start(self) -> None:
        self.logger.info("Server ready for connections...")
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            self.logger.info("Shutting down server.")
        finally:
            self.server_socket.close()


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
