"""Secure chat CLI client.

Connects to the server, verifies the server certificate against the CA,
presents its own certificate, performs a Diffie-Hellman key exchange, and then
sends and receives signed, encrypted messages.
"""
import argparse
import socket
import sys
import threading

from ..config import (
    CA_PRIVATE_KEY_PATH,
    CLIENT_CERT_PATH,
    CLIENT_PRIVATE_KEY_PATH,
    HOST,
    PORT,
)
from ..crypto.cipher import xor_encrypt_decrypt
from ..crypto.key_exchange import KeyExchange
from ..observability import setup_logger
from ..pki.certificate_authority import Certificate, PrivateKeyWrapper
from ..transport.messaging import create_signed_message, verify_message
from ..transport.protocol import recv_json, send_json


class Client:
    """Interactive command-line chat client."""

    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.logger = setup_logger("client")
        self.client_certificate = Certificate.load(CLIENT_CERT_PATH)
        self.server_public_key = None
        self.shared_secret = None
        self.client_socket = None
        # The client's own signing key — matches its certificate's public key.
        self.client_key = PrivateKeyWrapper.load(CLIENT_PRIVATE_KEY_PATH).private_key
        # The CA public key, used to verify the server's certificate.
        self.ca_public_key = PrivateKeyWrapper.load(CA_PRIVATE_KEY_PATH).point

    def connect_to_server(self) -> None:
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        self.logger.info(f"Connected to server at {self.host}:{self.port}")

    def exchange_certificates(self) -> None:
        server_cert_data = recv_json(self.client_socket)
        server_certificate = Certificate.from_dict(server_cert_data)

        self.server_public_key = server_certificate.public_key()
        if not server_certificate.verify(self.ca_public_key):
            self.logger.warning("Server certificate verification failed!")
            self.client_socket.close()
            sys.exit(1)

        self.logger.info("Server certificate verified.")
        send_json(self.client_socket, self.client_certificate.to_dict())

        data = recv_json(self.client_socket)
        if not verify_message(self.server_public_key, data):
            self.logger.warning("Server message verification failed!")
            self.client_socket.close()
            return
        server_key_generated = int(data["message"])

        kx = KeyExchange()
        key_generated = kx.public_component()
        send_json(self.client_socket, create_signed_message(self.client_key, key_generated))

        self.shared_secret = kx.derive_shared(server_key_generated)
        self.logger.info("Shared secret established with server.")

    def _receive_loop(self) -> None:
        try:
            while True:
                response = recv_json(self.client_socket)
                if not response:
                    break
                if not verify_message(self.server_public_key, response):
                    self.logger.warning("Server message verification failed!")
                    self.client_socket.close()
                    return
                decrypted_bytes = xor_encrypt_decrypt(response["message"], str(self.shared_secret))
                self.logger.info(decrypted_bytes.decode(errors="ignore"))
        except Exception as e:
            self.logger.exception(f"Error receiving message: {e}")

    def send_receive_messages(self) -> None:
        threading.Thread(target=self._receive_loop, daemon=True).start()
        try:
            while True:
                message = input("> ")
                if message.lower() == "exit":
                    break
                encrypted_bytes = xor_encrypt_decrypt(message, str(self.shared_secret))
                encrypted_message = encrypted_bytes.decode(errors="ignore")
                send_json(self.client_socket, create_signed_message(self.client_key, encrypted_message))
        except (EOFError, KeyboardInterrupt):
            pass
        except Exception as e:
            self.logger.exception(f"Error: {e}")
        finally:
            self.logger.info("Disconnected from server")
            self.client_socket.close()

    def start(self) -> None:
        self.connect_to_server()
        self.exchange_certificates()
        self.send_receive_messages()


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
