import socket
import json
import ast
import threading
import random
import argparse
from config import HOST, PORT, RECV_BYTES, CLIENT_PRIVATE_KEY_INT, P_FIELD, G_GENERATOR_NUM, XOR_ENCODING
from utils import xor_encrypt_decrypt, create_signed_message, verify_message, parse_certificate_bytes, reconstruct_certificate
from messages import SignedMessage
from protocol import send_json, recv_json
from key_exchange import KeyExchange
from certificate_authority import *
from ecc import *
from logging_util import setup_logger

client_key = CLIENT_PRIVATE_KEY_INT
server_public_key = ''

class Client:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.logger = setup_logger("client")
        self.cert_authority = CertificateAuthority()
        self.client_private_key_wrapper = self.cert_authority.get_private_key_wrapper()
        self.client_certificate = Certificate.load('client_certificate.pem')

    def connect_to_server(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        self.logger.info(f"Connected to server at {self.host}:{self.port}")

    def exchange_certificates(self):
        global server_public_key
        server_cert_data = recv_json(self.client_socket)
        server_certificate = reconstruct_certificate(server_cert_data)

        ca_private_key = PrivateKeyWrapper.load('ca_private.pem')

        server_public_key = S256Point(
            eval(server_cert_data['cert_data']['public_key_x']),
            eval(server_cert_data['cert_data']['public_key_y'])
        )
        if not server_certificate.verify(ca_private_key.point):
            self.logger.warning("Server certificate verification failed!")
            self.client_socket.close()
            exit(1)

        self.logger.info("Server certificate verified.")

        self.client_socket.send(self.client_certificate.cert_bytes())


        data = recv_json(self.client_socket)
        if not verify_message(server_public_key, data):
            self.logger.warning("Server message verification failed!")
            self.client_socket.close()
            return
        server_key_generated = data['message']

        kx = KeyExchange()
        key_generated = kx.public_component()

        send_json(self.client_socket, create_signed_message(PrivateKey(client_key), key_generated))

        self.shared_secret = kx.derive_shared(server_key_generated)

        self.logger.info("Shared secret established with server.")


    def send_receive_messages(self):
        def receive_messages():
            try:
                while True:
                    response = recv_json(self.client_socket)
                    if not response:
                        break

                    parsed = response
                    if not verify_message(server_public_key, parsed):
                        self.logger.warning("Server message verification failed!")
                        self.client_socket.close()
                        return

                    decrypted_bytes = xor_encrypt_decrypt(parsed['message'], str(self.shared_secret))
                    decrypted_message = decrypted_bytes.decode(errors=XOR_ENCODING)
                    self.logger.info(decrypted_message)
            except Exception as e:
                self.logger.exception(f"Error receiving message: {e}")

        threading.Thread(target=receive_messages, daemon=True).start()

        try:
            while True:
                message = input('> ')
                if message.lower() == 'exit':
                    break

                encrypted_bytes = xor_encrypt_decrypt(message, str(self.shared_secret))
                encrypted_message = encrypted_bytes.decode(errors=XOR_ENCODING)
                send_json(self.client_socket, create_signed_message(PrivateKey(client_key), encrypted_message))

        except Exception as e:
            self.logger.exception(f"Error: {e}")

        finally:
            self.logger.info("Disconnected from server")
            self.client_socket.close()

    def start(self):
        self.connect_to_server()
        self.exchange_certificates()
        self.send_receive_messages()


def parse_args():
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--host", default=HOST, help="Server host")
    parser.add_argument("--port", type=int, default=PORT, help="Server port")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    client = Client(host=args.host, port=args.port)
    client.start()
