import socket
import threading
import json
import argparse
from config import HOST, PORT, BACKLOG, SERVER_PRIVATE_KEY_INT, XOR_ENCODING
from utils import xor_encrypt_decrypt, create_signed_message, verify_message, parse_certificate_bytes, reconstruct_certificate
from messages import SignedMessage
from protocol import send_json, recv_json
from key_exchange import KeyExchange
from certificate_authority import *
from ecc import *
from logging_util import setup_logger

server_key = SERVER_PRIVATE_KEY_INT

connected_clients = []


class Server:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.logger = setup_logger("server")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(BACKLOG)

        self.cert_authority = CertificateAuthority()
        self.server_private_key_wrapper = self.cert_authority.get_private_key_wrapper()
        self.server_certificate = Certificate.load('server_certificate.pem')

        self.logger.info(f"Server started on {self.host}:{self.port}")

    def broadcast(self, sender_socket, message):
        for client_socket, _, client_shared_secret in connected_clients:
            if client_socket != sender_socket:
                try:
                    encrypted_bytes = xor_encrypt_decrypt(message, str(client_shared_secret))
                    encrypted_message = encrypted_bytes.decode(errors='ignore')
                    client_socket.send(str(create_signed_message(PrivateKey(server_key), encrypted_message)).encode())
                except:
                    pass
    

    def handle_client(self, client_socket, client_address):
        self.logger.info(f"New connection from {client_address}")

        try:
            client_socket.send(self.server_certificate.cert_bytes())

            client_cert_data = recv_json(client_socket)
            client_certificate = reconstruct_certificate(client_cert_data)

            ca_private_key = PrivateKeyWrapper.load('ca_private.pem')
            if not client_certificate.verify(ca_private_key.point):
                self.logger.warning(f"Certificate verification failed for {client_address}")
                client_socket.close()
                return
            
            client_public_key_x = client_cert_data['cert_data']['public_key_x']
            client_public_key_y = client_cert_data['cert_data']['public_key_y']
            client_public_key = S256Point(
                eval(client_public_key_x),
                eval(client_public_key_y)
            )

            self.logger.info(f"Client {client_address} certificate verified.")

            kx = KeyExchange()
            key_generated = kx.public_component()
            encoded = create_signed_message(PrivateKey(server_key), key_generated)
            send_json(client_socket, encoded)

            data = recv_json(client_socket)

            if not verify_message(client_public_key, data):
                self.logger.warning("Client message verification failed!")
                client_socket.close()
                return
            
            shared_secret = kx.derive_shared(data['message'])
            self.logger.info(f"Shared secret established with {client_address}")

            connected_clients.append((client_socket, client_address, shared_secret))

            while True:
                encrypted_message = recv_json(client_socket)
                if not encrypted_message:
                    break
                
                parsed = encrypted_message
                if not verify_message(client_public_key, parsed):
                    self.logger.warning(f"Client {client_address} message verification failed!")
                    client_socket.close()
                    return

                decrypted_bytes = xor_encrypt_decrypt(parsed['message'], str(shared_secret))
                decrypted_message = decrypted_bytes.decode(errors=XOR_ENCODING)

                self.logger.info(f"[{client_address}] {decrypted_message}")

                broadcast_message = f"[{client_address}] {decrypted_message}"

                self.broadcast(client_socket, broadcast_message)

        except Exception as e:
            self.logger.exception(f"Error with {client_address}: {e}")

        finally:
            self.logger.info(f"Disconnected: {client_address}")
            client_socket.close()
            for idx, (sock, addr, _) in enumerate(list(connected_clients)):
                if sock == client_socket and addr == client_address:
                    connected_clients.pop(idx)
                    break

    def start(self):
        self.logger.info("Server ready for connections...")
        while True:
            client_socket, client_address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()


def parse_args():
    parser = argparse.ArgumentParser(description="Secure Chat Server")
    parser.add_argument("--host", default=HOST, help="Host to bind")
    parser.add_argument("--port", type=int, default=PORT, help="Port to listen on")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    server = Server(host=args.host, port=args.port)
    server.start()
