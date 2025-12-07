import socket
import json
import hashlib
import ast
import threading
import random
from config import HOST, PORT, RECV_BYTES, CLIENT_PRIVATE_KEY_INT, P_FIELD, G_GENERATOR_NUM, XOR_ENCODING
from utils import xor_encrypt_decrypt, create_signed_message, verify_message
from certificate_authority import *
from ecc import *

client_key = CLIENT_PRIVATE_KEY_INT
server_public_key = ''

def verify_message(pub_key: S256Point, message_data: dict):
    z = hash_message(message_data['message'])
    sig = Signature(message_data['r'], message_data['s'])
    return pub_key.verify(z, sig)


def xor_encrypt_decrypt(data, key):
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()

    key_length = len(key)
    return bytes([data[i] ^ key[i % key_length] for i in range(len(data))])

def hash_message(msg):
    if isinstance(msg, int):
        msg_bytes = msg.to_bytes(32, 'big')
    elif isinstance(msg, str):
        msg_bytes = msg.encode()
    else:
        raise TypeError("Message must be int or str")
    return int.from_bytes(hashlib.sha256(msg_bytes).digest(), 'big')

def create_signed_message(private_key: PrivateKey, message: str):
    z = hash_message(message)
    signature = private_key.sign(z)
    return {'message': message, 'r': signature.r, 's': signature.s}


class Client:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.cert_authority = CertificateAuthority()
        self.client_private_key_wrapper = self.cert_authority.get_private_key_wrapper()
        self.client_certificate = Certificate.load('client_certificate.pem')

    def connect_to_server(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))
        print(f"[+] Connected to server at {self.host}:{self.port}")

    def exchange_certificates(self):
        global server_public_key
        server_cert_data = json.loads(self.client_socket.recv(RECV_BYTES).decode())
        server_certificate = Certificate(
            server_cert_data['cert_data'],
            Signature(
                r=eval(server_cert_data['signature']['r']),
                s=eval(server_cert_data['signature']['s'])
            )
        )

        ca_private_key = PrivateKeyWrapper.load('ca_private.pem')

        server_public_key = S256Point(
            eval(server_cert_data['cert_data']['public_key_x']),
            eval(server_cert_data['cert_data']['public_key_y'])
        )
        if not server_certificate.verify(ca_private_key.point):
            print("[-] Server certificate verification failed!")
            self.client_socket.close()
            exit(1)

        print("[+] Server certificate verified.")

        self.client_socket.send(self.client_certificate.cert_bytes())


        data_raw = self.client_socket.recv(RECV_BYTES)
        data = ast.literal_eval(data_raw.decode())
        if not verify_message(server_public_key, data):
            print("[-] Server message verification failed!")
            self.client_socket.close()
            return
        server_key_generated = data['message']

        p = P_FIELD
        G_num = G_GENERATOR_NUM
        encryption_private_key = random.randint(1, p - 1)
        key_generated = pow(G_num, encryption_private_key, p)

        self.client_socket.send(str(create_signed_message(PrivateKey(client_key), key_generated)).encode())

        self.shared_secret = pow(server_key_generated, encryption_private_key, p)

        print("[+] Shared secret established with server.")


    def send_receive_messages(self):
        def receive_messages():
            try:
                while True:
                    response = self.client_socket.recv(RECV_BYTES)
                    if not response:
                        break

                    parsed = ast.literal_eval(response.decode())
                    if not verify_message(server_public_key, parsed):
                        print("[-] Server message verification failed!")
                        self.client_socket.close()
                        return

                    decrypted_bytes = xor_encrypt_decrypt(parsed['message'], str(self.shared_secret))
                    decrypted_message = decrypted_bytes.decode(errors=XOR_ENCODING)
                    print(decrypted_message)
            except Exception as e:
                print(f"[!] Error receiving message: {e}")

        threading.Thread(target=receive_messages, daemon=True).start()

        try:
            while True:
                message = input('> ')
                if message.lower() == 'exit':
                    break

                encrypted_bytes = xor_encrypt_decrypt(message, str(self.shared_secret))
                encrypted_message = encrypted_bytes.decode(errors=XOR_ENCODING)
                self.client_socket.send(str(create_signed_message(PrivateKey(client_key), encrypted_message)).encode())

        except Exception as e:
            print(f"[!] Error: {e}")

        finally:
            print("[+] Disconnected from server")
            self.client_socket.close()

    def start(self):
        self.connect_to_server()
        self.exchange_certificates()
        self.send_receive_messages()


if __name__ == '__main__':
    client = Client()
    client.start()
