import socket
import json
import hashlib
from certificate_authority import *
from ecc import *
import threading
import random

client_key = 9957016483416681782736782534500483090238740989288695810619470189709094021823
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
    def __init__(self, host='localhost', port=8080):
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
        server_cert_data = json.loads(self.client_socket.recv(5000).decode())
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


        data = eval(self.client_socket.recv(5000).decode())
        if not verify_message(server_public_key, data):
            print("[-] Server message verification failed!")
            self.client_socket.close()
            return
        server_key_generated = data['message']

        p = 23
        G = FieldElement(5, p)
        encryption_private_key = FieldElement(random.randint(1, p - 1), p)
        key_generated = pow(G.num, encryption_private_key.num, p)

        self.client_socket.send(str(create_signed_message(PrivateKey(client_key), key_generated)).encode())

        self.shared_secret = pow(server_key_generated, encryption_private_key.num, p)

        print("[+] Shared secret established with server.")


    def send_receive_messages(self):
        def receive_messages():
            try:
                while True:
                    response = self.client_socket.recv(1024)
                    if not response:
                        break

                    if not verify_message(server_public_key, eval(response.decode())):
                        print("[-] Server message verification failed!")
                        self.client_socket.close()
                        return

                    decrypted_message = xor_encrypt_decrypt(eval(response.decode())['message'], str(self.shared_secret)).decode()
                    print(decrypted_message)
            except Exception as e:
                print(f"[!] Error receiving message: {e}")

        threading.Thread(target=receive_messages, daemon=True).start()

        try:
            while True:
                message = input('> ')
                if message.lower() == 'exit':
                    break

                encrypted_message = xor_encrypt_decrypt(message, str(self.shared_secret)).decode()
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
