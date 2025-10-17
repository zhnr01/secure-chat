import socket
import threading
import json
import hashlib
from certificate_authority import *
from ecc import *
import random

server_key = 15868289705152457917503632020531026166612756857419825123766511006865265396897

connected_clients = []


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


class Server:
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)

        self.cert_authority = CertificateAuthority()
        self.server_private_key_wrapper = self.cert_authority.get_private_key_wrapper()
        self.server_certificate = Certificate.load('server_certificate.pem')

        print(f"[+] Server started on {self.host}:{self.port}")

    def broadcast(self, sender_socket, message):
        for client_socket, _, client_shared_secret in connected_clients:
            if client_socket != sender_socket:
                try:
                    encrypted_message = xor_encrypt_decrypt(message, str(client_shared_secret)).decode()
                    client_socket.send(str(create_signed_message(PrivateKey(server_key), encrypted_message)).encode())
                except:
                    pass
    

    def handle_client(self, client_socket, client_address):
        print(f"[+] New connection from {client_address}")

        try:
            client_socket.send(self.server_certificate.cert_bytes())

            client_cert_data = json.loads(client_socket.recv(5000).decode())
            client_certificate = Certificate(client_cert_data['cert_data'], Signature(
                r=eval(client_cert_data['signature']['r']),
                s=eval(client_cert_data['signature']['s'])
            ))

            ca_private_key = PrivateKeyWrapper.load('ca_private.pem')
            if not client_certificate.verify(ca_private_key.point):
                print(f"[-] Certificate verification failed for {client_address}")
                client_socket.close()
                return
            
            client_public_key_x = client_cert_data['cert_data']['public_key_x']
            client_public_key_y = client_cert_data['cert_data']['public_key_y']
            client_public_key = S256Point(
                eval(client_public_key_x),
                eval(client_public_key_y)
            )

            print(f"[+] Client {client_address} certificate verified.")

            p = 2**256 - 2**32 - 977
            G = FieldElement(20039604507154726964694453930606668883942751177735706227159751703972799940977, p)
            encryption_private_key = FieldElement(random.randint(1, p - 1), p)
            key_generated = pow(G.num, encryption_private_key.num, p)
            encoded_msg = create_signed_message(PrivateKey(server_key), key_generated)
            client_socket.send(str(encoded_msg).encode())

            data = eval(client_socket.recv(5000).decode())

            if not verify_message(client_public_key, data):
                print("[-] Client message verification failed!")
                client_socket.close()
                return
            
            shared_secret = pow(data['message'], encryption_private_key.num, p)
            print(f"[+] Shared secret established with {client_address}")

            connected_clients.append((client_socket, client_address, shared_secret))

            while True:
                encrypted_message = client_socket.recv(5000)
                if not encrypted_message:
                    break
                
                if not verify_message(client_public_key, eval(encrypted_message.decode())):
                    print(f"[-] Client {client_address} message verification failed!")
                    client_socket.close()
                    return

                decrypted_message = xor_encrypt_decrypt(eval(encrypted_message.decode())['message'], str(shared_secret)).decode()

                print(f"[{client_address}] {decrypted_message}")

                broadcast_message = f"[{client_address}] {decrypted_message}"

                self.broadcast(client_socket, broadcast_message)

        except Exception as e:
            print(f"[!] Error with {client_address}: {e}")

        finally:
            print(f"[-] Disconnected: {client_address}")
            client_socket.close()
            connected_clients.remove((client_socket, client_address))

    def start(self):
        print("[+] Server ready for connections...")
        while True:
            client_socket, client_address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()


if __name__ == '__main__':
    server = Server()
    server.start()
