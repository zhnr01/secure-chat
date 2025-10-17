import sys
import json
import hashlib
import threading
import random
import socket

from certificate_authority import *
from ecc import *

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QLineEdit, QLabel, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

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

def verify_message(pub_key: S256Point, message_data: dict):
    z = hash_message(message_data['message'])
    sig = Signature(message_data['r'], message_data['s'])
    return pub_key.verify(z, sig)

class Communicator(QObject):
    message_received = pyqtSignal(str)

class ChatClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat Client")
        self.setGeometry(100, 100, 700, 500)

        self.comm = Communicator()
        self.comm.message_received.connect(self.display_message)

        self.client_key = 31580641622067585352553732580425217898746542081770544368011967812312526351079
        self.server_public_key = None
        self.shared_secret = None

        self.cert_authority = CertificateAuthority()
        self.client_private_key_wrapper = self.cert_authority.get_private_key_wrapper()
        self.client_certificate = Certificate.load('client_certificate.pem')
        self.client_socket = None

        self.init_ui()

    def init_ui(self):
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        self.message_input.returnPressed.connect(self.send_message)

        self.send_button = QPushButton("Send")
        self.connect_button = QPushButton("Connect to Server")

        self.send_button.clicked.connect(self.send_message)
        self.connect_button.clicked.connect(self.start_connection)

        # Layouts
        top_bar = QHBoxLayout()
        lock_label = QLabel("🔒 Secure")
        lock_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 16px;
                border: 2px solid red;
                border-radius: 10px;
                padding: 5px;
            }
        """)
        top_bar.addStretch()
        top_bar.addWidget(lock_label)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.send_button)
        bottom_layout.addWidget(self.connect_button)

        layout = QVBoxLayout()
        layout.addLayout(top_bar)
        layout.addWidget(self.chat_area)
        layout.addWidget(self.message_input)
        layout.addLayout(bottom_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #ffffff;
            }
            QTextEdit, QLineEdit {
                background-color: #2e2e2e;
                color: #ffffff;
                border: 1px solid #555;
                padding: 5px;
            }
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #f8f8f2;
            }
            QPushButton {
                background-color: #1e1e1e;
                color: white;
                padding: 8px;
                border-radius: 5px;
                font-weight: bold;
                border: 2px solid red;
            }
        """)

    def start_connection(self):
        threading.Thread(target=self.handle_connection, daemon=True).start()

    def handle_connection(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 8080))
            self.chat_area.append("[+] Connected to server.")

            # Certificate exchange
            server_cert_data = json.loads(self.client_socket.recv(5000).decode())
            server_certificate = Certificate(
                server_cert_data['cert_data'],
                Signature(
                    r=eval(server_cert_data['signature']['r']),
                    s=eval(server_cert_data['signature']['s'])
                )
            )
            ca_private_key = PrivateKeyWrapper.load('ca_private.pem')
            self.server_public_key = S256Point(
                eval(server_cert_data['cert_data']['public_key_x']),
                eval(server_cert_data['cert_data']['public_key_y'])
            )

            if not server_certificate.verify(ca_private_key.point):
                self.show_error("Server certificate verification failed!")
                return
            self.chat_area.append("[+] Server certificate verified.")
            self.client_socket.send(self.client_certificate.cert_bytes())

            data = eval(self.client_socket.recv(5000).decode())
            if not verify_message(self.server_public_key, data):
                self.show_error("Server message verification failed!")
                return

            server_key_generated = data['message']
            p = 2**256 - 2**32 - 977
            G = FieldElement(20039604507154726964694453930606668883942751177735706227159751703972799940977, p)
            encryption_private_key = FieldElement(random.randint(1, p - 1), p)
            key_generated = pow(G.num, encryption_private_key.num, p)

            self.client_socket.send(str(create_signed_message(PrivateKey(self.client_key), key_generated)).encode())
            self.shared_secret = pow(server_key_generated, encryption_private_key.num, p)
            self.chat_area.append("[+] Shared secret established.")

            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            self.show_error(f"[!] Connection error: {e}")

    def receive_messages(self):
        try:
            while True:
                response = self.client_socket.recv(2048)
                if not response:
                    break
                data = eval(response.decode())
                if not verify_message(self.server_public_key, data):
                    self.show_error("Invalid signature in received message.")
                    continue
                decrypted = xor_encrypt_decrypt(data['message'], str(self.shared_secret)).decode()
                self.comm.message_received.emit(f"{decrypted}")
        except Exception as e:
            self.show_error(f"[!] Error receiving message: {e}")

    def send_message(self):
        try:
            message = self.message_input.text().strip()
            if not message:
                return
            self.message_input.clear()
            encrypted = xor_encrypt_decrypt(message, str(self.shared_secret)).decode()
            signed = create_signed_message(PrivateKey(self.client_key), encrypted)
            self.client_socket.send(str(signed).encode())
            self.chat_area.append(f"[You]: {message}")
        except Exception as e:
            self.show_error(f"[!] Error sending message: {e}")

    def display_message(self, message):
        self.chat_area.append(message)

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.chat_area.append(f"[ERROR]: {message}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = ChatClient()
    client.show()
    sys.exit(app.exec_())
