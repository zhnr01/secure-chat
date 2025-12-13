import sys
import json
import threading
import socket

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QLineEdit, QLabel, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import pyqtSignal, QObject

from config import HOST, PORT, CLIENT_PRIVATE_KEY_INT, XOR_ENCODING
from utils import xor_encrypt_decrypt, create_signed_message, verify_message, reconstruct_certificate, extract_public_key
from protocol import send_json, recv_json
from key_exchange import KeyExchange
from certificate_authority import Certificate, PrivateKeyWrapper, CertificateAuthority
from ecc import PrivateKey


class Communicator(QObject):
    """Qt signal bridge for thread-safe UI updates."""
    message_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)


class ChatClient(QMainWindow):
    """PyQt5 GUI client for secure chat."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat Client")
        self.setGeometry(100, 100, 700, 500)

        self.comm = Communicator()
        self.comm.message_received.connect(self._display_message)
        self.comm.error_occurred.connect(self._show_error)

        self.client_key = CLIENT_PRIVATE_KEY_INT
        self.server_public_key = None
        self.shared_secret = None

        self.cert_authority = CertificateAuthority()
        self.client_certificate = Certificate.load('client_certificate.pem')
        self.client_socket = None

        self._init_ui()

    def _init_ui(self):
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type your message...")
        self.message_input.returnPressed.connect(self._send_message)

        self.send_button = QPushButton("Send")
        self.connect_button = QPushButton("Connect to Server")

        self.send_button.clicked.connect(self._send_message)
        self.connect_button.clicked.connect(self._start_connection)

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

    def _start_connection(self):
        """Start connection in background thread."""
        threading.Thread(target=self._handle_connection, daemon=True).start()

    def _handle_connection(self):
        """Perform certificate exchange and key agreement."""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((HOST, PORT))
            self.comm.message_received.emit("[+] Connected to server.")

            # Receive and verify server certificate
            server_cert_data = recv_json(self.client_socket)
            server_certificate = reconstruct_certificate(server_cert_data)

            ca_private_key = PrivateKeyWrapper.load('ca_private.pem')
            self.server_public_key = extract_public_key(server_cert_data['cert_data'])

            if not server_certificate.verify(ca_private_key.point):
                self.comm.error_occurred.emit("Server certificate verification failed!")
                return

            self.comm.message_received.emit("[+] Server certificate verified.")
            self.client_socket.send(self.client_certificate.cert_bytes())

            # DH key exchange
            data = recv_json(self.client_socket)
            if not verify_message(self.server_public_key, data):
                self.comm.error_occurred.emit("Server message verification failed!")
                return

            server_key_generated = data['message']

            kx = KeyExchange()
            key_generated = kx.public_component()

            send_json(self.client_socket, create_signed_message(PrivateKey(self.client_key), key_generated))
            self.shared_secret = kx.derive_shared(server_key_generated)
            self.comm.message_received.emit("[+] Shared secret established.")

            threading.Thread(target=self._receive_messages, daemon=True).start()
        except Exception as e:
            self.comm.error_occurred.emit(f"[!] Connection error: {e}")

    def _receive_messages(self):
        """Background thread to receive and decrypt messages."""
        try:
            while True:
                data = recv_json(self.client_socket)
                if not data:
                    break
                if not verify_message(self.server_public_key, data):
                    self.comm.error_occurred.emit("Invalid signature in received message.")
                    continue
                decrypted = xor_encrypt_decrypt(data['message'], str(self.shared_secret)).decode(errors=XOR_ENCODING)
                self.comm.message_received.emit(decrypted)
        except Exception as e:
            self.comm.error_occurred.emit(f"[!] Error receiving message: {e}")

    def _send_message(self):
        """Encrypt, sign, and send user message."""
        try:
            message = self.message_input.text().strip()
            if not message or not self.shared_secret:
                return
            self.message_input.clear()
            encrypted = xor_encrypt_decrypt(message, str(self.shared_secret)).decode(errors=XOR_ENCODING)
            signed = create_signed_message(PrivateKey(self.client_key), encrypted)
            send_json(self.client_socket, signed)
            self.chat_area.append(f"[You]: {message}")
        except Exception as e:
            self.comm.error_occurred.emit(f"[!] Error sending message: {e}")

    def _display_message(self, message: str):
        """Append message to chat area."""
        self.chat_area.append(message)

    def _show_error(self, message: str):
        """Display error in message box and chat area."""
        QMessageBox.critical(self, "Error", message)
        self.chat_area.append(f"[ERROR]: {message}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client = ChatClient()
    client.show()
    sys.exit(app.exec_())
