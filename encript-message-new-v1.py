import sys
import os
import random
import string
import hashlib
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QCheckBox, QSpinBox)
from PyQt5.QtGui import QIcon
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import yaml
from os import urandom

# Função para gerar uma chave baseada na senha
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Função para criptografar a mensagem
def encrypt_message(password: str, message: str) -> str:
    salt = urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())

    # Estrutura YAML para armazenar chave e mensagem
    data = {
        "public_key": base64.b64encode(salt).decode(),
        "message": encrypted_message.decode(),
        "algorithm": "AES + Twofish + Serpent",
        "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    return yaml.dump(data)

# Função para descriptografar a mensagem
def decrypt_message(password: str, encrypted_yaml: str) -> str:
    try:
        data = yaml.safe_load(encrypted_yaml)
        salt = base64.b64decode(data["public_key"])
        encrypted_message = data["message"].encode()
        key = generate_key(password, salt)
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        return f"Error: {str(e)}"

# Função para gerar uma senha aleatória com base em critérios
def generate_password(length=64, use_upper=True, use_lower=True, use_digits=True, use_symbols=True) -> str:
    char_pool = ''
    if use_upper:
        char_pool += string.ascii_uppercase
    if use_lower:
        char_pool += string.ascii_lowercase
    if use_digits:
        char_pool += string.digits
    if use_symbols:
        char_pool += string.punctuation

    if not char_pool:
        return ''

    return ''.join(random.choice(char_pool) for _ in range(length))

# Função para salvar mensagem criptografada em arquivo YAML
def save_message_to_file(encrypted_message: str):
    file_name = f"encrypted_message_{hashlib.sha256(encrypted_message.encode()).hexdigest()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    with open(file_name, 'w') as file:
        file.write(encrypted_message)
    print(f"Mensagem criptografada salva como {file_name}")

# Função para salvar senha gerada em arquivo YAML
def save_password_to_file(password: str):
    file_name = f"password_{hashlib.sha256(password.encode()).hexdigest()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    with open(file_name, 'w') as file:
        data = {
            "password": password,
            "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        yaml.dump(data, file)
    print(f"Senha salva como {file_name}")

# Classe principal da interface gráfica
class EncryptorApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Encryptor/Decryptor - v1.1")
        self.setFixedSize(500, 700)
        self.setWindowIcon(QIcon("encrypt_icon.png"))

        # Layout principal
        layout = QVBoxLayout()

        # Campo de senha
        self.label_password = QLabel("Senha 🔑:")
        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.Password)

        # Gerador de senha
        self.label_generate_password = QLabel("Gerador de Senha 🎲:")
        self.spin_length = QSpinBox()
        self.spin_length.setValue(64)
        self.check_upper = QCheckBox("Letras Maiúsculas")
        self.check_upper.setChecked(True)
        self.check_lower = QCheckBox("Letras Minúsculas")
        self.check_lower.setChecked(True)
        self.check_digits = QCheckBox("Números")
        self.check_digits.setChecked(True)
        self.check_symbols = QCheckBox("Símbolos")
        self.check_symbols.setChecked(True)

        self.button_generate_password = QPushButton("Gerar Senha 🔑")
        self.button_generate_password.clicked.connect(self.generate_password)

        self.button_copy_password = QPushButton("Copiar Senha 📋")
        self.button_copy_password.clicked.connect(self.copy_password)

        # Campo de mensagem
        self.label_message = QLabel("Mensagem 📄:")
        self.input_message = QTextEdit()

        # Botões de criptografia e descriptografia
        self.button_encrypt = QPushButton("Criptografar 🔒")
        self.button_encrypt.clicked.connect(self.encrypt)

        self.button_decrypt = QPushButton("Descriptografar 🔓")
        self.button_decrypt.clicked.connect(self.decrypt)

        # Botões de salvamento
        self.button_save_message = QPushButton("Salvar Mensagem 💾")
        self.button_save_message.clicked.connect(self.save_message)

        self.button_save_password = QPushButton("Salvar Senha 💾")
        self.button_save_password.clicked.connect(self.save_password)

        # Caixa de saída
        self.label_output = QLabel("Saída:")
        self.output_message = QTextEdit()
        self.output_message.setReadOnly(True)

        # Adicionar elementos ao layout
        layout.addWidget(self.label_password)
        layout.addWidget(self.input_password)

        layout.addWidget(self.label_generate_password)
        layout.addWidget(self.spin_length)
        layout.addWidget(self.check_upper)
        layout.addWidget(self.check_lower)
        layout.addWidget(self.check_digits)
        layout.addWidget(self.check_symbols)
        layout.addWidget(self.button_generate_password)
        layout.addWidget(self.button_copy_password)

        layout.addWidget(self.label_message)
        layout.addWidget(self.input_message)
        layout.addWidget(self.button_encrypt)
        layout.addWidget(self.button_decrypt)

        layout.addWidget(self.button_save_message)
        layout.addWidget(self.button_save_password)

        layout.addWidget(self.label_output)
        layout.addWidget(self.output_message)

        self.setLayout(layout)

    # Função de criptografia
    def encrypt(self):
        password = self.input_password.text()
        message = self.input_message.toPlainText()

        if not password or not message:
            print("Error: Por favor, insira uma senha e uma mensagem.")
            return

        try:
            encrypted_message = encrypt_message(password, message)
            self.output_message.setPlainText(encrypted_message)
        except Exception as e:
            print(f"Falha ao criptografar: {str(e)}")

    # Função de descriptografia
    def decrypt(self):
        password = self.input_password.text()
        encrypted_yaml = self.input_message.toPlainText()

        if not password or not encrypted_yaml:
            print("Error: Por favor, insira uma senha e a mensagem criptografada.")
            return

        try:
            decrypted_message = decrypt_message(password, encrypted_yaml)
            self.output_message.setPlainText(decrypted_message)
        except Exception as e:
            print(f"Falha ao descriptografar: {str(e)}")

    # Função para gerar a senha
    def generate_password(self):
        length = self.spin_length.value()
        use_upper = self.check_upper.isChecked()
        use_lower = self.check_lower.isChecked()
        use_digits = self.check_digits.isChecked()
        use_symbols = self.check_symbols.isChecked()

        password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
        self.input_password.setText(password)

    # Função para copiar a senha para a área de transferência
    def copy_password(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.input_password.text())

    # Função para salvar mensagem criptografada
    def save_message(self):
        encrypted_message = self.output_message.toPlainText()
        if encrypted_message:
            save_message_to_file(encrypted_message)

    # Função para salvar senha
    def save_password(self):
        password = self.input_password.text()
        if password:
            save_password_to_file(password)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec_())
