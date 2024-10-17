import os
import random
import string
import hashlib
from datetime import datetime
import streamlit as st
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
        return f"Erro: {str(e)}"

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
    return file_name

# Função para salvar senha gerada em arquivo YAML
def save_password_to_file(password: str):
    file_name = f"password_{hashlib.sha256(password.encode()).hexdigest()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    with open(file_name, 'w') as file:
        data = {
            "password": password,
            "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        yaml.dump(data, file)
    return file_name

# Interface do aplicativo Streamlit
st.title("Encryptor/Decryptor - v1.1")

# Campo de senha
password = st.text_input("Senha 🔑:", type="password")

# Gerador de senha
st.subheader("Gerador de Senha 🎲")
length = st.number_input("Comprimento da Senha:", min_value=1, max_value=128, value=64)
use_upper = st.checkbox("Letras Maiúsculas", value=True)
use_lower = st.checkbox("Letras Minúsculas", value=True)
use_digits = st.checkbox("Números", value=True)
use_symbols = st.checkbox("Símbolos", value=True)

# Variável de sessão para armazenar a senha gerada
if 'generated_password' not in st.session_state:
    st.session_state.generated_password = ''

if st.button("Gerar Senha 🔑"):
    generated_password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
    st.session_state.generated_password = generated_password
    st.text_input("Senha Gerada:", value=generated_password, key="generated_password_output", disabled=True)
    # Preencher automaticamente o campo de senha com a senha gerada
    password = generated_password  # Atualiza a variável local com a senha gerada
    st.text_input("Senha 🔑:", value=password, type="password", key="password_input")

# Campo de mensagem (unificado)
message_input = st.text_area("Mensagem (Digite ou cole aqui):")
output_message = st.empty()

# Botões de criptografia e descriptografar
if st.button("Criptografar 🔒"):
    if password and message_input:
        encrypted_message = encrypt_message(password, message_input)
        output_message.text_area("Mensagem Criptografada:", value=encrypted_message, height=300, key="encrypted_output")
    else:
        st.error("Por favor, insira uma senha e uma mensagem.")

if st.button("Descriptografar 🔓"):
    if password and message_input:
        decrypted_message = decrypt_message(password, message_input)
        output_message.text_area("Mensagem Descriptografada:", value=decrypted_message, height=300, key="decrypted_output")
    else:
        st.error("Por favor, insira uma senha e a mensagem criptografada.")

# Botões de salvamento
if st.button("Salvar Mensagem 💾"):
    encrypted_message = output_message.text_area("Mensagem Criptografada:")
    if encrypted_message:
        file_name = save_message_to_file(encrypted_message)
        st.success(f"Mensagem criptografada salva como {file_name}.")
    else:
        st.warning("Nada para salvar.")

if st.button("Salvar Senha 💾"):
    password_to_save = st.session_state.get("generated_password")
    if password_to_save:
        file_name = save_password_to_file(password_to_save)
        st.success(f"Senha salva como {file_name}.")
    else:
        st.warning("Nada para salvar.")
