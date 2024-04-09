from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os

#pip install cryptography

# パスワードとソルトを設定（これらは適切に保存する必要があります）
password = b'my_password'
salt = os.urandom(16)

# キー導出関数を設定
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

# キーを導出
key = kdf.derive(password)

# 暗号化器を設定
cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
encryptor = cipher.encryptor()

# パディングを設定
padder = sym_padding.PKCS7(128).padder()

# データをパディングし、暗号化
data = b'secret_data'
padded_data = padder.update(data) + padder.finalize()
cipher_text = encryptor.update(padded_data) + encryptor.finalize()

# 復号化器を設定
cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
decryptor = cipher.decryptor()

# データを復号化し、パディングを削除
decrypted_padded_data = decryptor.update(cipher_text) + decryptor.finalize()
unpadder = sym_padding.PKCS7(128).unpadder()
decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

print(decrypted_data)  # b'secret_data'
