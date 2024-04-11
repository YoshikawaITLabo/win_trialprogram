from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import sys

def main():
    OUTP = "s:"

    #コマンドライン引数を取得
    args = sys.argv

    password = args[1].encode("utf-8")
    salt = os.urandom(16)

    OUTP += base64.b64encode(salt).decode('utf-8')
    OUTP += "\nk:"

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

    OUTP +=  base64.b64encode(key).decode('utf-8')
    OUTP += "\n"

    #ファイル出力
    f = open('salt_key.txt', 'w')
    f.write(OUTP)
    f.close()

    print("完了")

if __name__ == "__main__":
    main()