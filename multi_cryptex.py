#!/usr/bin/env python3

import base64
import os
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT = b'\xfa\xda\x1d\x7c\xab\x15\xdb\xd8\x2d\x15\x17\x72\x8a\x4a\xba\x3f'

def generate_key(password):
    password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def is_encrypted(file_path):
    with open(file_path, 'rb') as f:
        first_line = f.readline()
        return first_line.startswith(b"gAAAAA")

def encrypt(file_path):
    try:
        f = Fernet(key)
        with open(file_path, 'rb') as f_in:
            data = f_in.read()
        encrypted_data = f.encrypt(data)
        with open(file_path, 'wb') as f_out:
            f_out.write(encrypted_data)
        print(f"File {file_path} has been encrypted.")
    except Exception as e:
        print(f"Encryption error: {file_path}: {e}")

def decrypt(file_path):
    try:
        f = Fernet(key)
        with open(file_path, 'rb') as f_in:
            data = f_in.read()
        decrypted_data = f.decrypt(data)
        with open(file_path, 'wb') as f_out:
            f_out.write(decrypted_data)
        print(f"File {file_path} has been decrypted.")
    except Exception as e:
        print(f"Decription error: {file_path}: {e}")

try:
    key = generate_key(input("Enter password: "))
except Exception as e:
    print(f"Keygen error: {e}")
    sys.exit(1)

if sys.argv[1] == "enc" or sys.argv[1] == "dec":
    i = 2
else:
    i = 1

if len(sys.argv) < 2:
    print("Usage: multi_cryptex.py [enc|dec] file1 [file2 ...]")
    sys.exit(1)

for file_path in sys.argv[i:]:
    if is_encrypted(file_path) and sys.argv[1] != "enc":
        decrypt(file_path)
    elif sys.argv[1] != "dec":
        encrypt(file_path)
