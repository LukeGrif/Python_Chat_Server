"""
Filename: encryption_utils.py
Author: Luke Griffin
Description:
    Provides cryptographic functions for RSA encryption/decryption, AES session key generation,
    AES encryption/decryption, and HMAC computation/verification.
    Ensures confidentiality and integrity during secure messaging.
Date: 2025-04-07
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_aes_key():
    return os.urandom(32)  # 256-bit AES


def encrypt_aes(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def decrypt_aes(key, ciphertext):
    iv, content = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(content) + decryptor.finalize()


def encrypt_rsa(public_key, data):
    return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(), label=None))


def decrypt_rsa(private_key, data):
    return private_key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))


def compute_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(key, message, mac):
    return hmac.compare_digest(compute_hmac(key, message), mac)
