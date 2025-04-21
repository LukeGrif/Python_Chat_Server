"""
Filename: server.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Shared helper functions and constants:
    AES encryption and decryption with IV
    HMAC tag generation and verification
    Certificate Authority and entity certificate generation
    Message type constants (KEY_SHARE, CHAT)
    Certificate persistence (save/load to certs.pkl)
Date: 21-04-2025
"""

import os, time, pickle
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, timedelta, timezone

# === Crypto Constants ===
KEY_SHARE = 'KEY_SHARE'
CHAT = 'CHAT'

# === AES + HMAC ===
def aes_encrypt(msg: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - len(msg) % 16
    padded = msg + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext

def aes_decrypt(iv: bytes, ct: bytes, key: bytes):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]

def hmac_digest(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        h.verify(tag)
        return True
    except:
        return False

# === Certificate Utilities ===
def generate_cert(name, ca_key, ca_cert):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert

def load_certs():
    with open("certs.pkl", "rb") as f:
        return pickle.load(f)

def save_certs(certs):
    with open("certs.pkl", "wb") as f:
        pickle.dump(certs, f)

def build_ca():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TestCA')])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert
