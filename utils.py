"""
Filename: utils.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Shared helper functions and constants for secure group chat:
    - AES-CBC encryption/decryption with PKCS7 padding
    - HMAC-SHA256 generation and verification
    - Certificate Authority (CA) and entity certificate generation
    - Message type constants (KEY_SHARE, CHAT)
    - Certificate persistence (save/load)
Date: 21-04-2025
"""

import os
import pickle
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Message type constants
KEY_SHARE = 'KEY_SHARE'
CHAT = 'CHAT'

def aes_encrypt(msg, key):
    """
    Encrypt data using AES-CBC with PKCS7 padding.

    Returns initialization vector and ciphertext.
    """
    iv = os.urandom(16)
    pad_len = 16 - (len(msg) % 16)
    padded = msg + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv, ct

def aes_decrypt(iv, ct, key):
    """
    Decrypt AES-CBC ciphertext and remove PKCS7 padding.

    Returns plaintext bytes.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len]

def hmac_digest(key, data):
    """
    Compute HMAC-SHA256 over data.

    Returns the HMAC tag.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_verify(key, data, tag):
    """
    Verify HMAC-SHA256 tag.

    Returns True if valid, False otherwise.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False

def generate_cert(common_name, ca_key, ca_cert):
    """
    Generate RSA key pair and X.509 certificate signed by the CA.

    Returns (private_key, certificate).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
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

def save_certs(certs):
    """Persist certificate/key dictionary to 'certs.pkl'."""
    with open('certs.pkl', 'wb') as f:
        pickle.dump(certs, f)

def load_certs():
    """
    Load certificate/key dictionary from 'certs.pkl'.

    Raises FileNotFoundError if the file does not exist.
    """
    with open('certs.pkl', 'rb') as f:
        return pickle.load(f)

def build_ca():
    """
    Create a self-signed CA certificate and private key.

    Returns (ca_private_key, ca_certificate).
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'TestCA')])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(cn)
        .issuer_name(cn)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert
