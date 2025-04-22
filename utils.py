# utils.py

"""
Filename: utils.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Crypto helpers for secure group chat:
      • AES-CBC w/ PKCS#7 padding
      • HMAC‑SHA256 digest & verify
      • RSA certificates: CA creation, issue, save/load
      • KEY_SHARE, CHAT constants
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

# -------------------------------------------------------------------
# Message‑type markers
KEY_SHARE = 'KEY_SHARE'
CHAT      = 'CHAT'
# -------------------------------------------------------------------

def aes_encrypt(msg, key):
    """
    AES‑CBC encrypt with manual PKCS#7 padding:
      1) Generate 16‑byte IV.
      2) Pad so len % 16 == 0.
      3) Encrypt and return (iv, ciphertext).
    """
    iv = os.urandom(16)
    pad_len = 16 - (len(msg) % 16)
    padded  = msg + bytes([pad_len]) * pad_len
    cipher  = Cipher(algorithms.AES(key), modes.CBC(iv))
    ct      = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return iv, ct

def aes_decrypt(iv, ct, key):
    """
    AES‑CBC decrypt & strip PKCS#7 padding:
      1) Decrypt with same IV + key.
      2) Read last byte → pad length.
      3) Strip that many bytes off the end.
    """
    cipher   = Cipher(algorithms.AES(key), modes.CBC(iv))
    padded   = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    pad_len  = padded[-1]
    return padded[:-pad_len]

def hmac_digest(key, data):
    """
    Compute an HMAC‑SHA256 tag over data.
    Returns the raw tag bytes for later verification.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_verify(key, data, tag):
    """
    Safely verify HMAC‑SHA256 tag.
    Returns True if it matches, False on any error.
    """
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except:
        return False

def generate_cert(common_name, ca_key, ca_cert):
    """
    Create a new RSA key and X.509 certificate:
      • subject CN=common_name
      • issued by ca_cert
      • valid 1 year
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([ x509.NameAttribute(NameOID.COMMON_NAME, common_name) ])
    cert = (x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert

def save_certs(certs):
    """Pickle the full dict of keys & certs to disk."""
    with open('certs.pkl', 'wb') as f:
        pickle.dump(certs, f)

def load_certs():
    """Unpickle and return the cert/key store; errors if missing."""
    with open('certs.pkl', 'rb') as f:
        return pickle.load(f)

def build_ca():
    """
    Generate a self‑signed CA certificate:
      1) New RSA key.
      2) CN=TestCA for both subject & issuer.
      3) Sign certificate with itself.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name   = x509.Name([ x509.NameAttribute(NameOID.COMMON_NAME, 'TestCA') ])
    ca_cert= (x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert
