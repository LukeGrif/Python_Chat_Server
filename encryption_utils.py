"""
Filename: encryption_utils.py
Author: Luke Griffin
Description:
    Provides cryptographic functions for RSA encryption/decryption, AES session key generation,
    AES encryption/decryption, and HMAC computation/verification.
    Ensures confidentiality and integrity during secure messaging.
Requirements Addressed:
    Requirement 5: Integrity checks using HMAC
    Requirement 6: Uses AES for confidentiality, RSA for encryption, and HMAC-SHA256 for integrity/authentication
Date: 2025-04-07
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_aes_key():
    """
    Generates a secure random 256-bit AES key for symmetric encryption.
    Returns:
        bytes: 32-byte (256-bit) key
    Implements:
        Confidentiality for secure session key (Req 6).
    """
    return os.urandom(32)  # 256-bit AES


def encrypt_aes(key, plaintext):
    """
    Encrypts plaintext using AES in CFB mode with a random IV.
    Args:
        key (bytes): AES key
        plaintext (bytes): Data to encrypt
    Returns:
        bytes: IV + ciphertext
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def decrypt_aes(key, ciphertext):
    """
   Decrypts AES-encrypted data using the provided key.
   Args:
       key (bytes): AES key
       ciphertext (bytes): Encrypted data (IV + ciphertext)
   Returns:
       bytes: Decrypted plaintext
   """
    iv, content = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(content) + decryptor.finalize()


def encrypt_rsa(public_key, data):
    """
    Encrypts data using RSA-OAEP with SHA256 padding.
    Args:
        public_key: Receiver's public RSA key
        data (bytes): Plaintext data
    Returns:
        bytes: Encrypted output
    Implements:
        Confidentiality for key transmission (Req 6).
    """
    return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(), label=None))


def decrypt_rsa(private_key, data):
    """
    Decrypts data encrypted with RSA-OAEP.
    Args:
        private_key: Entity's private RSA key
        data: Encrypted data
    Returns:
        bytes: Decrypted plaintext
    """
    return private_key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))


def compute_hmac(key, message):
    """
    Computes HMAC-SHA256 for a given message and key.
    Args:
        key: Secret key (session key Kabc)
        message: Data to authenticate
    Returns:
        bytes: HMAC digest
    Implements:
        Integrity and authentication check (Req 5).
    """
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(key, message, mac):
    """
    Verifies that the provided HMAC is valid for the given message and key.
    Args:
        key: Shared secret
        message: Original message
        mac: HMAC to verify
    Returns:
        bool: True if MAC matches; otherwise, False
    """
    return hmac.compare_digest(compute_hmac(key, message), mac)
