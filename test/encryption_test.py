"""
Filename: encryption_test.py
Author: Luke Griffin
Description:
    Tests cryptographic functions for RSA encryption/decryption, AES session key generation,
    AES encryption/decryption, and HMAC computation/verification.
    Ensures confidentiality and integrity during secure messaging.
Date: 2025-04-07
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils_cert import generate_keypair, generate_certificate
from utils_encryption import generate_aes_key, encrypt_rsa, decrypt_rsa, compute_hmac, verify_hmac

# Step 1: Generate keys and certs
clients = {}
for name in ["A", "B", "C"]:
    priv, pub = generate_keypair()
    cert = generate_certificate(name, pub, "CA", priv)  # self-signed for simulation
    clients[name] = {
        "name": name,
        "priv": priv,
        "pub": pub,
        "cert": cert,
    }

print("\nStep 1: Mutual certificate verification (simulated)")
for client in clients.values():
    print(f"{client['name']}'s cert issued by CA")

# Step 2: Public key distribution
print("\nStep 2: Public key access (simulated — everyone has each other's certs)")

# Step 3: Generate Kabc and send to B and C
print("\nStep 3: A generates Kabc and sends to B and C (encrypted + HMAC'd)")
Kabc = generate_aes_key()
A = clients["A"]
payload = A["name"].encode() + b"||" + b"timestamp" + b"||" + Kabc
hmac = compute_hmac(Kabc, payload)

packet = payload + b"||" + hmac
encrypted_for_B = encrypt_rsa(clients["B"]["pub"], packet)
encrypted_for_C = encrypt_rsa(clients["C"]["pub"], packet)

# Step 4: B and C decrypt and verify
print("\nStep 4: B and C ACK back to A (simulated by HMAC verification)")

for target in ["B", "C"]:
    decrypted = decrypt_rsa(clients[target]["priv"], encrypted_for_B if target == "B" else encrypted_for_C)
    parts = decrypted.split(b"||")
    sender, ts, key, received_hmac = parts
    valid = verify_hmac(key, b"||".join(parts[:3]), received_hmac)
    print(f"{target} received Kabc: {'OK' if valid else 'FAIL'}")
