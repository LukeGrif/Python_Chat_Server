
import os
import time
from cert_utils import generate_keypair, generate_certificate
from encryption_utils import (
    generate_aes_key, encrypt_rsa, decrypt_rsa,
    compute_hmac, verify_hmac
)
from cryptography.x509.oid import NameOID

# Simulated trusted CA
CA_priv, CA_pub = generate_keypair()

# Step 1: Generate clients A, B, and C key pairs + X.509 certs signed by CA
def setup_entity(name):
    priv, pub = generate_keypair()
    cert = generate_certificate(name, pub, "CA", CA_priv)
    return {"name": name, "priv": priv, "pub": pub, "cert": cert}

A = setup_entity("A")
B = setup_entity("B")
C = setup_entity("C")

# Simulate Server S storing certs for clients
SERVER_CERT_STORE = {
    "A": A["cert"],
    "B": B["cert"],
    "C": C["cert"]
}

# Step 2: Simulate A requesting certs for B and C from server
cert_B = SERVER_CERT_STORE["B"]
cert_C = SERVER_CERT_STORE["C"]

for client in [A, B, C]:
    print(f"{client['name']}'s cert issued by CA (CommonName = {client['cert'].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value})")

# Step 3: A generates AES session key and securely sends it to B and C
Kabc = generate_aes_key()
timestamp = str(int(time.time())).encode()

def prepare_session_key_packet(sender_name, session_key, recipient_pubkey):
    payload = sender_name.encode() + b"||" + timestamp + b"||" + session_key
    hmac_value = compute_hmac(session_key, payload)
    full_packet = payload + b"||" + hmac_value
    return encrypt_rsa(recipient_pubkey, full_packet)

packet_to_B = prepare_session_key_packet("A", Kabc, B["pub"])
packet_to_C = prepare_session_key_packet("A", Kabc, C["pub"])


# Step 4: B and C decrypt + verify HMAC
def receive_session_key(packet, recipient_privkey):
    try:
        decrypted = decrypt_rsa(recipient_privkey, packet)
        parts = decrypted.split(b"||")
        sender, ts, key, received_hmac = parts[0], parts[1], parts[2], parts[3]
        verified = verify_hmac(key, b"||".join(parts[:3]), received_hmac)
        return verified, key
    except Exception as e:
        return False, None

ok_B, key_B = receive_session_key(packet_to_B, B["priv"])
ok_C, key_C = receive_session_key(packet_to_C, C["priv"])

print(f"B received Kabc: {'OK' if ok_B else 'FAIL'}")
print(f"C received Kabc: {'OK' if ok_C else 'FAIL'}")

assert key_B == Kabc and key_C == Kabc
