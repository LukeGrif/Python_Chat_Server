"""
Filename: cert_utils.py
Author: Luke Griffin
Description:
    Handles key pair generation and certificate creation for X.509-based authentication.
    Implements certificate generation, serialization, and parsing utilities.
Requirements Addressed:
    Requirement 2: Each entity (A, B, C, S) has a Public Key Certificate.
    Requirement 4: Each entity must authenticate to the server using its certificate.
Date: 2025-04-07
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime


def generate_keypair():
    """
    Generates an RSA private-public key pair.
    Returns:
        private_key: The private RSA key
        public_key: The associated public key
    Implements:
        Requirement 2: Part of certificate creation needed for encryption/authentication.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def generate_certificate(name: str, pubkey, signer_name: str, signer_private_key):
    """
    Creates a self-signed X.509 certificate for the given entity using the provided signer.
    Args:
        name (str): Name of the certificate subject
        pubkey: The public key to be embedded in the certificate
        signer_name (str): Signer name
        signer_private_key: Signer's private key to sign the certificate
    Returns:
        x509.Certificate: The generated certificate
    Implements:
        Requirement 2: Each entity has a certificate.
        Requirement 4: Authentication by cert submission.
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, signer_name)]))
        .public_key(pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(signer_private_key, hashes.SHA256())
    )
    return cert


def serialize_cert(cert):
    """
    Converts a certificate object to encoded bytes for transmission/storage.
    Args:
        cert (x509.Certificate): The certificate object to serialize
    Returns:
        bytes: encoded certificate
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert(pem_data):
    """
    Parses a PEM-encoded certificate into a usable certificate object.
    Args:
        pem_data (bytes): PEM-encoded certificate bytes
    Returns:
        x509.Certificate: Parsed certificate object
    """
    return x509.load_pem_x509_certificate(pem_data)
