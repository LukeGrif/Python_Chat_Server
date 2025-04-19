"""
Filename: utils_cert.py
Author: Luke Griffin 21334538, Aaron Smith 21335168, Adam Jarvis 21339767, Nahid Islam 21337063
Description:
    Handles key pair generation and certificate creation for X.509-based authentication.
    Implements certificate generation.
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
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def generate_ca():
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )
    return ca_private_key, ca_cert


def generate_certificate(name: str, pubkey, ca_cert, ca_private_key):
    """
    Creates a self-signed X.509 certificate for the given entity using the provided signer.
    Args:
        name (str): Name of the certificate subject
        pubkey: The public key to be embedded in the certificate
        ca_cert (str): Signer name
        ca_private_key: Signer's private key to sign the certificate
    Returns:
        x509.Certificate: The generated certificate
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert


def serialize_cert(cert):
    """
    Converts a certificate object to encoded bytes for transmission/storage.
    Args:
        cert (x509.Certificate): The certificate object to serialize
    Returns:
        encoded certificate
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
