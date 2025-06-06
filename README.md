# 🔐 Secure Multi-Party Chat Protocol – EE6032

## 📘 Overview

This project implements a secure group communication system enabling three untrusted clients (A, B, and C) to establish a shared symmetric session key **Kabc**, used for encrypted real-time messaging. All communication is relayed through an **intermediary server**, which remains blind to message content.

The system ensures:
- End-to-end encryption between clients  
- Certificate-based authentication  
- Integrity via HMAC  
- Confidentiality using RSA & AES  

**Contributors:**
- Luke Griffin – Socket Implementation, Protocol Integration  
- Aaron Smith – GUI (PySide6)  
- Adam Jarvis – Encryption (RSA, AES, HMAC), Video  
- Nahid Islam – Protocol Design, Documentation, Video  

---

## 🧠 Problem Statement

The goal is to design and implement a secure communication protocol where:
- Clients **do not communicate directly**
- A **shared session key (Kabc)** is established securely
- The **server cannot read or alter** any client messages
- All parties are authenticated via **X.509 certificates**
- **Integrity, confidentiality, and authentication** are ensured end-to-end

![image](https://github.com/user-attachments/assets/b2d47ab9-63e9-4123-9656-78222e655114)

**🖼️ High-level system diagram showing A, B, C ↔ Server**

---

## 🔒 Protocol Design

The protocol is divided into three main phases:

---

### 🔐 Phase 1: Certificate-Based Authentication

Each client uses an RSA key pair and an X.509 certificate to authenticate to the server.

**Steps:**
- Clients sign a nonce and timestamp using their private key
- Server validates:
  - Certificate via CA's public key
  - Signature on nonce/timestamp
  - Timestamp freshness to prevent replay attacks

**Algorithms Used:**
- RSA 2048-bit  
- X.509 Certificates  
- SHA-256 / RSA-PKCS1v15  
- Nonce + Timestamp validation  

**Security Guarantees:**
- Identity verification  
- Replay attack prevention  
- Trust via digital certificates  

---

### 🔑 Phase 2: Session Key Agreement via Encrypted Shares

Each client contributes a 16-byte key share. Final session key `Kabc = S_A ⊕ S_B ⊕ S_C`

**Steps:**
1. Clients request and validate each other's certificates
2. Each generates a share and encrypts it for the other two using their public keys
3. Shares are routed via server but remain encrypted
4. Each client computes final key via XOR of three shares

**Algorithms Used:**
- RSA-OAEP with SHA-256  
- XOR for key aggregation  

**Security Guarantees:**
- Mutual contribution to key  
- Server cannot learn the key  
- End-to-end confidentiality established  

---

### 💬 Phase 3: Secure Chat Messaging

Once `Kabc` is known:
- Messages are AES-256 encrypted with CBC mode
- An HMAC-SHA256 is generated for integrity
- Messages are sent through server, which cannot decrypt them

**Message Format:**
- IV || AES-CBC Ciphertext  
- HMAC = HMAC_SHA256(Kabc, IV + Ciphertext)

**Security Guarantees:**
- Confidentiality via AES  
- Integrity via HMAC  
- Server cannot forge, modify, or read messages  

---

## 🧪 Implementation Notes

- Language: Python  
- GUI: PySide6 (Qt)  
- Communication: Socket programming over `127.0.0.1`  
- All messages are logged securely; tampered messages are discarded

---

## 🧑‍💻 Team Roles

| Name         | ID        | Contribution                                |
|--------------|-----------|---------------------------------------------|
| Luke Griffin | 21334528  | Socket architecture, protocol integration   |
| Aaron Smith  | 21335168  | PySide6 GUI development                     |
| Adam Jarvis  | 21339767  | RSA/AES/HMAC logic, scripting video demo    |
| Nahid Islam  | 21337063  | Protocol logic, video scripting, report     |

---

## ✅ Conclusion

This project delivers a robust, secure group messaging protocol with:
- Strong client authentication  
- Encrypted group key establishment  
- End-to-end confidentiality and integrity  
- Modular Python implementation

The server acts purely as a relay and **never has access to private data**. The system is extensible to more clients or asymmetric trust models with minor protocol adaptations.

---

## 📎 References

1. RFC 5280 – Internet X.509 Public Key Infrastructure Certificate  
2. RFC 8017 – PKCS #1: RSA Cryptography  
3. NIST FIPS 197 – Advanced Encryption Standard (AES)  
4. Python `cryptography` and `socket` libraries documentation  
