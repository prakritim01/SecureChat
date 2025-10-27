# SecureChat Design Document

## 1. Threat Model

This section defines the assets we are protecting, the capabilities of our assumed adversary, and our core assumptions.

### Assets to Protect
- **Message Confidentiality**: The content of messages must be unreadable to any third party.
- **Message Integrity**: Messages cannot be altered in transit without detection.
- **Message Authenticity**: A client must be able to verify that a message was sent by the claimed sender.

### Adversary Model
We assume a network adversary (Man-in-the-Middle) with the following capabilities:
- **Eavesdrop**: The adversary can read all traffic between the clients and the server.
- **Modify**: The adversary can alter, inject, or delete messages in transit.
- **Relay**: The adversary can control the entire network, acting as a relay for all communication.

### Assumptions
- **Untrusted Server**: The server is considered part of the untrusted network. It faithfully relays messages but may be compromised or malicious, meaning it could inspect, log, or modify traffic if it were not encrypted.
- **Trusted Clients**: The client software and the operating systems they run on are assumed to be secure and not compromised.
- **Secure Primitives**: The underlying cryptographic algorithms (AES, ECDH, SHA-256) are assumed to be secure and correctly implemented by the `cryptography` library.

---

## 2. Security Goals & Non-Goals

### Security Goals
1.  **Confidentiality**: Only the intended recipient can read a message.
2.  **Integrity**: Any modification to a message during transit must be detectable.
3.  **Authentication**: Users can verify the identity of their communication partner (to prevent MitM attacks).
4.  **Replay Protection**: An adversary cannot successfully resend an old, captured message.

### Non-Goals
- **Anonymity**: This protocol does not hide the identities or IP addresses of the participants from the server or a network adversary.
- **Denial-of-Service (DoS) Protection**: The protocol does not aim to prevent an adversary from disrupting the service (e.g., by dropping all packets).
- **Metadata Protection**: The server and a network adversary can see who is talking to whom and when, just not *what* they are saying.

---

## 3. Cryptographic Primitives

- **Key Exchange**: **Elliptic Curve Diffie-Hellman (ECDH)** using the **`secp256r1`** curve. This provides a shared secret over an insecure channel.
- **Key Derivation**: **HKDF (HMAC-based Key Derivation Function)** with **SHA-256**. This will be used to derive a strong 256-bit AES key from the ECDH shared secret.
- **Symmetric Cipher**: **AES-256 in GCM (Galois/Counter Mode)**. This is an Authenticated Encryption with Associated Data (AEAD) mode, providing both confidentiality and integrity in one primitive.
- **Identity Verification**: **Public Key Fingerprints**. We will display a SHA-256 hash of each user's public key for manual, out-of-band verification.

---

## 4. Protocol Flow

The communication will proceed in two main stages:

1.  **Handshake / Key Exchange Stage**:
    - Client A and Client B connect to the server.
    - The server pairs them and instructs them to begin the handshake.
    - Client A generates an ephemeral ECDH key pair (`privA`, `pubA`).
    - Client A sends its public key, `pubA`, to the server, which forwards it to Client B.
    - Client B receives `pubA`, generates its own ephemeral ECDH key pair (`privB`, `pubB`), and sends `pubB` to Client A via the server.
    - Both clients display a **fingerprint** of the public key they received for manual verification.
    - Client A computes the shared secret: `S = ECDH(privA, pubB)`.
    - Client B computes the same shared secret: `S = ECDH(privB, pubA)`.
    - Both clients use HKDF to derive the symmetric session key: `session_key = HKDF(S)`.

2.  **Secure Communication Stage**:
    - For every message, the sender (e.g., Client A) generates a unique **nonce**.
    - Client A encrypts the plaintext message using AES-256-GCM with the `session_key` and the nonce. This produces the **ciphertext** and an **authentication tag**.
    - Client A sends a JSON object containing the `{nonce, ciphertext, tag, seq_num}` to the server.
    - The server relays the JSON object to Client B without inspecting its contents.
    - Client B receives the JSON, uses the `session_key`, nonce, ciphertext, and tag to decrypt the message. The decryption will fail if the ciphertext or tag was tampered with.
    - Client B also verifies the **sequence number (`seq_num`)** to prevent replay attacks.

---

## 5. Message Formats (JSON)

We will use simple JSON objects to structure our messages. All binary data (keys, nonces, ciphertext, tags) will be **Base64 encoded** for safe transport.

### Handshake Message
```json
{
  "type": "handshake_pubkey",
  "from": "alice",
  "pubkey": "BASE64_ENCODED_PUBLIC_KEY"
}
```

### Encrypted Data Message
```json
{
  "type": "encrypted_msg",
  "from": "alice",
  "seq": 1,
  "nonce": "BASE64_ENCODED_NONCE",
  "ciphertext": "BASE64_ENCODED_CIPHERTEXT",
  "tag": "BASE64_ENCODED_GCM_TAG"
}
```