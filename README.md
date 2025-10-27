# SecureChat — End-to-End Encrypted Messaging

## Objective

SecureChat is a Python-based, end-to-end encrypted (E2EE) command-line chat application. It demonstrates the implementation of a secure communication channel where a central server acts only as an untrusted relay for ciphertext. The protocol ensures message confidentiality, integrity, authenticity, and provides protection against replay attacks.

## Security Features

- **Confidentiality**: Messages are encrypted using **AES-256-GCM**, ensuring only the intended recipient can read them.
- **Integrity & Authenticity**: The use of AES-GCM's authentication tag guarantees that any message tampered with in transit will be detected and rejected.
- **Secure Key Exchange**: A shared session key is established using **Elliptic Curve Diffie-Hellman (ECDH)** over the `secp256r1` curve.
- **Man-in-the-Middle (MitM) Protection**: MitM attacks are prevented through manual, out-of-band verification of **SHA-256 public key fingerprints**.
- **Replay Protection**: Messages are tagged with a sequence number, and any message received with an old or repeated sequence number is discarded.
- **Zero-Trust Server**: The server only relays encrypted messages and has no knowledge of the session keys or plaintext content.

## Project Structure

```
SecureChat/
├── README.md
├── requirements.txt
├── server.py             # Main server for live chat
├── client.py             # Main client for live chat
├── key_exchange.py       # ECDH key exchange logic
├── crypto_utils.py       # AES-GCM encryption/decryption helpers
├── protocol.py           # JSON message formatting
├── tests/
│   ├── test_crypto.py
│   ├── test_key_exchange.py
│   └── test_integration.py
└── server_test_mode.py   # Special server for integration tests
```

## How to Run

### 1. Setup

First, set up the Python virtual environment and install dependencies.

```bash
# Create and activate the virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### 2. Run the Unit Tests (Optional)

To verify the cryptographic components are working correctly:

```bash
pytest -v
```

### 3. Run the Secure Chat

You will need three separate terminals, with the virtual environment activated in each.

**Terminal 1: Start the Server**
```bash
python server.py
```

**Terminal 2: Start Client A (Alice)**
```bash
python client.py --username alice
```

**Terminal 3: Start Client B (Bob)**
```bash
python client.py --username bob
```

After both clients connect, you will be prompted to manually verify the public key fingerprints. Check that Alice's "Peer Fingerprint" matches Bob's "Your Fingerprint", and vice-versa. Type `yes` in both clients to begin the secure chat.

### 4. Run the Security Integration Tests

To demonstrate tamper and replay protection, run the integration test suite.

**Terminal 1: Start the Test Server**
```bash
python server_test_mode.py
```

**Terminal 2: Start the Victim Client (Alice)**
```bash
python client.py --username alice
```

**Terminal 3: Start the Attacker Script**
```bash
python tests/test_integration.py
```

After starting the attacker script, you have 10 seconds to switch to Alice's terminal and type `yes` to approve the handshake. You will then see log messages in Alice's terminal demonstrating that the tampered and replayed messages were successfully rejected.