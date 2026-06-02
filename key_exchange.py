# key_exchange.py
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

def generate_ecdh_key_pair():
    """Generates a new ECDH private and public key pair."""
    # Using the secp256r1 curve as defined in our design
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serializes a public key to bytes for network transmission."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    """Deserializes a public key from bytes received from the network."""
    return serialization.load_pem_public_key(pem_data)

def create_shared_secret(private_key, peer_public_key):
    """Creates a shared secret using our private key and the peer's public key."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_session_key(shared_secret, my_pub_bytes, peer_pub_bytes):
    """
    Derives a 256-bit (32-byte) session key from the shared secret using HKDF.
    Mixes both public keys into the context string to prevent cross-protocol attacks.
    """
    # Sort the public keys so both Alice and Bob generate the exact same info string
    # regardless of who initiated the connection.
    context_info = b'secure-chat:' + min(my_pub_bytes, peer_pub_bytes) + max(my_pub_bytes, peer_pub_bytes)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=None,
        info=context_info,
    )
    return hkdf.derive(shared_secret)

def get_public_key_fingerprint(public_key_pem):
    """Creates a hex fingerprint of a PEM public key for manual verification."""
    # A fingerprint is a short, recognizable hash of the full public key.
    # Users can compare these fingerprints out-of-band to prevent MitM attacks.
    sha256 = hashlib.sha256()
    sha256.update(public_key_pem)
    return sha256.hexdigest()