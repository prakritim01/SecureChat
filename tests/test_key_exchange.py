# tests/test_key_exchange.py
import sys
import os

# This is a bit of a hack to allow the test to import from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from key_exchange import (
    generate_ecdh_key_pair,
    serialize_public_key,
    deserialize_public_key,
    create_shared_secret,
    derive_session_key,
    get_public_key_fingerprint
)

def test_full_key_exchange_and_derivation():
    """
    Simulates a full ECDH key exchange and tests if both parties
    derive the identical session key.
    """
    # 1. Alice generates her key pair
    alice_priv, alice_pub = generate_ecdh_key_pair()
    alice_pub_pem = serialize_public_key(alice_pub)

    # 2. Bob generates his key pair
    bob_priv, bob_pub = generate_ecdh_key_pair()
    bob_pub_pem = serialize_public_key(bob_pub)

    # 3. They exchange public keys
    # Alice receives Bob's public key
    received_bob_pub = deserialize_public_key(bob_pub_pem)
    
    # Bob receives Alice's public key
    received_alice_pub = deserialize_public_key(alice_pub_pem)

    # 4. Both parties generate the shared secret independently
    alice_shared_secret = create_shared_secret(alice_priv, received_bob_pub)
    bob_shared_secret = create_shared_secret(bob_priv, received_alice_pub)

    # ASSERTION 1: The raw shared secrets must be identical
    assert alice_shared_secret == bob_shared_secret

    # 5. Both parties derive the final session key from the shared secret
    alice_session_key = derive_session_key(alice_shared_secret)
    bob_session_key = derive_session_key(bob_shared_secret)

    # ASSERTION 2: The final derived session keys must be identical
    assert alice_session_key == bob_session_key
    
    # ASSERTION 3: The key must be 32 bytes (256 bits) long
    assert len(alice_session_key) == 32

    print("\n✅ Key exchange simulation successful!")
    print(f"   Alice's Key: {alice_session_key.hex()}")
    print(f"   Bob's Key:   {bob_session_key.hex()}")

def test_fingerprint_creation():
    """Tests that the fingerprint function runs and produces a valid hex digest."""
    _, pub_key = generate_ecdh_key_pair()
    pub_key_pem = serialize_public_key(pub_key)
    
    fingerprint = get_public_key_fingerprint(pub_key_pem)
    
    # ASSERTION: Fingerprint should be a 64-character hex string for SHA-256
    assert len(fingerprint) == 64
    int(fingerprint, 16) # This will raise a ValueError if it's not a valid hex string
    
    print(f"\n✅ Fingerprint generation successful: {fingerprint[:16]}...")