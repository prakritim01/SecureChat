# tests/test_crypto.py
import sys
import os
import pytest
from cryptography.exceptions import InvalidTag

# Add the root project directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_utils import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    AES_KEY_SIZE
)

def test_encrypt_decrypt_roundtrip():
    """
    Tests that a message can be encrypted and then successfully decrypted
    back to its original form.
    """
    # 1. Setup
    key = os.urandom(AES_KEY_SIZE)
    plaintext = b"This is a secret message for the roundtrip test."

    # 2. Encrypt
    nonce, ciphertext, tag = encrypt_aes_gcm(plaintext, key)

    # 3. Decrypt
    decrypted_plaintext = decrypt_aes_gcm(nonce, ciphertext, tag, key)

    # 4. Assert
    assert decrypted_plaintext == plaintext
    print("\n✅ Encrypt/decrypt roundtrip successful.")

def test_tamper_detection_on_ciphertext():
    """
    Tests that decryption fails with an InvalidTag error if the
    ciphertext is modified in transit. This proves our integrity check works.
    """
    # 1. Setup
    key = os.urandom(AES_KEY_SIZE)
    plaintext = b"This message will be tampered with."
    nonce, ciphertext, tag = encrypt_aes_gcm(plaintext, key)

    # 2. Tamper with the ciphertext (flip one bit)
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0x01 # XOR the first byte with 1
    tampered_ciphertext = bytes(tampered_ciphertext)

    # 3. Assert that decryption raises the correct exception
    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(nonce, tampered_ciphertext, tag, key)
    
    print("\n✅ Ciphertext tamper detection successful.")

def test_tamper_detection_on_tag():
    """
    Tests that decryption fails if the authentication tag is modified.
    """
    # 1. Setup
    key = os.urandom(AES_KEY_SIZE)
    plaintext = b"This message's tag will be tampered with."
    nonce, ciphertext, tag = encrypt_aes_gcm(plaintext, key)
    
    # 2. Tamper with the tag
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0x01
    tampered_tag = bytes(tampered_tag)

    # 3. Assert that decryption raises the correct exception
    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(nonce, ciphertext, tampered_tag, key)

    print("\n✅ Authentication tag tamper detection successful.")