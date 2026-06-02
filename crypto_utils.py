# crypto_utils.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM uses a 256-bit key
AES_KEY_SIZE = 32
# GCM standard recommends a 96-bit (12-byte) nonce for efficiency and security
NONCE_SIZE = 12

def encrypt_aes_gcm(plaintext, key, aad=None):
    """
    Encrypts plaintext using AES-256-GCM with Authenticated Additional Data (AAD).

    Args:
        plaintext (bytes): The data to encrypt.
        key (bytes): The 256-bit (32-byte) encryption key.
        aad (bytes, optional): Authenticated Additional Data (e.g., sequence numbers).

    Returns:
        A tuple of (nonce, combined_ciphertext) as bytes.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes for AES-256")

    # A nonce (number used once) is critical for GCM's security.
    # It must NEVER be reused with the same key. os.urandom is a secure source.
    nonce = os.urandom(NONCE_SIZE)
    
    aesgcm = AESGCM(key)
    
    # Pass AAD to bind metadata (like sequence numbers) to this specific ciphertext.
    # The cryptography library automatically appends the 16-byte authentication tag 
    # to the end of the ciphertext, creating a single unified byte string.
    combined_ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce, combined_ciphertext


def decrypt_aes_gcm(nonce, combined_ciphertext, key, aad=None):
    """
    Decrypts ciphertext using AES-256-GCM, verifying the AAD.

    Args:
        nonce (bytes): The nonce that was used for encryption.
        combined_ciphertext (bytes): The encrypted data with the appended auth tag.
        key (bytes): The 256-bit (32-byte) encryption key.
        aad (bytes, optional): Authenticated Additional Data used during encryption.

    Returns:
        The decrypted plaintext (bytes).
    
    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (tampering detected).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes for AES-256")
    
    aesgcm = AESGCM(key)

    # Decryption will fail with an InvalidTag exception if the key is wrong,
    # the nonce is wrong, the data/tag was tampered with, or the AAD doesn't match.
    plaintext = aesgcm.decrypt(nonce, combined_ciphertext, aad)
    return plaintext

# --- Helper functions for network transmission ---

def b64_encode(data):
    """Encodes bytes to a URL-safe Base64 string."""
    return base64.urlsafe_b64encode(data).decode('utf-8')

def b64_decode(encoded_str):
    """Decodes a URL-safe Base64 string back to bytes."""
    return base64.urlsafe_b64decode(encoded_str.encode('utf-8'))