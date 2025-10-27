# crypto_utils.py
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM uses a 256-bit key
AES_KEY_SIZE = 32
# GCM standard recommends a 96-bit (12-byte) nonce for efficiency and security
NONCE_SIZE = 12

def encrypt_aes_gcm(plaintext, key):
    """
    Encrypts plaintext using AES-256-GCM.

    Args:
        plaintext (bytes): The data to encrypt.
        key (bytes): The 256-bit (32-byte) encryption key.

    Returns:
        A tuple of (nonce, ciphertext, tag) as bytes.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes for AES-256")

    # A nonce (number used once) is critical for GCM's security.
    # It must NEVER be reused with the same key. os.urandom is a secure source.
    nonce = os.urandom(NONCE_SIZE)
    
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None) # No associated data

    # The tag is generated during encryption and is used for authentication
    # GCM's tag is typically appended to the ciphertext, but we'll handle it separately.
    # The standard tag size for GCM is 16 bytes.
    tag_start_index = len(ciphertext) - 16
    tag = ciphertext[tag_start_index:]
    actual_ciphertext = ciphertext[:tag_start_index]

    return nonce, actual_ciphertext, tag


def decrypt_aes_gcm(nonce, ciphertext, tag, key):
    """
    Decrypts ciphertext using AES-256-GCM.

    Args:
        nonce (bytes): The nonce that was used for encryption.
        ciphertext (bytes): The encrypted data.
        tag (bytes): The authentication tag.
        key (bytes): The 256-bit (32-byte) encryption key.

    Returns:
        The decrypted plaintext (bytes).
    
    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (tampering detected).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes for AES-256")
    
    aesgcm = AESGCM(key)
    
    # Combine ciphertext and tag for decryption
    combined_ciphertext = ciphertext + tag

    # Decryption will fail with an InvalidTag exception if the key is wrong,
    # the nonce is wrong, or the data/tag was tampered with.
    plaintext = aesgcm.decrypt(nonce, combined_ciphertext, None)
    return plaintext

# --- Helper functions for network transmission ---

def b64_encode(data):
    """Encodes bytes to a URL-safe Base64 string."""
    return base64.urlsafe_b64encode(data).decode('utf-8')

def b64_decode(encoded_str):
    """Decodes a URL-safe Base64 string back to bytes."""
    return base64.urlsafe_b64decode(encoded_str.encode('utf-8'))