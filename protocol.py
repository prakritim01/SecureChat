# protocol.py
import json
from crypto_utils import b64_encode, b64_decode

def create_handshake_message(username, public_key_pem):
    """Creates a JSON message for the public key handshake."""
    return json.dumps({
        "type": "handshake_pubkey",
        "from": username,
        "pubkey": b64_encode(public_key_pem)
    }).encode('utf-8')

def create_encrypted_message(username, nonce, ciphertext, tag, seq_num):
    """Creates a JSON message for an encrypted data payload."""
    return json.dumps({
        "type": "encrypted_msg",
        "from": username,
        "seq": seq_num, # Added sequence number
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
        "tag": b64_encode(tag)
    }).encode('utf-8')

def parse_message(json_bytes):
    """Parses a JSON message and decodes base64 fields if necessary."""
    try:
        message = json.loads(json_bytes.decode('utf-8'))
        msg_type = message.get("type")

        if msg_type == "handshake_pubkey":
            message["pubkey"] = b64_decode(message["pubkey"])
        elif msg_type == "encrypted_msg":
            # We now also expect a sequence number
            if "seq" not in message or not isinstance(message["seq"], int):
                return None # Malformed message
            
            message["nonce"] = b64_decode(message["nonce"])
            message["ciphertext"] = b64_decode(message["ciphertext"])
            message["tag"] = b64_decode(message["tag"])
            
        return message
    except (json.JSONDecodeError, KeyError, TypeError):
        return None # Return None if message is malformed