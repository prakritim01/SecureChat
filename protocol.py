# protocol.py
import json
from crypto_utils import b64_encode, b64_decode

# --- NEW LOBBY & CHAT INITIATION MESSAGES ---

def create_login_message(username):
    """(Client -> Server) First message client sends to register."""
    return json.dumps({
        "type": "login",
        "username": username
    }).encode('utf-8')

def create_user_list_message(users):
    """(Server -> Client) Broadcasts the new list of online users."""
    return json.dumps({
        "type": "user_list",
        "users": users
    }).encode('utf-8')

def create_chat_request_message(from_user, to_user):
    """(Client -> Server -> Client) Alice asks to chat with Bob."""
    return json.dumps({
        "type": "chat_request",
        "from": from_user,
        "to": to_user
    }).encode('utf-8')

def create_chat_accept_message(from_user, to_user):
    """(Client -> Server -> Client) Bob accepts Alice's chat request."""
    return json.dumps({
        "type": "chat_accept",
        "from": from_user,
        "to": to_user
    }).encode('utf-8')

def create_chat_reject_message(from_user, to_user):
    """(Client -> Server -> Client) Bob rejects Alice's chat request."""
    return json.dumps({
        "type": "chat_reject",
        "from": from_user,
        "to": to_user
    }).encode('utf-8')

def create_chat_end_message(from_user, to_user):
    """(Client -> Server -> Client) Alice tells Bob the chat is over."""
    return json.dumps({
        "type": "chat_end",
        "from": from_user,
        "to": to_user
    }).encode('utf-8')


# --- EXISTING E2EE MESSAGES ---

def create_handshake_message(username, public_key_pem):
    """(Client -> Server -> Client) Relays a public key."""
    return json.dumps({
        "type": "handshake_pubkey",
        "from": username,
        "pubkey": b64_encode(public_key_pem)
    }).encode('utf-8')

def create_encrypted_message(username, nonce, combined_ciphertext, tag, seq_num):
    """
    (Client -> Server -> Client) Relays an encrypted message.
    Note: The 'tag' parameter is kept in the function signature for backwards 
    compatibility with client.py, but is ignored because the tag is now 
    securely baked into the combined_ciphertext.
    """
    return json.dumps({
        "type": "encrypted_msg",
        "from": username,
        "seq": seq_num,
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(combined_ciphertext)
    }).encode('utf-8')

# --- PARSER (Now handles all message types) ---

def parse_message(json_bytes):
    """Parses any valid JSON message from the server or client."""
    try:
        message = json.loads(json_bytes.decode('utf-8'))
        msg_type = message.get("type")

        if not msg_type:
            return None

        # Decode base64 fields where necessary
        if msg_type == "handshake_pubkey":
            message["pubkey"] = b64_decode(message["pubkey"])
            
        elif msg_type == "encrypted_msg":
            if "seq" not in message or not isinstance(message["seq"], int):
                return None # Malformed
                
            message["nonce"] = b64_decode(message["nonce"])
            message["ciphertext"] = b64_decode(message["ciphertext"])
            
            # Safely handle the tag if an older client sends one
            if "tag" in message and message["tag"]:
                message["tag"] = b64_decode(message["tag"])
            else:
                message["tag"] = b""
                
        return message
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None # Return None if message is malformed