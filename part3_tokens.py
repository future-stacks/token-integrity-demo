import base64
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

# --- Keys: the issuer keeps the private key, the API server only gets the public key ---
issuer_private_key = Ed25519PrivateKey.generate()
server_public_key = issuer_private_key.public_key()


def b64e(data):
    return base64.urlsafe_b64encode(data).decode()


def b64d(text):
    return base64.urlsafe_b64decode(text.encode())


# --- Issuer: builds and signs a token ---
def issue_token(app_id, lifetime_seconds=30):
    payload = {
        "app_id": app_id,
        "exp": time.time() + lifetime_seconds,
        "jti": str(uuid.uuid4()),
    }
    payload_bytes = json.dumps(payload).encode()
    signature = issuer_private_key.sign(payload_bytes)
    return b64e(payload_bytes) + "." + b64e(signature)


# --- API server: checks a token ---
seen_ids = set()


def check_token(token):
    # 1. Split and decode
    try:
        payload_b64, signature_b64 = token.split(".")
        payload_bytes = b64d(payload_b64)
        signature = b64d(signature_b64)
    except ValueError:
        return "rejected: malformed"

    # 2. Verify the signature before trusting anything inside the payload
    try:
        server_public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return "rejected: bad signature"

    payload = json.loads(payload_bytes)

    # 3. Expiry
    if payload["exp"] < time.time():
        return "rejected: expired"

    # 4. Replay
    if payload["jti"] in seen_ids:
        return "rejected: replay"
    seen_ids.add(payload["jti"])

    return "accepted (app_id=" + payload["app_id"] + ")"


# --- Demo ---

# 1. A fresh token is accepted
token = issue_token("genuine-app")
print("1. Fresh token:   ", check_token(token))

# 2. The same token sent again is a replay
print("2. Same token:    ", check_token(token))

# 3. Change app_id after signing, keep the original signature
fresh = issue_token("genuine-app")
payload_b64, signature_b64 = fresh.split(".")
payload = json.loads(b64d(payload_b64))
payload["app_id"] = "attacker-app"
forged = b64e(json.dumps(payload).encode()) + "." + signature_b64
print("3. Edited app_id: ", check_token(forged))

# 4. A token that is already expired (no sleeping needed)
expired = issue_token("genuine-app", lifetime_seconds=-1)
print("4. Expired token: ", check_token(expired))