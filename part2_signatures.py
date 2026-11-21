from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

message = b"app=genuine;device=ok"
signature = private_key.sign(message)
print("Signature:", signature.hex())

public_key.verify(signature, message)   # raises InvalidSignature if wrong
print("Valid")

# Task 2: change the message, keep the original signature
tampered_message = b"app=tampered;device=ok"

try:
    public_key.verify(signature, tampered_message)
    print("Tampered message accepted (this should never happen)")
except InvalidSignature:
    print("Tampered message rejected")

# Task 3: verify the genuine signature with someone else's public key
attacker_private = Ed25519PrivateKey.generate()
attacker_public = attacker_private.public_key()

try:
    attacker_public.verify(signature, message)
    print("Wrong key accepted (this should never happen)")
except InvalidSignature:
    print("Wrong key rejected")