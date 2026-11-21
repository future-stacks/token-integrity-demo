import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)                      # never reuse a nonce with the same key
ciphertext = aesgcm.encrypt(nonce, b"your message", b"header-data")
plaintext = aesgcm.decrypt(nonce, ciphertext, b"header-data")
print("Ciphertext:", ciphertext.hex())
print("Decrypted:", plaintext.decode())

# Task 2: flip one byte in the ciphertext and try to decrypt it
tampered = bytearray(ciphertext)   # editable copy of the encrypted bytes
tampered[0] ^= 1                   # flip one bit of the first byte

try:
    aesgcm.decrypt(nonce, bytes(tampered), b"header-data")
    print("Decrypted tampered data (this should never happen)")
except InvalidTag:
    print("Tampering detected")

# Task 3: correct ciphertext, wrong associated data
try:
    aesgcm.decrypt(nonce, ciphertext, b"wrong-header")
    print("Decrypted with wrong header (this should never happen)")
except InvalidTag:
    print("Wrong header detected")