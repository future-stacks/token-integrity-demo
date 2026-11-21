# token-integrity-demo

A small Python demo of three integrity mechanisms used to protect apps and APIs:

1. **Authenticated encryption (AES-GCM):** keeps data secret *and* detects any change to it.
2. **Digital signatures (Ed25519):** prove a message came from whoever holds the private key and hasn't been altered.
3. **Short-lived signed tokens:** a signed token with an expiry time and a one-time ID, so a stolen token is only useful briefly and only once.

Each part runs an honest case, then one or more attacks, and shows that the attacks are rejected.

## How to run

Requires Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python part1_aes_gcm.py
python part2_signatures.py
python part3_tokens.py
```

Keys, nonces and token IDs are random, so hex values differ on every run.

## What each part shows

### Part 1: AES-GCM authenticated encryption (`part1_aes_gcm.py`)

A message is encrypted with a 256-bit key, a random 12-byte nonce and some *associated data* (a header that is authenticated but not encrypted). Two attacks are then tried:

- **Flip one bit of the ciphertext:** decryption raises `InvalidTag` instead of returning corrupted plaintext.
- **Decrypt with the wrong associated data:** decryption also fails, even though the ciphertext itself is untouched. This binds the encrypted data to its context, for example a user ID or request path.

```
Ciphertext: 6fabfeddaaf5cba2f8203726f2e1116adc7ec9dc57d9223b3d0a8ba6
Decrypted: your message
Tampering detected
Wrong header detected
```

The ciphertext is 28 bytes: the 12-byte message plus a 16-byte authentication tag. The tag is what detects the tampering.

### Part 2: Ed25519 digital signatures (`part2_signatures.py`)

A private key signs `app=genuine;device=ok`, and the matching public key verifies it. Two attacks are then tried:

- **Change the message** to `app=tampered;device=ok` and reuse the original signature: rejected.
- **Verify with a different public key:** rejected, because a signature only verifies against the key pair that made it.

```
Signature: d7c075b1d55e7c79a35d42499a844107cc49b5d50d2cfb65d129024cdce9f0532b330a560daa6ce41fa2efb429e7fb6f75c804202c3cffbdd855b84731b4a401
Valid
Tampered message rejected
Wrong key rejected
```

This is the idea behind app attestation. Only the holder of the private key can produce a valid signature, and the public key can be shared freely because it can only check signatures, not create them.

### Part 3: Short-lived signed tokens with replay protection (`part3_tokens.py`)

An issuer creates a JSON payload with `app_id`, `exp` (now + 30 seconds) and `jti` (a random unique ID), signs it with Ed25519, and encodes it as `base64(payload).base64(signature)`.

The API server's `check_token` function:

1. splits and decodes the token,
2. verifies the signature *before* trusting anything in the payload,
3. rejects the token if `exp` has passed,
4. rejects the token if its `jti` has been seen before, and otherwise records it.

```
1. Fresh token:    accepted (app_id=genuine-app)
2. Same token:     rejected: replay
3. Edited app_id:  rejected: bad signature
4. Expired token:  rejected: expired
```

Each attack is tested on its own token so that it fails for exactly one reason.

## What I learned

Integrity is a separate property from secrecy. Base64 and even encryption don't stop someone changing data; the authentication tag and the signature are what make a change detectable. I was surprised that AES-GCM refuses to return anything at all for a one-bit change, rather than giving back slightly wrong data. Building Part 3 showed me that the order of checks matters: the signature has to be verified before reading `exp` or `jti`, otherwise an attacker controls the values being checked. From an attacker's point of view, a stolen token is worth little when it expires in 30 seconds and works once. So the place to push on a mobile app's API is the token issuer: can I get fresh, valid tokens without running the genuine app?

## Limitations

- **Replay protection is in memory.** `seen_ids` is a Python set: it is lost on restart, isn't shared between servers, and grows forever. A real system would use a shared store such as Redis, with each entry expiring when its token does.
- **Keys are generated on every run.** A real system would keep the private key in an HSM or secure enclave, publish the public key through a trusted channel, and rotate keys.
- **The issuer signs for anyone.** Here `issue_token` trusts its caller. In a real system, tokens are issued only after the app proves it's genuine through attestation, and that step is the one attackers target.
- **No clock-skew handling.** Expiry compares directly against the server clock, with no tolerance for clocks that drift apart.
- **Simplified token format.** There's no header, algorithm or key-ID field like in a JWT, so the format can't support multiple keys or algorithms.
- **Demo only.** For production, use a vetted standard such as JWT/PASETO with a maintained library rather than a hand-rolled format.
