#!/usr/bin/python3
import base64
import hashlib
import hmac
import json

SecretKey = 0xa4062df2cd209c531ccd0b714e77c9f799089a240ec5d0a241afb225bea2ee12
CustomNonce = (0x8f69ecd30d6cd2ed042f1ce39c9cd166533343aa3bc615b6d0098ad7e9fe9f8a)
HMAC_KEY="marlboro"

CURVE_CONFIGS = {
    "ES256": {  # NIST P-256 (secp256r1)
        "hash": hashlib.sha256,
        "byte_len": 32,
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "order": (
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        ),
        "generator": (
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        ),
    },
    "ES384": {  # NIST P-384 (secp384r1)
        "hash": hashlib.sha384,
        "byte_len": 48,
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        "a": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        "order": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        "generator": (
            0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
            0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
        ),
    },
    "ES512": {  # NIST P-521 (secp521r1)
        "hash": hashlib.sha512,
        "byte_len": 66,
        "p": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
        "order": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
        "generator": (
            0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
            0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650,
        ),
    },
}

HMAC_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

def base64url_encode(data: bytes) -> str:
  return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def point_add(p1, p2, p, a):
  if p1 is None:
    return p2
  if p2 is None:
    return p1
  x1, y1 = p1
  x2, y2 = p2
  if x1 == x2 and y1 != y2:
    return None
  if x1 == x2:
    slope = ((3 * x1 * x1 + a) * pow(2 * y1, -1, p)) % p
  else:
    slope = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
  x3 = (slope * slope - x1 - x2) % p
  y3 = (slope * (x1 - x3) - y1) % p
  return (x3, y3)

def scalar_multiply(k: int, point: tuple, p: int, a: int):
  result = None
  addend = point
  while k > 0:
    if k & 1:
      result = point_add(result, addend, p, a)
    addend = point_add(addend, addend, p, a)
    k >>= 1
  return result

def sign_jwt(payload: dict, key, alg: str = "ES256", nonce_int: int = None):
  header = {"alg": alg, "typ": "JWT"}
  encoded_header = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
  encoded_payload = base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
  signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")

  # Handle HMAC (HS256, HS384, HS512)
  if alg in HMAC_HASHES:
    secret_bytes = key.encode("utf-8") if isinstance(key, str) else key
    raw_signature = hmac.new(secret_bytes, signing_input, HMAC_HASHES[alg]).digest()

  # Handle ECDSA (ES256, ES384, ES512)
  elif alg in CURVE_CONFIGS:
    if nonce_int is None:
      raise ValueError(f"A custom nonce_int is required for {alg}.")
    cfg = CURVE_CONFIGS[alg]
    order = cfg["order"]
    byte_len = cfg["byte_len"]
    digest = cfg["hash"](signing_input).hexdigest()
    message_hash = int(digest, 16)
    point_r = scalar_multiply(nonce_int, cfg["generator"], cfg["p"], cfg["a"])
    sig_r = point_r[0] % order
    sig_s = ((message_hash + (sig_r * key)) * pow(nonce_int, -1, order)) % order
    if sig_r == 0 or sig_s == 0:
      raise ValueError("Invalid nonce: resulted in zero signature component. Pick another nonce.")
    raw_signature = sig_r.to_bytes(byte_len, "big") + sig_s.to_bytes(byte_len, "big")

  else:
    raise ValueError(f"Unsupported algorithm: {alg}")

  encoded_signature = base64url_encode(raw_signature)
  return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

if __name__ == "__main__":
    jwt_1_data = {
        "uuid":1,
        "username": "user01",
        "email": "user01@example.tld",
        "is_admin": False,
        "iat": 1794472381,
        "exp": 1794472681
    }
    jwt_2_data = {
        "uuid":2,
        "username": "user02",
        "email": "user02@example.tld",
        "is_admin": False,
        "iat": 1794472381,
        "exp": 1794472681
    }

print("[+] Generating examples...")
print(f"jwt1: {jwt_1_data}")
print(f"jwt2: {jwt_2_data}")

for alg in CURVE_CONFIGS:
    print(f"\n══════ [{alg}] [VULN]"+"══════"*9)
    print(f"[+] jwt1={sign_jwt(jwt_1_data,SecretKey,alg,CustomNonce)}\n")
    print(f"[+] jwt2={sign_jwt(jwt_2_data,SecretKey,alg,CustomNonce)}")

for alg in HMAC_HASHES:
    print(f"\n══════ [{alg}] [SAFE-ISH] "+"══════"*9)
    print("[*] These tokens are crackable using: hashcat -m 16500")
    print(f"[+] jwt1={sign_jwt(jwt_1_data,HMAC_KEY,alg,CustomNonce)}\n")
    print(f"[+] jwt2={sign_jwt(jwt_2_data,HMAC_KEY,alg,CustomNonce)}")
