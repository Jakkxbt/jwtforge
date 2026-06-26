# JWTForge - JWT Attack Toolkit

A self-contained JWT security assessment tool for authorised penetration testing and bug bounty research. Pure Python standard library — no external dependencies.

## Features

- **Decode & Analyse** — Pretty-print JWT structure with automated security flagging
- **Crack** — Brute-force HMAC secrets against wordlists (HS256/384/512)
- **Forge** — Re-sign tokens with tampered claims using known/cracked secrets
- **Alg-None** — Generate `alg:none` bypass variants
- **Confuse** — RSA→HMAC key confusion attack (RS256 → HS256)
- **KID Injection** — Generate path traversal, SQLi, and command injection variants via the `kid` header

## Installation

No installation required. Just Python 3.6+:

```bash
chmod +x jwtforge.py
./jwtforge.py -h
```

Or run directly:

```bash
python3 jwtforge.py <command>
```

## Usage

### Decode & Analyse

Pretty-print the JWT structure and flag common security issues:

```bash
python3 jwtforge.py decode "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

**Security flags:**
- ⚠ Weak algorithms (`alg=none`)
- ⓘ Symmetric vs asymmetric algorithm usage
- ⚠ Missing `exp` claim (token never expires)
- ⚠ Sensitive claims exposed in payload (passwords, API keys)
- ⓘ Missing issuer/audience claims
- ⓘ Path traversal patterns in `kid` header

### Crack (HMAC Secret Brute-Force)

Test weak HMAC secrets against a wordlist:

```bash
python3 jwtforge.py crack "<token>" /path/to/wordlist.txt
```

**Supports:** HS256, HS384, HS512

**Example wordlist:** `/usr/share/wordlists/rockyou.txt` (if available on Kali)

### Forge (Re-sign with Tampered Claims)

Re-sign a JWT with a known secret and optionally modify claims:

```bash
# Basic re-sign
python3 jwtforge.py forge "<token>" --secret "mysecret"

# Role escalation attempt
python3 jwtforge.py forge "<token>" --secret "mysecret" --set role=admin

# Modify multiple claims
python3 jwtforge.py forge "<token>" --secret "mysecret" --set role=admin --set sub=attacker
```

### Alg-None Attack

Generate `alg:none` bypass variants (signature stripped):

```bash
python3 jwtforge.py alg-none "<token>"
```

**Generates variants:** `none`, `None`, `NONE`, `nOnE`, `NoNe`, `NONe`

**What it does:** Removes the signature and sets `alg: none`. If the server skips signature verification for this algorithm, the token will be accepted regardless of payload tampering.

### Confuse (RSA→HMAC Key Confusion)

Re-sign an RSA token using the RSA public key as an HMAC secret:

```bash
python3 jwtforge.py confuse "<token>" --pubkey /path/to/public.pem
```

**What it does:** If the server mistakenly uses the RSA public key to verify HMAC signatures (a critical implementation bug), this attack lets you forge tokens by signing with the public key.

**Produces:** HS256, HS384, HS512 variants signed with the RSA public key material.

### KID Injection

Generate injection payloads via the `kid` (Key ID) header:

```bash
python3 jwtforge.py kid "<token>" --inject "/var/www/html"
```

**What it does:** The `kid` header specifies which key to use for verification. Vulnerable applications may use this value in a file path, SQL query, or command without proper sanitisation.

**Generated variants:**
1. **Path Traversal** — `../../../path/to/key` (read arbitrary files as keys)
2. **Dev Null** — `../../../../dev/null` (force empty key for predictable HMAC)
3. **SQL Injection** — `../../../sqlite:///key?or=1--`
4. **Command Injection** — `../../../key; cat /etc/passwd`

## Attack Explanations

### Alg-None Bypass

JWT supports an `alg: none` algorithm intended for debugging. The spec says implementations MUST reject unsigned tokens, but many libraries don't properly enforce this. An attacker can:

1. Tamper with the payload (e.g., set `role: admin`)
2. Change `alg` to `none`
3. Strip the signature

If the server accepts it, they've bypassed authentication entirely.

### Key Confusion (RSA → HMAC)

RSA signatures use a private key to sign and a public key to verify. HMAC uses the same secret for both.

**The vulnerability:** Some implementations use whatever key is available for verification. If you can get the RSA public key and the server uses it as an HMAC secret, you can forge valid tokens.

### KID Injection

The `kid` header tells the server which key to use:

```json
{
  "alg": "HS256",
  "kid": "/path/to/secret.key",
  "typ": "JWT"
}
```

Vulnerable code might look like:

```python
key_path = f"/keys/{header['kid']}"
key = open(key_path).read()  # Unsafe!
```

An attacker sets `kid: ../../../etc/passwd` and the server verifies with the contents of `/etc/passwd` as the HMAC secret.

## Exit Codes

- `0` — Success
- `1` — Error / Secret not found
- `130` — Interrupted by user (Ctrl+C)

## Disclaimer

**Authorised use only.** This tool is for legitimate security testing, penetration testing with written authorisation, and bug bounty programs within scope. Unauthorised use is illegal. Use responsibly.

## License

For authorised pentesting and bug bounty use only.

---

**CobraSEC** — Offensive Security & Adversary Emulation
