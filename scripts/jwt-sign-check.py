#!/usr/bin/env python
"""jwt-sign-check — pinpoint a JWT HS256 signature mismatch (no deps, stdlib only).

Why: "signature is invalid" from the gateway means the HMAC key the other app
signed with != the entry's configured secret. The usual cause is not a wrong
string but a different KEY DERIVATION: many libraries (Java jjwt, python-jose,
some Node setups) BASE64-DECODE the configured secret before using it as the
HMAC key, while others use the raw UTF-8 bytes. A secret containing - or _ or
trailing = is the trap; both sides must agree.

Usage:
    python jwt-sign-check.py <token> [candidate-secret ...]

With no candidate given it reads ZT_OTHERAPP_JWT_SECRET from .env (and
ZT_JWT_SECRET). Prints, per candidate, whether the token verifies using
   raw   = secret as UTF-8 bytes
   b64u  = base64url-decoded secret
   b64   = standard base64-decoded secret
and reports the token's alg/claims so shape problems are visible too. Never
prints a secret; only pass/fail and the claim NAMES.
"""
import base64, hashlib, hmac, json, pathlib, re, sys

def b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def env_candidates() -> list[tuple[str, str]]:
    out = []
    p = pathlib.Path(".env")
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"^\s*(ZT_[A-Z_]*(?:OTHERAPP|OTHER_APP|JUMPHOST|EXTERNAL|JWT)[A-Z_]*)=(.+)$", line)
            if m:
                out.append((m.group(1).strip(), m.group(2).strip()))
    return out

def variants(secret: str):
    yield "raw", secret.encode()
    try:
        yield "b64u", b64u_dec(secret)
    except Exception:
        pass
    try:
        pad = "=" * (-len(secret) % 4)
        yield "b64", base64.b64decode(secret + pad)
    except Exception:
        pass

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    token = sys.argv[1].strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        print(f"NOT A JWT: {len(parts)} segments (want 3) — truncated paste or wrong header")
        return 1
    h, p, s = parts
    header = json.loads(b64u_dec(h))
    payload = json.loads(b64u_dec(p))
    signing_input = f"{h}.{p}".encode()
    want = b64u_dec(s)

    print(f"alg={header.get('alg')!r} typ={header.get('typ')!r}  (gateway pins HS256)")
    print(f"claims present: {sorted(payload.keys())}")
    for k in ("iss", "aud", "jti", "exp", "iat"):
        if k in payload:
            print(f"  {k} = {payload[k]!r}")
    sub_hint = payload.get("username") or payload.get("sub")
    role_hint = payload.get("role")
    print(f"  username-ish = {sub_hint!r}   role = {role_hint!r}")
    print()
    if header.get("alg") != "HS256":
        print(f"!! alg is {header.get('alg')!r}: the gateway accepts HS256 only — this alone is a 401")

    cands = [(f"arg:{i}", a) for i, a in enumerate(sys.argv[2:])] or env_candidates()
    if not cands:
        print("no candidate secrets (pass them as args, or set one in .env)")
        return 1
    matches = []
    for name, secret in cands:
        for label, key in variants(secret):
            got = b64u_dec(base64.urlsafe_b64encode(
                hmac.new(key, signing_input, hashlib.sha256).digest()).rstrip(b"=").decode())
            if hmac.compare_digest(got, want):
                matches.append(f"{name} using {label} key derivation (secret len={len(secret)})")
    print("VERDICT:")
    if matches:
        for m in matches:
            print(f"  MATCH → {m}")
        print("  → the other app must use THIS secret with THIS derivation.")
    else:
        print("  NO MATCH against any candidate/derivation → the other app signed with a")
        print("  different secret value entirely (or its library derives the key another")
        print("  way: base64-of-hex, PBKDF2, a keystore entry, ...). Make both sides use")
        print("  ONE plain-hex secret to remove the derivation ambiguity.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
