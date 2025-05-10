#!/usr/bin/env python3
import os
import json
import getpass
import sys
import hashlib
import hmac

import pyotp
import qrcode

CONFIG_PATH = os.path.expanduser("~/.myvault_config.json")
VAULT_PATH  = os.path.expanduser("~/.myvault.txt")
PBKDF2_ITER = 100_000
KEY_LEN     = 32  # bytes

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derive a key from password+salt using PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac("sha256", password, salt, PBKDF2_ITER, dklen=KEY_LEN)

def setup():
    if os.path.exists(CONFIG_PATH):
        print("⚠  Vault already initialized.")
        return

    # 1) Master password
    pw  = getpass.getpass("Set master password: ").encode()
    pw2 = getpass.getpass("Confirm password: ").encode()
    if pw != pw2:
        print("✗ Passwords did not match.")
        sys.exit(1)

    # Derive and store salt+key
    salt = os.urandom(16)
    key  = derive_key(pw, salt)

    # 2) TOTP secret
    secret = pyotp.random_base32()
    totp  = pyotp.TOTP(secret)
    uri   = totp.provisioning_uri(name="you@local", issuer_name="MyVault")

    print("\nScan this QR code with Google Authenticator (or similar):\n")
    qrcode.print_ascii(uri)
    print(f"\n—or manually enter secret: {secret}\n")

    # Save config: base64-encode binary data for JSON safety
    cfg = {
        "salt": salt.hex(),
        "key":  key.hex(),
        "totp_secret": secret
    }
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f)
    print("✓ Vault setup complete. Store your notes in:", VAULT_PATH)

def access():
    if not os.path.exists(CONFIG_PATH):
        print("✗ Vault not initialized; run with `setup` first.")
        sys.exit(1)

    cfg = json.load(open(CONFIG_PATH))
    salt = bytes.fromhex(cfg["salt"])
    stored_key = bytes.fromhex(cfg["key"])
    secret = cfg["totp_secret"]

    # 1) Verify password
    pw = getpass.getpass("Master password: ").encode()
    key = derive_key(pw, salt)
    if not hmac.compare_digest(key, stored_key):
        print("✗ Incorrect password.")
        sys.exit(1)

    # 2) Verify TOTP
    code = input("TOTP code: ").strip()
    totp = pyotp.TOTP(secret)
    if not totp.verify(code):
        print("✗ Invalid or expired code.")
        sys.exit(1)

    # 3) Access granted
    print("\n✓ Access granted. Your vault contents:\n")
    if os.path.exists(VAULT_PATH):
        print(open(VAULT_PATH).read())
    else:
        print("[empty vault]")

def main():
    import argparse
    p = argparse.ArgumentParser(description="My Zero-Trust Vault")
    p.add_argument("action", choices=["setup", "access"])
    args = p.parse_args()

    if args.action == "setup":
        setup()
    else:
        access()

if __name__ == "__main__":
    main()
