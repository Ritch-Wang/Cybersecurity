#!/usr/bin/env python3
import os
import json
import getpass
import sys

from argon2 import PasswordHasher, exceptions
import pyotp
import qrcode

CONFIG_PATH = os.path.expanduser("~/.myvault_config.json")
VAULT_PATH  = os.path.expanduser("~/.myvault.txt")

def setup():
    if os.path.exists(CONFIG_PATH):
        print("⚠  Vault already initialized.")
        return

    # 1) Master password
    ph = PasswordHasher()
    pw  = getpass.getpass("Set master password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw != pw2:
        print("✗ Passwords did not match.")
        sys.exit(1)
    pw_hash = ph.hash(pw)

    # 2) TOTP secret
    secret = pyotp.random_base32()
    totp  = pyotp.TOTP(secret)
    uri   = totp.provisioning_uri(name="you@local", issuer_name="MyVault")

    print("\nScan this QR code with Google Authenticator (or similar):\n")
    qrcode.print_ascii(uri)
    print(f"\n—or manually enter secret: {secret}\n")

    # Save config
    with open(CONFIG_PATH, "w") as f:
        json.dump({"pw_hash": pw_hash, "totp_secret": secret}, f)
    print("✓ Vault setup complete. Store your notes in:", VAULT_PATH)

def access():
    if not os.path.exists(CONFIG_PATH):
        print("✗ Vault not initialized; run with `setup` first.")
        sys.exit(1)

    cfg = json.load(open(CONFIG_PATH))
    ph = PasswordHasher()

    # 1) Verify password
    pw = getpass.getpass("Master password: ")
    try:
        ph.verify(cfg["pw_hash"], pw)
    except exceptions.VerifyMismatchError:
        print("✗ Incorrect password.")
        sys.exit(1)

    # 2) Verify TOTP
    code = input("TOTP code: ").strip()
    totp = pyotp.TOTP(cfg["totp_secret"])
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
