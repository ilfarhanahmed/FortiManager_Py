#!/usr/bin/env python3
"""
fmg_decrypt.py — Standalone decryption tool for encrypted FMG export files.

Usage:
    python fmg_decrypt.py <encrypted_file.fmgenc>
    python fmg_decrypt.py <encrypted_file.fmgenc> --out output.json
    python fmg_decrypt.py <encrypted_file.fmgenc> --print

Encrypted files are produced by fmg_adom_extractor.py when the user opts
to encrypt the export. They use AES-256-GCM with PBKDF2-HMAC-SHA256 key
derivation (600,000 iterations).

No third-party dependencies — uses only Python stdlib + cryptography package
(bundled with most Python installations).
"""

import argparse
import getpass
import json
import os
import sys

_ENC_MAGIC    = b"FMGENC1\x00"
_ENC_SALT_LEN = 16
_ENC_NONCE_LEN = 12
_PBKDF2_ITERS = 600_000
_PBKDF2_DKLEN = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    import hashlib
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PBKDF2_ITERS,
        dklen=_PBKDF2_DKLEN,
    )


def decrypt_file(path: str, password: str) -> dict:
    """Decrypt an .fmgenc file and return parsed JSON dict."""
    with open(path, "rb") as f:
        blob = f.read()

    if not blob.startswith(_ENC_MAGIC):
        raise ValueError(
            f"'{path}' is not an encrypted FMG export file.\n"
            "Expected magic header not found. Is this a plain .json file?"
        )

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ImportError:
        print("ERROR: 'cryptography' package is required.")
        print("Install with:  pip install cryptography")
        sys.exit(1)

    offset     = len(_ENC_MAGIC)
    salt       = blob[offset:offset + _ENC_SALT_LEN]
    offset    += _ENC_SALT_LEN
    nonce      = blob[offset:offset + _ENC_NONCE_LEN]
    offset    += _ENC_NONCE_LEN
    ciphertext = blob[offset:]

    key    = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong password or file is corrupted.")

    return json.loads(plaintext.decode("utf-8"))


def prompt_password() -> str:
    """Prompt for password with masking."""
    in_pycharm = (
        "PYCHARM_HOSTED" in os.environ
        or "PYDEV_CONSOLE_EXECUTE_HOOK" in os.environ
    )
    if not in_pycharm:
        try:
            return getpass.getpass("  Decryption password: ")
        except Exception:
            pass

    if os.name == "nt":
        try:
            import msvcrt
            sys.stdout.write("  Decryption password: ")
            sys.stdout.flush()
            chars = []
            while True:
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    break
                elif ch == "\x08":
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":
                    raise KeyboardInterrupt
                elif ch >= " ":
                    chars.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
            return "".join(chars)
        except Exception:
            pass

    print("  WARNING: Masked input not available. Password will be visible.")
    return input("  Decryption password: ")


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt an encrypted FMG export file (.fmgenc).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file",
        help="Path to the .fmgenc encrypted file")
    parser.add_argument("--out", "-o",
        help="Output JSON path (default: same name with .json extension)")
    parser.add_argument("--print", "-p",
        action="store_true", dest="print_json",
        help="Print decrypted JSON to stdout instead of saving to file")
    parser.add_argument("--password",
        help="Decryption password (avoid on shared systems — prefer interactive prompt)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"ERROR: File not found: {args.file}")
        sys.exit(1)

    if not args.file.endswith(".fmgenc"):
        print(f"WARNING: File does not have .fmgenc extension: {args.file}")
        confirm = input("Continue anyway? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            sys.exit(0)

    # Determine output path
    out_path = args.out
    if not out_path and not args.print_json:
        out_path = args.file.replace(".fmgenc", ".json")
        if os.path.exists(out_path):
            confirm = input(f"  '{out_path}' already exists. Overwrite? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Aborted.")
                sys.exit(0)

    # Get password
    password = args.password or prompt_password()
    if not password:
        print("ERROR: Password cannot be empty.")
        sys.exit(1)

    # Decrypt
    print(f"  Decrypting {args.file} ...", end=" ", flush=True)
    try:
        data = decrypt_file(args.file, password)
    except ValueError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)

    print("OK")

    # Output
    if args.print_json:
        print()
        print(json.dumps(data, indent=2))
    else:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        size_kb = os.path.getsize(out_path) / 1024
        print(f"  Saved → {out_path}  ({size_kb:.0f} KB)")
        print()
        print("  WARNING: This file is now unencrypted and may contain sensitive data.")
        print("           Restrict access and delete after use.")


if __name__ == "__main__":
    main()
