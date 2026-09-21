#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — AES Universal
================================================
Un seul outil pour tous les cas AES rencontrés en CTF, plutôt qu'un
script par challenge :
  - Modes : ECB, CBC, GCM, CTR
  - Dérivation de clé : brute (hex/raw), MD5(pass), SHA256(pass), PBKDF2

Usage CLI :
    python3 aes_universal.py --mode gcm --key-hex <64 car.> \
        --nonce-hex <...> --tag-hex <...> --ciphertext-hex <...>

    python3 aes_universal.py --mode cbc --key-derive sha256 --password "hunter2" \
        --iv-hex <...> --ciphertext-hex <...>

Usage import :
    from aes_universal import aes_decrypt
    pt = aes_decrypt(mode="gcm", key=key_bytes, nonce=nonce, tag=tag, ct=ct)

Auteur : Xeno CTF Arsenal
================================================
"""

import argparse
import hashlib
import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad


def derive_key(method: str, password: bytes = None, raw_hex: str = None,
                key_len: int = 32, salt: bytes = b"", iterations: int = 100_000) -> bytes:
    if method == "raw":
        return bytes.fromhex(raw_hex)
    if method == "md5":
        return hashlib.md5(password).digest()  # 16 octets -> AES-128
    if method == "sha256":
        return hashlib.sha256(password).digest()  # 32 octets -> AES-256
    if method == "sha256-32":
        return hashlib.sha256(password).digest()
    if method == "pbkdf2":
        return PBKDF2(password, salt, dkLen=key_len, count=iterations)
    raise ValueError(f"Méthode de dérivation inconnue : {method}")


def aes_decrypt(mode: str, key: bytes, ct: bytes, iv: bytes = None,
                 nonce: bytes = None, tag: bytes = None, try_unpad: bool = True) -> bytes:
    mode = mode.lower()

    if mode == "ecb":
        cipher = AES.new(key, AES.MODE_ECB)
        pt = cipher.decrypt(ct)
    elif mode == "cbc":
        if iv is None:
            raise ValueError("CBC nécessite un IV.")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = cipher.decrypt(ct)
    elif mode == "gcm":
        if nonce is None:
            raise ValueError("GCM nécessite un nonce.")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if tag is not None:
            pt = cipher.decrypt_and_verify(ct, tag)
            return pt  # pas de padding en GCM
        pt = cipher.decrypt(ct)
        return pt
    elif mode == "ctr":
        if nonce is None:
            raise ValueError("CTR nécessite un nonce (souvent 8 ou 16 octets selon l'implém).")
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        return pt
    else:
        raise ValueError(f"Mode inconnu : {mode}")

    if try_unpad and mode in ("ecb", "cbc"):
        try:
            pt = unpad(pt, AES.block_size)
        except ValueError:
            pass  # pas de padding PKCS7 valide, on retourne tel quel

    return pt


def _build_cli():
    p = argparse.ArgumentParser(description="AES Universal — déchiffrement multi-mode.")
    p.add_argument("--mode", required=True, choices=["ecb", "cbc", "gcm", "ctr"])
    p.add_argument("--ciphertext-hex", required=True)
    p.add_argument("--iv-hex")
    p.add_argument("--nonce-hex")
    p.add_argument("--tag-hex")

    p.add_argument("--key-derive", default="raw",
                    choices=["raw", "md5", "sha256", "pbkdf2"])
    p.add_argument("--key-hex", help="Requis si --key-derive raw")
    p.add_argument("--password", help="Requis si --key-derive md5/sha256/pbkdf2")
    p.add_argument("--salt-hex", default="")
    p.add_argument("--pbkdf2-iterations", type=int, default=100_000)
    p.add_argument("--key-len", type=int, default=32)

    p.add_argument("--no-unpad", action="store_true",
                    help="Ne pas essayer de retirer le padding PKCS7 (ECB/CBC).")
    return p


def main():
    args = _build_cli().parse_args()

    key = derive_key(
        args.key_derive,
        password=args.password.encode() if args.password else None,
        raw_hex=args.key_hex,
        key_len=args.key_len,
        salt=bytes.fromhex(args.salt_hex) if args.salt_hex else b"",
        iterations=args.pbkdf2_iterations,
    )

    pt = aes_decrypt(
        mode=args.mode,
        key=key,
        ct=bytes.fromhex(args.ciphertext_hex),
        iv=bytes.fromhex(args.iv_hex) if args.iv_hex else None,
        nonce=bytes.fromhex(args.nonce_hex) if args.nonce_hex else None,
        tag=bytes.fromhex(args.tag_hex) if args.tag_hex else None,
        try_unpad=not args.no_unpad,
    )

    try:
        print(pt.decode())
    except UnicodeDecodeError:
        print(f"[binaire, {len(pt)} octets] {pt!r}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        print("=== Démo : AES-256-GCM, clé dérivée d'un entier via SHA256 ===")
        d = 0x529ad8e5c0717a257ad7d514ecaf04b9193e0d068d24e1b0f73a30dada244b0a
        key = hashlib.sha256(d.to_bytes(32, "big")).digest()
        ct = bytes.fromhex(
            "ed6e8df55be59a6c05ddfff73b85c58fc8c45088db59071d39663e72bca9803d67db17770f37a7f43225"
        )
        tag = bytes.fromhex("23bd64f6ea9c6a4d49e27dd6b7bfb79c")
        nonce = bytes.fromhex("f44d6dba2523d98297263e5b785e0277")
        pt = aes_decrypt(mode="gcm", key=key, ct=ct, nonce=nonce, tag=tag)
        print(f"  Flag : {pt.decode()}")
        print("\nUsage CLI :")
        print("  python3 aes_universal.py --mode gcm --key-derive raw "
              "--key-hex <64 hex> --nonce-hex <...> --tag-hex <...> "
              "--ciphertext-hex <...>")
