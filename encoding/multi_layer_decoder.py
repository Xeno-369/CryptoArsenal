#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — Multi-Layer Decoder
================================================
Beaucoup de challenges empilent les encodages (base64 d'un base32 d'un
hex d'un XOR...). Ce module détecte automatiquement le type d'encodage
d'une chaîne et décode en cascade jusqu'à ce que ça n'ait plus de sens
(ou qu'un flag apparaisse).

Encodages détectés : hex, base64 (standard + urlsafe), base32, base85,
base58 (Bitcoin-style), rot13, binaire (0/1 espacés).

Usage CLI :
    python3 multi_layer_decoder.py "gASVCAAAAAAAAACMBHRlc3SULg=="

Usage import :
    from multi_layer_decoder import auto_decode_chain
    for layer in auto_decode_chain(mystery_string):
        print(layer)

Auteur : Xeno CTF Arsenal
================================================
"""

import base64
import re
import sys

FLAG_PATTERNS = [
    r"[A-Za-z0-9_]+\{[^}]{3,100}\}",  # forme générique NOM{...}
]

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def looks_like_flag(s: str) -> bool:
    return any(re.search(p, s) for p in FLAG_PATTERNS)


def try_hex(s: str):
    s = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0 and len(s) >= 4:
        try:
            return bytes.fromhex(s)
        except ValueError:
            return None
    return None


def try_base64(s: str):
    s = s.strip()
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) and len(s) % 4 == 0 and len(s) >= 4:
        try:
            return base64.b64decode(s, validate=True)
        except Exception:
            return None
    return None


def try_base64_urlsafe(s: str):
    s = s.strip()
    if re.fullmatch(r"[A-Za-z0-9\-_]+={0,2}", s) and len(s) >= 4:
        try:
            return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        except Exception:
            return None
    return None


def try_base32(s: str):
    s = s.strip().upper()
    if re.fullmatch(r"[A-Z2-7]+={0,6}", s) and len(s) >= 8:
        try:
            return base64.b32decode(s)
        except Exception:
            return None
    return None


def try_base85(s: str):
    s = s.strip()
    if re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+", s) and len(s) >= 5:
        try:
            return base64.b85decode(s)
        except Exception:
            return None
    return None


def try_base58(s: str):
    s = s.strip()
    if re.fullmatch(f"[{BASE58_ALPHABET}]+", s) and len(s) >= 4:
        try:
            n = 0
            for c in s:
                n = n * 58 + BASE58_ALPHABET.index(c)
            # compte les zéros de tête (représentés par '1' en base58)
            n_leading = len(s) - len(s.lstrip('1'))
            body = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
            return b'\x00' * n_leading + body
        except Exception:
            return None
    return None


def try_rot13(s: str):
    if re.fullmatch(r"[A-Za-z0-9 _\-{}.,!?']+", s):
        return s.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        ))
    return None


def try_binary(s: str):
    compact = s.strip().replace(" ", "")
    if re.fullmatch(r"[01]+", compact) and len(compact) % 8 == 0 and len(compact) >= 8:
        try:
            n = int(compact, 2)
            return n.to_bytes(len(compact) // 8, 'big')
        except Exception:
            return None
    return None


DECODERS = [
    ("hex", try_hex),
    ("base64", try_base64),
    ("base64-urlsafe", try_base64_urlsafe),
    ("base32", try_base32),
    ("base85", try_base85),
    ("base58", try_base58),
    ("binary", try_binary),
    ("rot13", try_rot13),
]


def _to_str(data) -> str:
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    return data


def auto_decode_chain(s: str, max_depth: int = 10, verbose: bool = True):
    """
    Décode en cascade jusqu'à un flag, une profondeur max, ou plus aucun
    décodage reconnu. Retourne la liste [(nom_encodage, résultat), ...].
    """
    chain = [("input", s)]
    current = s

    for depth in range(max_depth):
        if looks_like_flag(current):
            if verbose:
                print(f"[!!!] Motif de flag détecté à la profondeur {depth} : {current}")
            break

        progressed = False
        for name, fn in DECODERS:
            result = fn(current)
            if result is None:
                continue
            result_str = _to_str(result)
            # Évite de "décoder" vers du charabia binaire illisible sans le signaler
            printable_ratio = sum(1 for c in result_str if c.isprintable()) / max(len(result_str), 1)
            if printable_ratio < 0.6:
                continue
            if verbose:
                print(f"[{depth}] {name:16s} -> {result_str!r}")
            chain.append((name, result_str))
            current = result_str
            progressed = True
            break

        if not progressed:
            if verbose:
                print(f"[*] Aucun décodage supplémentaire reconnu à la profondeur {depth}. Arrêt.")
            break

    return chain


if __name__ == "__main__":
    if len(sys.argv) > 1:
        auto_decode_chain(sys.argv[1])
    else:
        print("=== Démo : hex -> base64 -> texte contenant un flag ===")
        secret = "EthACTF{ch41ned_3nc0d1ng_1s_3asy_t0_p33l}"
        layer1 = base64.b64encode(secret.encode()).decode()
        layer0 = layer1.encode().hex()
        print(f"Donnée de départ (hex d'un base64) : {layer0}\n")
        auto_decode_chain(layer0)
