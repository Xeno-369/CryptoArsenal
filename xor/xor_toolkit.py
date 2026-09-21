#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — XOR Toolkit
================================================
Couvre les 3 scénarios XOR les plus fréquents en CTF :

  1. single_byte_bruteforce()  : clé d'un seul octet (0-255)
  2. crib_drag / recover_key_from_crib : retrouve la clé (longueur + valeur)
                                  en XORant le ciphertext avec un mot connu
                                  du clair (ex: "flag{", "EthACTF{") à
                                  toutes les positions.
  3. auto_break_repeating_xor(): longueur de clé inconnue → estime-la via
                                  la distance de Hamming normalisée, puis
                                  casse chaque colonne comme un XOR
                                  single-byte (façon cryptanalyse Vigenère).

Auteur : Xeno CTF Arsenal
================================================
"""

import string

PRINTABLE = set(bytes(string.printable, "ascii"))


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def printable_score(data: bytes) -> float:
    """Score simple : proportion de caractères imprimables + bonus lettres/espaces."""
    if not data:
        return 0.0
    letters_spaces = sum(1 for b in data if chr(b).isalpha() or chr(b) == " ")
    printable = sum(1 for b in data if b in PRINTABLE)
    return (printable / len(data)) + (letters_spaces / len(data))


# ============================================================
# 1. SINGLE-BYTE XOR BRUTEFORCE
# ============================================================

def single_byte_bruteforce(data: bytes, top_n: int = 5):
    """Retourne les top_n meilleures clés (0-255) triées par score de lisibilité."""
    results = []
    for key in range(256):
        pt = xor_bytes(data, bytes([key]))
        results.append((printable_score(pt), key, pt))
    results.sort(key=lambda x: -x[0])
    return results[:top_n]


# ============================================================
# 2. CRIB DRAGGING — retrouve la clé depuis un mot du clair connu
# ============================================================

def crib_drag(ciphertext: bytes, crib: bytes):
    """
    XOR le crib (ex: b"EthACTF{") avec le ciphertext à CHAQUE position.
    Si la clé est plus courte que le crib et se répète, le résultat va
    faire apparaître la clé qui se répète visiblement dans la sortie.
    """
    out = []
    for pos in range(len(ciphertext) - len(crib) + 1):
        segment = ciphertext[pos:pos + len(crib)]
        candidate_key = xor_bytes(segment, crib)
        out.append((pos, candidate_key))
    return out


def recover_key_from_crib(ciphertext: bytes, crib: bytes, key_len: int):
    """
    Si tu connais déjà la longueur de clé (key_len) et un crib présent
    quelque part dans le clair, reconstruit la clé complète en alignant
    le crib à sa position réelle (trouvée par crib_drag) modulo key_len.
    """
    for pos, candidate in crib_drag(ciphertext, crib):
        key = bytearray(key_len)
        mask = [False] * key_len
        for i, b in enumerate(candidate):
            key[(pos + i) % key_len] = b
            mask[(pos + i) % key_len] = True
        if all(mask):
            return bytes(key)
    return None


# ============================================================
# 3. REPEATING-KEY XOR — longueur de clé inconnue (façon "Vigenère XOR")
# ============================================================

def hamming_distance(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_key_lengths(data: bytes, max_len: int = 40, top_n: int = 3):
    """Estime la/les longueur(s) de clé les plus probables via la distance de Hamming normalisée."""
    scores = []
    for klen in range(2, max_len + 1):
        chunks = [data[i:i + klen] for i in range(0, len(data), klen)][:4]
        if len(chunks) < 2:
            continue
        dists = [
            hamming_distance(chunks[i], chunks[i + 1]) / klen
            for i in range(len(chunks) - 1)
            if len(chunks[i]) == len(chunks[i + 1]) == klen
        ]
        if dists:
            scores.append((sum(dists) / len(dists), klen))
    scores.sort()
    return [klen for _, klen in scores[:top_n]]


def break_repeating_key_xor(data: bytes, key_len: int) -> bytes:
    """Casse chaque colonne (i mod key_len) comme un XOR single-byte indépendant."""
    key = bytearray(key_len)
    for col in range(key_len):
        column = data[col::key_len]
        best_score, best_key, _ = single_byte_bruteforce(column, top_n=1)[0]
        key[col] = best_key
    return bytes(key)


def auto_break_repeating_xor(data: bytes, max_len: int = 40, verbose: bool = True):
    """Pipeline complet : devine les longueurs de clé probables, casse chacune, retourne le meilleur résultat."""
    candidates = []
    for klen in guess_key_lengths(data, max_len):
        key = break_repeating_key_xor(data, klen)
        pt = xor_bytes(data, key)
        score = printable_score(pt)
        candidates.append((score, klen, key, pt))
        if verbose:
            print(f"[*] key_len={klen:2d}  clé={key!r}  score={score:.3f}")
    candidates.sort(key=lambda x: -x[0])
    return candidates[0] if candidates else None


if __name__ == "__main__":
    print("=== Démo 1 : single-byte XOR ===")
    demo = xor_bytes(b"EthACTF{d3m0_x0r_s1ngl3_byt3}", bytes([0x5A]))
    for score, key, pt in single_byte_bruteforce(demo, top_n=3):
        print(f"  clé=0x{key:02x}  score={score:.2f}  -> {pt}")

    print("\n=== Démo 2 : repeating-key XOR (longueur inconnue) ===")
    secret_key = b"key5"
    demo2 = xor_bytes(b"EthACTF{r3p3at1ng_k3y_x0r_1s_w3ak_t00}" * 2, secret_key)
    result = auto_break_repeating_xor(demo2, max_len=10)
    if result:
        score, klen, key, pt = result
        print(f"[!!!] Meilleure trouvaille : clé={key} -> {pt[:60]}")

    print("\n=== Démo 3 : crib dragging (clé connue via un mot du clair) ===")
    key5 = recover_key_from_crib(demo2, b"EthACTF{", key_len=4)
    print(f"  clé retrouvée via crib 'EthACTF{{' : {key5}")
