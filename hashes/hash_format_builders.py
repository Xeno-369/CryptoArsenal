#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — Hash Format Builders (Hashcat)
================================================
Construit le format exact attendu par hashcat pour des types de hash
"composites" (nécessitant plusieurs valeurs assemblées dans un ordre
précis) — la partie qu'on oublie/rate le plus souvent, pas l'attaque
elle-même.

Couvre (d'après nos vrais challenges résolus) :
  - MySQL CRAM-SHA1 (mode 11200)   : $mysqlna$scramble*response
  - RACF (mode 8500)               : $racf$*USER*HASH
  - Identification rapide du type de hash à partir de sa longueur/forme

Auteur : Xeno CTF Arsenal
================================================
"""

import re


def build_mysqlna_hash(scramble_hex: str, response_hex: str) -> str:
    """
    Format hashcat -m 11200 (MySQL CRAM-SHA1 challenge-response).

    scramble_hex : le salt/scramble envoyé par le serveur dans le paquet
                   "Server Greeting" (2 morceaux à concaténer : 8 octets
                   avant les capability flags + 12 octets après, dans
                   l'ordre — 20 octets au total = 40 caractères hex).
    response_hex : la réponse SHA1 envoyée par le client dans le paquet
                   "Login Request" (champ mysql.passwd, 20 octets).
    """
    scramble_hex = scramble_hex.strip().lower()
    response_hex = response_hex.strip().lower()
    assert len(scramble_hex) == 40, f"scramble doit faire 40 car. hex (reçu {len(scramble_hex)})"
    assert len(response_hex) == 40, f"response doit faire 40 car. hex (reçu {len(response_hex)})"
    return f"$mysqlna${scramble_hex}*{response_hex}"


def build_racf_hash(username: str, hash_hex: str) -> str:
    """Format hashcat -m 8500 (RACF, mainframe IBM z/OS)."""
    return f"$racf$*{username.upper()}*{hash_hex.strip().lower()}"


# --------------------------------------------------------------
# Cheatsheet + identification rapide (pas exhaustif, les cas les
# plus fréquents rencontrés en CTF)
# --------------------------------------------------------------

HASH_MODES = {
    32:  [("MD5 / NTLM", 0), ("MD5(unix)/others", None)],
    40:  [("SHA1", 100), ("MySQL4.1+ passwd (sans $)", 300)],
    64:  [("SHA256 / SHA3-256 / Keccak-256", 1400)],
    96:  [("SHA384", 10800)],
    128: [("SHA512", 1700)],
}

HASH_PREFIXES = {
    "$1$":     ("md5crypt", 500),
    "$2y$":    ("bcrypt", 3200),
    "$2a$":    ("bcrypt", 3200),
    "$2b$":    ("bcrypt", 3200),
    "$5$":     ("sha256crypt", 7400),
    "$6$":     ("sha512crypt", 1800),
    "$racf$":  ("RACF", 8500),
    "$mysqlna$": ("MySQL CRAM-SHA1", 11200),
    "$P$":     ("phpass (WordPress/Drupal)", 400),
}


def identify_hash(h: str):
    """
    Heuristique rapide d'identification (PAS un remplacement de
    hashcat --identify, juste un aide-mémoire pour les cas fréquents).
    """
    h = h.strip()

    for prefix, (name, mode) in HASH_PREFIXES.items():
        if h.startswith(prefix):
            return [(name, mode)]

    if re.fullmatch(r"[0-9a-fA-F]+", h):
        return HASH_MODES.get(len(h), [("longueur non reconnue", None)])

    return [("format non reconnu — vérifie manuellement", None)]


if __name__ == "__main__":
    print("=== Démo : MySQL CRAM-SHA1 (challenge ARP-spoofing MITM) ===")
    scramble = "5c25593304590a382e465657142e673536524e0f"
    response = "23b100646fd1c6fe196ff12c7e3506f87dec22ae"[:40]  # garde-fou démo
    h = build_mysqlna_hash(scramble, response[:40] if len(response) >= 40 else response.ljust(40, '0'))
    print(f"  {h}")
    print("  -> hashcat -m 11200 -a 0 hash.txt rockyou.txt -r best64.rule\n")

    print("=== Démo : identification rapide ===")
    for sample in ["5f4dcc3b5aa765d61d8327deb882cf99",
                   "$1$aQtb0kQr$UBcO2t2xaB0YjxxdrPCyR1",
                   "96719db60d8e3f498c98d94155e1296aac105c4923290c89eeeb3ba26d3eef92"]:
        print(f"  {sample[:50]:52s} -> {identify_hash(sample)}")
