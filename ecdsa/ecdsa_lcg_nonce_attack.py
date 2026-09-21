#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — ECDSA LCG-Linked Nonce Attack
================================================
Contexte : deux signatures ECDSA dont les nonces k1, k2 sont deux sorties
CONSÉCUTIVES d'un LCG (Linear Congruential Generator) aux paramètres connus :

    k_{i+1} = (a * k_i + b) mod n

("The signer trusted its clock. The clock was a liar." — un LCG n'est
JAMAIS un générateur de nonce sûr : dès que deux sorties consécutives sont
utilisées comme k, la relation linéaire entre elles permet de retrouver d
directement, sans jamais deviner k1 ni k2 individuellement.)

Principe :
    ECDSA :  k = s^-1 * (h + r*d)  mod n
    LCG   :  k2 = a*k1 + b         mod n

    En substituant k1 et k2 par leurs expressions ECDSA respectives dans
    la relation LCG, on obtient une équation linéaire en d, résoluble
    directement par algèbre modulaire (aucune recherche, aucun bruteforce).

    d = (a*s1^-1*h1 - s2^-1*h2 + b) * (s2^-1*r2 - a*s1^-1*r1)^-1  mod n

Vérification automatique : une fois d trouvé, on recalcule k1 depuis sig1,
puis k2 via le LCG ET via sig2 — si les deux correspondent, d est confirmé
sans ambiguïté (pas de faux positif possible).

Usage :
    Modifie les paramètres en bas du fichier (courbe, LCG, sig1, sig2),
    ou importe recover_d_from_lcg_nonces() dans ton propre script.

Auteur : Xeno CTF Arsenal
================================================
"""

import hashlib
from dataclasses import dataclass


@dataclass
class Signature:
    h: int  # hash du message (déjà en entier)
    r: int
    s: int


def recover_d_from_lcg_nonces(n: int, a: int, b: int, sig1: Signature, sig2: Signature):
    """
    Retrouve la clé privée d à partir de deux signatures dont les nonces
    sont liés par k2 = a*k1 + b (mod n).

    Retourne (d, k1, k2) si la vérification LCG passe, sinon lève ValueError.
    """
    A1 = pow(sig1.s, -1, n)
    A2 = pow(sig2.s, -1, n)

    num = (a * A1 * sig1.h - A2 * sig2.h + b) % n
    denom = (A2 * sig2.r - a * A1 * sig1.r) % n

    if denom == 0:
        raise ValueError("Dénominateur nul — vérifie les paramètres (a, b, r, s, h).")

    d = (num * pow(denom, -1, n)) % n

    # Vérification croisée : k1 (via sig1) -> LCG -> doit == k2 (via sig2)
    k1 = A1 * (sig1.h + sig1.r * d) % n
    k2_lcg = (a * k1 + b) % n
    k2_sig = A2 * (sig2.h + sig2.r * d) % n

    if k2_lcg != k2_sig:
        raise ValueError(
            "d trouvé mais échec de vérification LCG — vérifie l'ordre "
            "(sig1/sig2 sont-elles bien consécutives dans ce sens ?) ou les "
            "paramètres a/b."
        )

    return d, k1, k2_lcg


def sha256_int(data: bytes) -> int:
    """Hash SHA256 -> entier (utile si tu n'as que le message en clair, pas h)."""
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


def derive_aes_key_from_d(d: int, key_size_bytes: int = 32) -> bytes:
    """
    Motif fréquent en CTF : la clé AES est dérivée de d via SHA256(d en
    big-endian sur N octets). Adapte key_size_bytes si l'énoncé précise
    une autre taille (souvent 32 pour secp256k1/P-256, parfois 48/66).
    """
    d_bytes = d.to_bytes(key_size_bytes, "big")
    return hashlib.sha256(d_bytes).digest()


if __name__ == "__main__":
    # ============================================================
    # PARAMÈTRES — remplace par ceux du challenge
    # ============================================================

    # secp256k1 (le plus courant en CTF crypto-blockchain)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # Paramètres du LCG : k_{i+1} = (a*k_i + b) mod n
    a = 0xbace8ab1aeb06fa073d2a497e19e5909
    b = 0x48d207bb998bd4178a0bc63c1631e568

    sig1 = Signature(
        h=0x7bc409afe48bea19f8ba9ed4e7cf03dfa50782be907afeea89cc6d753f90708c,
        r=0x84ff233cc09ed46c271a5bfb79ca810ca89f00c1f35a9a8ac39a0b1187826891,
        s=0x4b7fb097262d96f471fa7430d376d05bec00af19a71cac9b48d4b53804936e54,
    )
    sig2 = Signature(
        h=0xa09be3c23e4e6ee534aacd94f55ba8931fa09d4fcece19e8e6b660ac97806c01,
        r=0x16c6f460284f41fdecdd826a2d3bca195772eca3f7b0f62a92d59330c3faa0c1,
        s=0xf92d88a58b0839027a2b7ed65e5d4c2350cd70040c6540878e069f048c6603c2,
    )

    d, k1, k2 = recover_d_from_lcg_nonces(n, a, b, sig1, sig2)
    print(f"[+] d  = {hex(d)}")
    print(f"[+] k1 = {hex(k1)}")
    print(f"[+] k2 = {hex(k2)}  (vérifié via LCG ET via sig2)")

    key = derive_aes_key_from_d(d, key_size_bytes=32)
    print(f"[+] Clé AES dérivée (SHA256(d)) = {key.hex()}")

    # Déchiffrement AES-256-GCM si le challenge fournit ciphertext/tag/nonce
    try:
        from Crypto.Cipher import AES

        ciphertext = bytes.fromhex(
            "ed6e8df55be59a6c05ddfff73b85c58fc8c45088db59071d39663e72bca9803d67db17770f37a7f43225"
        )
        tag = bytes.fromhex("23bd64f6ea9c6a4d49e27dd6b7bfb79c")
        nonce = bytes.fromhex("f44d6dba2523d98297263e5b785e0277")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        flag = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"[!!!] FLAG : {flag.decode()}")
    except ImportError:
        print("[*] pycryptodome non installé — d et la clé AES sont prêts, "
              "déchiffre avec ton propre outil AES-GCM.")
