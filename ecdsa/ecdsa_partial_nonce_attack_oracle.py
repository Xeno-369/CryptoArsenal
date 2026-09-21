#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — ECDSA Partial Nonce Attack
================================================
Attaque : Partial Nonce Leak (MSB connus)
Algo    : Meet-in-the-Middle
Courbe  : secp256k1 (adaptable)

Usage CTF :
    - Oracle donne nonce_msb + unknown_bits
    - On récupère la clé privée
    - On forge une signature

Auteur  : Xeno CTF Arsenal
================================================
"""

import requests
from hashlib import sha256

# ================================================
# CONFIGURATION — À MODIFIER SELON LE CHALLENGE
# ================================================

TARGET      = "http://TARGET_IP:PORT"   # URL du challenge
SIGN_ROUTE  = "/sign"                   # Route pour signer
VERIFY_ROUTE= "/verify"                 # Route pour vérifier
PUBKEY_ROUTE= "/pubkey"                 # Route pour la clé publique
SECRET_MSG  = "message à signer"       # Message cible (souvent donné dans l'énoncé)
UNKNOWN_BITS= 20                        # Nombre de bits inconnus du nonce

# Paramètres de la courbe secp256k1 (ne pas modifier sauf si autre courbe)
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# ================================================
# ÉTAPE 1 — RÉCUPÉRER LA CLÉ PUBLIQUE
# ================================================

def get_pubkey():
    """Récupère la clé publique depuis l'oracle."""
    print("[*] Récupération de la clé publique...")
    r = requests.get(f"{TARGET}{PUBKEY_ROUTE}")
    data = r.json()
    print(f"[+] Clé publique récupérée")
    print(f"    pub_x : {data.get('pub_x', '?')}")
    print(f"    pub_y : {data.get('pub_y', '?')}")
    return data

# ================================================
# ÉTAPE 2 — COLLECTER LES SIGNATURES
# ================================================

def get_signature(message):
    """Demande une signature à l'oracle."""
    r = requests.post(
        f"{TARGET}{SIGN_ROUTE}",
        json={"message": message}
    )
    return r.json()

def collect_signatures(count=5):
    """Collecte plusieurs signatures depuis l'oracle."""
    print(f"\n[*] Collecte de {count} signatures...")
    sigs = []
    for i in range(count):
        msg = f"message_{i}"
        data = get_signature(msg)
        sig = {
            "message": msg,
            "h"      : int(data["h"]),
            "r"      : int(data["r"]),
            "s"      : int(data["s"]),
            "msb"    : int(data["nonce_msb"])
        }
        sigs.append(sig)
        print(f"[+] Signature {i+1} : r={str(sig['r'])[:20]}...")
    return sigs

# ================================================
# ÉTAPE 3 — MEET-IN-THE-MIDDLE ATTACK
# ================================================

def compute_AB(sig, n, bits):
    """
    Calcule A et B pour une signature.
    d = A + B*x  mod n
    où x est la partie inconnue du nonce (0 <= x < 2^bits)
    """
    r_inv = pow(sig['r'], -1, n)
    A = (sig['s'] * sig['msb'] * (2**bits) - sig['h']) * r_inv % n
    B = sig['s'] * r_inv % n
    return A, B

def meet_in_the_middle(sigs, n, bits):
    """
    Attaque Meet-in-the-Middle sur 2 signatures.
    Complexité : O(2^bits) au lieu de O(2^(2*bits))
    """
    print(f"\n[*] Lancement Meet-in-the-Middle (2^{bits} = {2**bits} itérations)...")

    A1, B1 = compute_AB(sigs[0], n, bits)
    A2, B2 = compute_AB(sigs[1], n, bits)

    # Construction du dictionnaire depuis sig1
    print("[*] Construction du dictionnaire...")
    d_map = {}
    for x in range(2**bits):
        d = (A1 + B1 * x) % n
        d_map[d] = x

    # Recherche de collision avec sig2
    print("[*] Recherche de collision...")
    for x in range(2**bits):
        d = (A2 + B2 * x) % n
        if d in d_map:
            print(f"[!!!] Clé privée trouvée !")
            print(f"      d = {d}")
            return d

    # Si pas trouvé avec sig1+sig2, essaie d'autres combinaisons
    print("[-] Pas trouvé avec sig1+sig2, essai des autres combinaisons...")
    for i in range(len(sigs)):
        for j in range(len(sigs)):
            if i == j:
                continue
            Ai, Bi = compute_AB(sigs[i], n, bits)
            Aj, Bj = compute_AB(sigs[j], n, bits)
            d_map = {(Ai + Bi*x) % n: x for x in range(2**bits)}
            for x in range(2**bits):
                d = (Aj + Bj*x) % n
                if d in d_map:
                    print(f"[!!!] Clé privée trouvée avec sig{i+1}+sig{j+1} !")
                    print(f"      d = {d}")
                    return d

    print("[-] Clé privée non trouvée")
    return None

# ================================================
# ÉTAPE 4 — FORGER UNE SIGNATURE
# ================================================

def forge_signature(privkey, message):
    """Forge une signature avec la clé privée récupérée."""
    print(f"\n[*] Forge de signature pour : '{message}'")
    try:
        from ecdsa import SigningKey, SECP256k1
        sk  = SigningKey.from_secret_exponent(privkey, curve=SECP256k1)
        sig = sk.sign(message.encode(), hashfunc=sha256)
        r   = int.from_bytes(sig[:32], 'big')
        s   = int.from_bytes(sig[32:], 'big')
        print(f"[+] Signature forgée !")
        print(f"    r = {r}")
        print(f"    s = {s}")
        return r, s
    except ImportError:
        print("[!] pip install ecdsa")
        return None, None

# ================================================
# ÉTAPE 5 — SOUMETTRE ET RÉCUPÉRER LE FLAG
# ================================================

def submit_flag(message, r, s):
    """Soumet la signature forgée pour récupérer le flag."""
    print(f"\n[*] Soumission de la signature...")
    resp = requests.post(
        f"{TARGET}{VERIFY_ROUTE}",
        json={"message": message, "r": r, "s": s}
    )
    print(f"[!!!] Réponse : {resp.text}")
    return resp.json()

# ================================================
# UTILISATION AVEC SIGNATURES MANUELLES
# ================================================

def attack_with_manual_sigs(sigs, privkey=None):
    """
    Si t'as déjà collecté les signatures manuellement.
    Format sigs :
    [
        {"h": int, "r": int, "s": int, "msb": int},
        ...
    ]
    """
    if not privkey:
        privkey = meet_in_the_middle(sigs, N, UNKNOWN_BITS)

    if privkey:
        r, s = forge_signature(privkey, SECRET_MSG)
        if r and s:
            submit_flag(SECRET_MSG, r, s)

# ================================================
# MAIN — FLOW AUTOMATIQUE COMPLET
# ================================================

def auto_attack():
    """Flow complet automatique."""
    print("=" * 50)
    print("  ECDSA Partial Nonce Attack — CTF Arsenal")
    print("=" * 50)

    # 1. Clé publique
    get_pubkey()

    # 2. Signatures
    sigs = collect_signatures(count=5)

    # 3. Clé privée
    privkey = meet_in_the_middle(sigs, N, UNKNOWN_BITS)
    if not privkey:
        print("[-] Échec — essaie d'augmenter count dans collect_signatures()")
        return

    # 4. Forge
    r, s = forge_signature(privkey, SECRET_MSG)
    if not r:
        return

    # 5. Flag
    submit_flag(SECRET_MSG, r, s)

# ================================================
# EXEMPLE D'UTILISATION AVEC SIGNATURES CONNUES
# (copie-colle tes signatures ici si tu les as déjà)
# ================================================

MANUAL_SIGS = [
    # {
    #     "h"  : 20329878786436204988385760252021328656300425018755239228739303522659023427620,
    #     "r"  : 78539200880775885206468414123531317765221144776612215748252215172445290077166,
    #     "s"  : 44160292514509673616948616780776621493398079834237419823285488453381042000712,
    #     "msb": 36506763952777953975591713294265038763552526884988169372298670686675572
    # },
    # Ajoute d'autres signatures ici...
]

# ================================================
# LANCEMENT
# ================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "manual":
        # Mode manuel — utilise les signatures dans MANUAL_SIGS
        if len(MANUAL_SIGS) < 2:
            print("[!] Ajoute au moins 2 signatures dans MANUAL_SIGS")
        else:
            attack_with_manual_sigs(MANUAL_SIGS)
    else:
        # Mode auto — contacte l'oracle directement
        auto_attack()
