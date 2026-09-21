#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — RSA Universal Decryptor
================================================
Usage :
    # Avec p et q
    python3 rsa_decrypt.py -c CIPHER --p P --q Q

    # Avec d directement
    python3 rsa_decrypt.py -c CIPHER --n N --d D

    # Avec n seul (tentative de factorisation auto)
    python3 rsa_decrypt.py -c CIPHER --n N --e E

    # Attaque small e (e=3)
    python3 rsa_decrypt.py -c CIPHER --n N --e 3 --attack small_e

    # Attaque Fermat (p et q proches)
    python3 rsa_decrypt.py -c CIPHER --n N --e E --attack fermat

    # Attaque Wiener (d petit)
    python3 rsa_decrypt.py -c CIPHER --n N --e E --attack wiener

Auteur : Xeno CTF Arsenal
================================================
"""

from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
import argparse
import base64
import binascii
import math
import sys
import requests

# ================================================
# COULEURS
# ================================================

G = "\033[92m"   # vert
R = "\033[91m"   # rouge
Y = "\033[93m"   # jaune
B = "\033[94m"   # bleu
NC = "\033[0m"   # reset

def ok(msg):  print(f"{G}[+]{NC} {msg}")
def err(msg): print(f"{R}[-]{NC} {msg}")
def inf(msg): print(f"{B}[*]{NC} {msg}")
def win(msg): print(f"{G}[!!!]{NC} {msg}")

# ================================================
# PARSING DES ENTIERS (dec, hex, base64)
# ================================================

def parse_int(value):
    value = str(value).strip()
    if value.startswith(("0x", "0X")):
        return int(value, 16)
    return int(value)

def b64decode_with_padding(value):
    raw = value.strip().encode() if isinstance(value, str) else value.strip()
    raw += b"=" * (-len(raw) % 4)
    return base64.b64decode(raw, validate=True)

def ciphertext_to_int(value, input_format="auto"):
    """Détecte et convertit automatiquement le format du ciphertext."""
    value = value.strip()

    if input_format == "int":
        return parse_int(value), "int"
    if input_format == "hex":
        value = value[2:] if value.startswith(("0x", "0X")) else value
        return bytes_to_long(bytes.fromhex(value)), "hex"
    if input_format == "base64":
        return bytes_to_long(b64decode_with_padding(value)), "base64"

    # Auto-detect
    if value.lstrip('-').isdigit():
        return int(value), "int"
    if value.startswith(("0x", "0X")):
        return bytes_to_long(bytes.fromhex(value[2:])), "hex"
    try:
        return bytes_to_long(b64decode_with_padding(value)), "base64"
    except (binascii.Error, ValueError):
        pass
    try:
        return bytes_to_long(bytes.fromhex(value)), "hex"
    except ValueError as exc:
        raise ValueError(
            "Format inconnu. Utilise --format int, base64 ou hex."
        ) from exc

# ================================================
# PADDING
# ================================================

def remove_pkcs1_v15_padding(block):
    if block.startswith((b"\x00\x02", b"\x00\x01")):
        sep = block.find(b"\x00", 2)
        if sep != -1:
            return block[sep + 1:], True
    return block.lstrip(b"\x00"), False

def maybe_base64_decode(payload):
    try:
        decoded = b64decode_with_padding(payload.decode("ascii"))
        if decoded:
            return decoded
    except Exception:
        pass
    return None

# ================================================
# ATTAQUE — SMALL E (cube root si e=3)
# ================================================

def attack_small_e(c, e):
    """
    Si e est petit (ex: 3) et le message n'est pas paddé,
    m^e < n → m = c^(1/e) (racine entière).
    """
    inf(f"Attaque Small-e (e={e})...")
    # Racine e-ième entière de c
    m = int(round(c ** (1/e)))
    # Affinage (Newton)
    for delta in range(-2, 3):
        candidate = m + delta
        if candidate ** e == c:
            win(f"Racine entière trouvée ! m = {candidate}")
            return candidate
    # Recherche par bisection
    lo, hi = 0, c
    while lo < hi:
        mid = (lo + hi) // 2
        val = mid ** e
        if val == c:
            win(f"Message trouvé par bisection ! m = {mid}")
            return mid
        elif val < c:
            lo = mid + 1
        else:
            hi = mid
    err("Small-e: racine entière non trouvée (message probablement paddé)")
    return None

# ================================================
# ATTAQUE — FERMAT (p et q proches)
# ================================================

def attack_fermat(n, max_iter=1_000_000):
    """
    Si p et q sont proches, Fermat factorise rapidement.
    n = p*q avec p ≈ q → p ≈ sqrt(n)
    """
    inf(f"Attaque Fermat ({max_iter} itérations max)...")
    a = math.isqrt(n)
    if a * a == n:
        ok(f"n est un carré parfait ! p = q = {a}")
        return a, a
    a += 1
    b2 = a * a - n
    for _ in range(max_iter):
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            ok(f"Fermat: p = {p}")
            ok(f"Fermat: q = {q}")
            return p, q
        a += 1
        b2 = a * a - n
    err("Fermat: p et q pas assez proches")
    return None, None

# ================================================
# ATTAQUE — WIENER (d petit)
# ================================================

def attack_wiener(e, n):
    """
    Wiener's attack: si d < n^(1/4)/3, on peut retrouver d
    via les fractions continues de e/n.
    """
    inf("Attaque Wiener (d petit)...")

    def continued_fraction(num, den):
        cf = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    def convergents(cf):
        convs = []
        for i in range(len(cf)):
            if i == 0:
                convs.append((cf[0], 1))
            elif i == 1:
                convs.append((cf[0]*cf[1]+1, cf[1]))
            else:
                h_prev2, k_prev2 = convs[-2]
                h_prev1, k_prev1 = convs[-1]
                h = cf[i] * h_prev1 + h_prev2
                k = cf[i] * k_prev1 + k_prev2
                convs.append((h, k))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        phi_candidate = (e * d - 1) // k
        # Vérifie si phi est valide : n - phi + 1 = p + q
        b = n - phi_candidate + 1
        discriminant = b * b - 4 * n
        if discriminant < 0:
            continue
        sqrt_disc = math.isqrt(discriminant)
        if sqrt_disc * sqrt_disc == discriminant:
            p = (b + sqrt_disc) // 2
            q = (b - sqrt_disc) // 2
            if p * q == n:
                ok(f"Wiener: d = {d}")
                ok(f"Wiener: p = {p}")
                ok(f"Wiener: q = {q}")
                return d, p, q
    err("Wiener: d pas assez petit")
    return None, None, None

# ================================================
# FACTORISATION VIA FACTORDB
# ================================================

def try_factordb(n):
    """Essaie de factoriser n via factordb.com."""
    inf("Tentative de factorisation via factordb.com...")
    try:
        r = requests.get(
            f"http://factordb.com/api",
            params={"query": str(n)},
            timeout=10
        )
        data = r.json()
        status = data.get("status", "")
        factors = data.get("factors", [])
        if status in ("FF", "P", "C") and len(factors) == 2:
            p = int(factors[0][0])
            q = int(factors[1][0])
            ok(f"FactorDB: p = {p}")
            ok(f"FactorDB: q = {q}")
            return p, q
        else:
            err(f"FactorDB: statut={status}, facteurs={factors}")
    except Exception as ex:
        err(f"FactorDB inaccessible : {ex}")
    return None, None

# ================================================
# CONSTRUCTION DE LA CLÉ PRIVÉE
# ================================================

def build_private_exponent(args):
    e = args.e

    # Cas 1 : d fourni directement
    if args.d is not None:
        if args.n is None and (args.p is None or args.q is None):
            raise ValueError("Avec --d, donne aussi --n ou --p et --q.")
        n = args.n if args.n is not None else args.p * args.q
        return n, e, args.d

    # Cas 2 : p et q fournis
    if args.p is not None and args.q is not None:
        n = args.p * args.q
        phi = (args.p - 1) * (args.q - 1)
        d = inverse(e, phi)
        return n, e, d

    # Cas 3 : n seul → tentatives de factorisation
    if args.n is not None:
        n = args.n

        # Wiener
        if args.attack in ("wiener", "auto"):
            d, p, q = attack_wiener(e, n)
            if d:
                phi = (p - 1) * (q - 1)
                return n, e, inverse(e, phi)

        # Fermat
        if args.attack in ("fermat", "auto"):
            p, q = attack_fermat(n)
            if p:
                phi = (p - 1) * (q - 1)
                d = inverse(e, phi)
                return n, e, d

        # FactorDB
        p, q = try_factordb(n)
        if p and q:
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            return n, e, d

        raise ValueError(
            "Impossible de calculer d. "
            "Donne --p et --q, ou --d, ou essaie --attack fermat/wiener."
        )

    raise ValueError("Donne au moins (--p et --q) ou (--n et --d) ou --n seul.")

# ================================================
# DÉCHIFFREMENT PRINCIPAL
# ================================================

def decrypt_rsa(args):
    n, e, d = build_private_exponent(args)
    c, detected_format = ciphertext_to_int(args.ciphertext, args.format)

    if c >= n:
        raise ValueError("c >= n. Vérifie le format ou la clé.")

    # Attaque small e (sans clé privée)
    if args.attack == "small_e":
        m = attack_small_e(c, e)
        if m is None:
            raise ValueError("Small-e échoué.")
    else:
        m = pow(c, d, n)

    key_len = (n.bit_length() + 7) // 8
    block   = long_to_bytes(m, key_len)
    payload, had_padding = remove_pkcs1_v15_padding(block)
    payload = payload.strip()

    return {
        "n"              : n,
        "e"              : e,
        "d"              : d,
        "c"              : c,
        "detected_format": detected_format,
        "block"          : block,
        "payload"        : payload,
        "had_padding"    : had_padding,
        "payload_b64"    : maybe_base64_decode(payload),
    }

# ================================================
# AFFICHAGE
# ================================================

def print_result(result):
    print()
    print("=" * 55)
    ok(f"Format ciphertext : {result['detected_format']}")
    ok(f"Padding PKCS#1    : {'oui' if result['had_padding'] else 'non'}")
    print("=" * 55)

    payload = result["payload"]

    win("MESSAGE DÉCHIFFRÉ :")
    print(f"  Texte : {payload.decode(errors='replace')}")
    print(f"  Hex   : {payload.hex()}")
    print(f"  Taille: {len(payload)} octets")

    if result["payload_b64"] is not None:
        decoded = result["payload_b64"]
        print()
        inf("Le payload ressemble à du base64 !")
        print(f"  Décodé texte : {decoded.decode(errors='replace')}")
        print(f"  Décodé hex   : {decoded.hex()}")

    print()

# ================================================
# ARGUMENTS
# ================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="RSA Universal Decryptor — Arsenal CTF"
    )
    parser.add_argument(
        "-c", "--ciphertext", required=True,
        help="Ciphertext : entier, base64 ou hex"
    )
    parser.add_argument(
        "--format",
        choices=["auto", "int", "base64", "hex"],
        default="auto",
        help="Format du ciphertext (défaut: auto)"
    )
    parser.add_argument("--p",   type=parse_int, help="Facteur premier p")
    parser.add_argument("--q",   type=parse_int, help="Facteur premier q")
    parser.add_argument("--e",   type=parse_int, default=65537, help="Exposant public e (défaut: 65537)")
    parser.add_argument("--n",   type=parse_int, help="Module RSA n")
    parser.add_argument("--d",   type=parse_int, help="Exposant privé d")
    parser.add_argument(
        "--attack",
        choices=["auto", "small_e", "fermat", "wiener", "none"],
        default="auto",
        help="Attaque à utiliser (défaut: auto)"
    )
    return parser.parse_args()

# ================================================
# MAIN
# ================================================

if __name__ == "__main__":
    try:
        print_result(decrypt_rsa(parse_args()))
    except Exception as exc:
        err(str(exc))
        sys.exit(1)
