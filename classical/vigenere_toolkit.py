#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — Vigenère Toolkit
================================================
1. encode(text, key) / decode(text, key)   — quand la clé est connue
2. guess_key_length(ciphertext)             — Indice de Coïncidence (IC),
   pas besoin de connaître la clé
3. crack(ciphertext)                        — casse complète sans clé :
   devine la longueur (IC), puis chaque sous-clé par analyse de fréquence
   (corrélation avec les fréquences des lettres en français/anglais)

Auteur : Xeno CTF Arsenal
================================================
"""

from collections import Counter

# Fréquences approximatives des lettres (%), pour l'analyse de fréquence
FREQ_EN = {
    'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 12.7, 'f': 2.2, 'g': 2.0,
    'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 4.0, 'm': 2.4, 'n': 6.7,
    'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1, 'u': 2.8,
    'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
}
FREQ_FR = {
    'a': 7.6, 'b': 0.9, 'c': 3.3, 'd': 3.7, 'e': 14.7, 'f': 1.1, 'g': 1.0,
    'h': 0.7, 'i': 7.5, 'j': 0.5, 'k': 0.05, 'l': 5.5, 'm': 3.0, 'n': 7.1,
    'o': 5.3, 'p': 3.0, 'q': 1.4, 'r': 6.6, 's': 8.0, 't': 7.3, 'u': 6.3,
    'v': 1.6, 'w': 0.04, 'x': 0.4, 'y': 0.3, 'z': 0.1,
}


def _shift_letter(c, k, decode=True):
    if not c.isalpha():
        return c
    base = ord('A') if c.isupper() else ord('a')
    kk = k if decode else -k
    return chr((ord(c) - base - kk) % 26 + base)


def encode(text: str, key: str) -> str:
    key = [ord(c.lower()) - ord('a') for c in key if c.isalpha()]
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            out.append(_shift_letter(c, key[ki % len(key)], decode=False))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)


def decode(text: str, key: str) -> str:
    key = [ord(c.lower()) - ord('a') for c in key if c.isalpha()]
    out, ki = [], 0
    for c in text:
        if c.isalpha():
            out.append(_shift_letter(c, key[ki % len(key)], decode=True))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)


def _index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def guess_key_length(ciphertext: str, max_len: int = 20):
    """
    Teste chaque longueur de clé candidate en calculant l'IC moyen des
    sous-séquences. Un IC proche de ~0.065-0.07 (français/anglais) indique
    la bonne longueur ; un IC proche de ~0.038 (uniforme) indique une
    mauvaise longueur (le résultat ressemble encore à du bruit).
    """
    letters = [c.lower() for c in ciphertext if c.isalpha()]
    scores = []
    for klen in range(1, max_len + 1):
        subs = [''.join(letters[i::klen]) for i in range(klen)]
        avg_ic = sum(_index_of_coincidence(s) for s in subs) / klen
        scores.append((klen, avg_ic))
    scores.sort(key=lambda x: -x[1])
    return scores


def _best_shift_for_subsequence(sub: str, freq_table: dict) -> int:
    """Trouve le décalage qui corrèle le mieux avec la table de fréquences."""
    best_shift, best_score = 0, -1
    n = len(sub)
    if n == 0:
        return 0
    counts = Counter(c.lower() for c in sub if c.isalpha())
    for shift in range(26):
        score = 0.0
        for letter, cnt in counts.items():
            plain_letter = chr((ord(letter) - ord('a') - shift) % 26 + ord('a'))
            score += (cnt / n) * freq_table.get(plain_letter, 0)
        if score > best_score:
            best_score, best_shift = score, shift
    return best_shift


def crack(ciphertext: str, key_length: int = None, lang: str = "fr", max_len: int = 20):
    """
    Casse un Vigenère sans connaître la clé.
    Si key_length n'est pas fourni, le devine automatiquement via IC.
    lang : "fr" ou "en" (table de fréquences à utiliser).
    Retourne (clé_devinée, texte_déchiffré).
    """
    freq_table = FREQ_FR if lang == "fr" else FREQ_EN

    if key_length is None:
        candidates = guess_key_length(ciphertext, max_len)
        # Piège classique : un multiple de la vraie longueur (2x, 3x...) a
        # souvent un IC aussi élevé (voire plus, sur un texte court) que la
        # vraie longueur. On préfère donc la PLUS PETITE longueur dont l'IC
        # dépasse un seuil proche du langage naturel, plutôt que le max brut.
        THRESHOLD = 0.06
        plausible = [c for c in candidates if c[1] >= THRESHOLD]
        key_length = min(plausible, key=lambda c: c[0])[0] if plausible else candidates[0][0]
        print(f"[*] Longueur de clé devinée : {key_length} "
              f"(IC={dict(candidates)[key_length]:.4f})")
        print(f"    Top candidats : {sorted(candidates, key=lambda c: -c[1])[:5]}")

    letters = [c.lower() for c in ciphertext if c.isalpha()]
    key = []
    for i in range(key_length):
        sub = ''.join(letters[i::key_length])
        shift = _best_shift_for_subsequence(sub, freq_table)
        key.append(chr(shift + ord('a')))
    key = ''.join(key)

    print(f"[+] Clé devinée : {key}")
    return key, decode(ciphertext, key)


if __name__ == "__main__":
    print("=== Démo 1 : encode/decode avec clé connue ===")
    msg = "ATTAQUE A L AUBE"
    key = "LOV"
    enc = encode(msg, key)
    dec = decode(enc, key)
    print(f"  clair   : {msg}")
    print(f"  chiffré : {enc}")
    print(f"  déchif. : {dec}")
    assert dec == msg

    print("\n=== Démo 2 : crack sans connaître la clé ===")
    secret_key = "CYBER"
    plaintext = ("CETTE PHRASE EST ASSEZ LONGUE POUR QUE L ANALYSE DE FREQUENCE "
                 "FONCTIONNE CORRECTEMENT SUR CE TEXTE CHIFFRE EN VIGENERE AVEC "
                 "UNE CLE INCONNUE DE L ATTAQUANT MAIS RETROUVEE PAR LA MACHINE")
    ciphertext = encode(plaintext, secret_key)
    found_key, recovered = crack(ciphertext, lang="fr")
    print(f"  clé réelle   : {secret_key}")
    print(f"  clé trouvée  : {found_key}")
    print(f"  texte récup. : {recovered[:70]}...")
