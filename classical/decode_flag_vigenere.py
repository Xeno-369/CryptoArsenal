#!/usr/bin/env python3
# ============================================================
#  decode_flag.py — Vigenère decoder pour EcowasCTF
#  Clé : Nyansapo
#  Flag encodé : RaojssRHS{3pz03g_0f_4d1bxp4_n1v3a3r3}
# ============================================================

def vigenere_decode(text, key):
    result = []
    key = key.upper()  # on met la clé en majuscules

    for i, c in enumerate(text):
        if c.isalpha():  # on traite seulement les lettres
            # Le décalage = position de la lettre de clé dans l'alphabet
            shift = ord(key[i % len(key)]) - ord('A')

            if c.isupper():
                # Lettre majuscule : on décale dans A-Z
                decoded_char = chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
            else:
                # Lettre minuscule : on décale dans a-z
                decoded_char = chr((ord(c) - ord('a') - shift) % 26 + ord('a'))

            result.append(decoded_char)
        else:
            # Chiffres, {, }, _ → on les garde tels quels
            # MAIS on avance quand même l'index i (boucle for)
            result.append(c)

    return ''.join(result)


# ── Paramètres ──────────────────────────────────────────────
encoded = "RaojssRHS{3pz03g_0f_4d1bxp4_n1v3a3r3}"
key     = "Nyansapo"

# ── Décodage ────────────────────────────────────────────────
decoded = vigenere_decode(encoded, key)

# ── Résultat ────────────────────────────────────────────────
print(f"Texte encodé : {encoded}")
print(f"Clé          : {key}")
print(f"Flag décodé  : {decoded}")
