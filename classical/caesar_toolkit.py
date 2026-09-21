#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — Caesar Toolkit
================================================
Deux modes de résolution :

1. brute_force_all_shifts(text)
   Affiche les 26 décalages d'un coup — repérage visuel rapide quand
   TOUT le texte partage le même décalage.

2. per_word_dictionary_match(text, wordlist_path)
   Pour CHAQUE mot, teste les 26 décalages et ne garde que ceux qui
   donnent un vrai mot du dictionnaire. Indispensable quand le décalage
   change d'un mot à l'autre (technique utilisée pour retrouver la
   comptine "Un, deux, trois, j'irai dans les bois..." cachée mot par
   mot avec un décalage différent à chaque position).

Wordlist FR par défaut si aucune n'est fournie :
    https://raw.githubusercontent.com/words/an-array-of-french-words/master/index.json

Auteur : Xeno CTF Arsenal
================================================
"""

import json
import re
import urllib.request

FR_WORDLIST_URL = (
    "https://raw.githubusercontent.com/words/an-array-of-french-words/"
    "master/index.json"
)


def shift_char(c: str, k: int) -> str:
    if c.isalpha():
        base = ord('a') if c.islower() else ord('A')
        return chr((ord(c) - base - k) % 26 + base)
    return c


def shift_text(text: str, k: int) -> str:
    return ''.join(shift_char(c, k) for c in text)


def brute_force_all_shifts(text: str, show: bool = True):
    """Retourne {décalage: texte_décalé} pour les 26 décalages. Affiche si show=True."""
    results = {}
    for k in range(26):
        out = shift_text(text, k)
        results[k] = out
        if show:
            print(f"{k:2d} | {out}")
    return results


def load_wordlist(path_or_url: str = None) -> set:
    """Charge une wordlist JSON (liste de mots) depuis un fichier local ou une URL."""
    path_or_url = path_or_url or FR_WORDLIST_URL
    if path_or_url.startswith("http"):
        with urllib.request.urlopen(path_or_url) as resp:
            words = json.load(resp)
    else:
        with open(path_or_url, encoding="utf-8") as f:
            words = json.load(f)
    return set(w.lower() for w in words)


def per_word_dictionary_match(text: str, wordlist: set, min_len: int = 2):
    """
    Pour chaque mot du texte (multi-lignes autorisé), teste les 26
    décalages et retourne les correspondances trouvées dans le dico.

    Retourne : liste de (ligne_idx, mot_original, [(décalage, mot_décodé), ...])
    """
    results = []
    for li, line in enumerate(text.split('\n')):
        for tok in line.split(' '):
            core = re.sub(r"[^A-Za-z']", '', tok)
            if len(core) < min_len:
                continue
            matches = []
            for k in range(26):
                cand = shift_text(core, k)
                if cand.lower() in wordlist:
                    matches.append((k, cand))
            if matches:
                results.append((li, tok, matches))
    return results


def solve_and_print(text: str, wordlist_path: str = None):
    """Pipeline complet : charge le dico, matche mot par mot, affiche le résumé."""
    print("[*] Chargement de la wordlist...")
    wordlist = load_wordlist(wordlist_path)
    print(f"[+] {len(wordlist)} mots chargés.\n")

    matches = per_word_dictionary_match(text, wordlist)
    for li, tok, cands in matches:
        cands_str = ", ".join(f"k={k}:{w}" for k, w in cands)
        print(f"  ligne {li+1:2d} | {tok!r:20s} -> {cands_str}")

    return matches


if __name__ == "__main__":
    print("=== Démo 1 : décalage unique sur tout le texte ===")
    brute_force_all_shifts("Khoor Zruog")

    print("\n=== Démo 2 : décalage différent par mot (nécessite une wordlist) ===")
    sample = "tm bcsv qolfp"  # -> "un deux trois" (k=25, 24, 23 respectivement)
    try:
        solve_and_print(sample)
    except Exception as e:
        print(f"[!] Wordlist indisponible dans cet environnement ({e}). "
              f"Fournis un fichier JSON local via solve_and_print(text, 'chemin.json').")
