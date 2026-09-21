# 🗝️ CryptoArsenal

> *"Every cipher trusts something. Find what it trusts, and it breaks."*

Une boîte à outils de cryptographie offensive pour CTF — RSA, ECDSA, AES,
XOR, chiffrement classique (César/Vigenère), padding oracle, encodages
en cascade, et formats de hash pour hashcat.

Chaque module a été **conçu, écrit et vérifié sur un vrai challenge résolu**
(pas de théorie jamais testée) — la démo intégrée à chaque script (`python3
fichier.py` sans argument) reproduit un flag réel qu'on a obtenu avec.

---

## 📦 Structure

```
CryptoArsenal/
├── rsa/
│   ├── rsa_decrypt.py                     # Wiener, Fermat, e petit, factordb...
│   └── rsa_blinding_attack.py
├── ecdsa/
│   ├── ecdsa_toolkit.py                   # signature, vérification, nonce réutilisé (même r)
│   ├── ecdsa_partial_nonce_attack_oracle.py
│   └── ecdsa_lcg_nonce_attack.py          # 🆕 nonces liés par un LCG connu
├── aes/
│   ├── aes_universal.py                   # 🆕 ECB/CBC/GCM/CTR, dérivation de clé multi-méthode
│   ├── AES_Decrypt.py
│   └── Script_AES_decrypt.py
├── xor/
│   ├── xor_toolkit.py                     # 🆕 single-byte, repeating-key, crib-dragging
│   ├── Script_xor_decrypt.py
│   └── XorDecript_0x5B
├── classical/
│   ├── caesar_toolkit.py                  # 🆕 bruteforce + solveur par mot (dictionnaire)
│   ├── vigenere_toolkit.py                # 🆕 encode/decode + crack sans clé (IC + fréquences)
│   ├── cipher_cesaer.py
│   └── decode_flag_vigenere.py
├── padding_oracle/
│   └── padding_oracle_attack.py           # 🆕 attaque Vaudenay générique (oracle pluggable)
├── encoding/
│   └── multi_layer_decoder.py             # 🆕 hex/base64/base32/base85/base58/rot13 en cascade
├── hashes/
│   └── hash_format_builders.py            # 🆕 formats hashcat composites ($mysqlna$, $racf$...)
├── openssl/
│   └── openssl_decrypt.sh
├── convertisseur/
│   └── convertisseur_hex_ascii.py
├── requirements.txt
└── LICENSE
```

🆕 = ajouté pour généraliser une attaque qu'on avait résolue *ad hoc* en
plein CTF, afin de ne plus jamais repartir de zéro dessus.

---

## 🚀 Installation

```bash
git clone https://github.com/xeno369/CryptoArsenal.git
cd CryptoArsenal
pip install -r requirements.txt --break-system-packages
```

Chaque script est autonome — pas besoin d'installer tout le dépôt pour en
utiliser un seul, juste `pycryptodome` (et `sympy` pour Wiener/RSA).

---

## 🧰 Le dépôt en un coup d'œil

| Module | Technique | Quand l'utiliser | Testé sur |
|---|---|---|---|
| `rsa_decrypt.py` | Wiener (fractions continues) | `d` anormalement petit vs `n` | *Petite fuite*, ESIG Tech Arena |
| `ecdsa_toolkit.py` | Nonce réutilisé (même `r`) | Deux signatures avec le même `k` | — |
| `ecdsa_lcg_nonce_attack.py` | Nonces liés par un LCG connu | `k_{i+1} = a·k_i + b mod n` publié | Challenge ECDSA/LCG, ESIG Tech Arena |
| `aes_universal.py` | ECB/CBC/GCM/CTR + dérivation de clé | N'importe quel AES avec clé/IV/nonce/tag connus | Idem (déchiffrement final du flag) |
| `xor_toolkit.py` | Single-byte, repeating-key, crib-dragging | XOR avec clé courte inconnue | — |
| `caesar_toolkit.py` | Bruteforce 26 + solveur par mot (dico) | Décalage unique **ou** différent par mot | Comptine "Un, deux, trois..." cachée |
| `vigenere_toolkit.py` | Indice de Coïncidence + fréquences | Vigenère sans connaître la clé | — |
| `padding_oracle_attack.py` | Padding Oracle CBC (Vaudenay) | Un service confirme/infirme juste un padding PKCS#7 | *Oracle bavard*, ESIG Tech Arena |
| `multi_layer_decoder.py` | Auto-détection + décodage en cascade | Encodages empilés (hex→b64→b32...) | Layers Discord/stégano, plusieurs CTF |
| `hash_format_builders.py` | Formats hashcat composites | MySQL CRAM-SHA1, RACF... | MITM ARP-spoofing (MySQL) |

---

## 💡 Exemples rapides

**Casser un RSA à `d` faible (Wiener) :**
```bash
python3 rsa/rsa_decrypt.py --wiener --n <n> --e <e> --c <c>
```

**Récupérer `d` depuis deux signatures ECDSA à nonces liés par LCG :**
```python
from ecdsa_lcg_nonce_attack import recover_d_from_lcg_nonces, Signature
d, k1, k2 = recover_d_from_lcg_nonces(n, a, b, Signature(h1, r1, s1), Signature(h2, r2, s2))
```

**Déchiffrer un jeton AES-256-GCM dérivé d'une clé entière :**
```bash
python3 aes/aes_universal.py --mode gcm --key-derive raw \
  --key-hex <64 car. hex> --nonce-hex <...> --tag-hex <...> --ciphertext-hex <...>
```

**Casser un padding oracle CBC (branche ton propre oracle réseau) :**
```python
from padding_oracle_attack import decrypt_padding_oracle

def my_oracle(prev_block, target_block):
    r = requests.post(URL, data={"iv": prev_block.hex(), "ct": target_block.hex()})
    return "padding valide" in r.text

plaintext = decrypt_padding_oracle(my_oracle, iv, ciphertext)
```

**Décoder un mystère à couches multiples :**
```bash
python3 encoding/multi_layer_decoder.py "gASVCAAAAAAAAACMBHRlc3SULg=="
```

---

## 🎯 Philosophie

La plupart des challenges crypto de CTF ne cassent pas les maths — ils
cassent une **implémentation** : un paramètre affaibli exprès (`d` trop
petit), un canal d'information résiduel (padding oracle), une source
d'aléa qui n'en est pas une (LCG comme générateur de nonce), une clé
réutilisée. Ce dépôt encode ces schémas d'attaque une fois pour toutes,
pour ne plus jamais repartir d'une feuille blanche en pleine compétition.

---

## 👤 Auteur

**Xeno** ([@Xeno-369](https://github.com/Xeno-369)) — étudiant en
cybersécurité, IAI-Togo. Écrit et maintenu au fil des CTF (Cyberini,
Root-Me, TryHackMe, ESIG Tech Arena, CTFtime).

Contributions bienvenues — PR ou issue si tu as une variante d'attaque
qui manque encore à l'arsenal.

## 📄 Licence

MIT — utilise, modifie, redistribue librement. Voir [LICENSE](LICENSE).
