#!/usr/bin/env python3

from Crypto.Cipher import AES
from hashlib import md5, sha256

# =========================
# CONFIG A MODIFIER
# =========================

hex_data = "e29cde241a699057f58a50742bf7bcb584e979f2bbd7c4d3c0c74c7a8d43b55d9adea5faa3918a6a223315b4a43b67fd"
password = "akoma"

# =========================
# PREPARATION
# =========================

data = bytes.fromhex(hex_data)

# Génération des clés possibles
keys = [
    password.encode(),
    md5(password.encode()).digest(),
    sha256(password.encode()).digest(),
]

# Padding remover
def unpad(data):
    try:
        pad_len = data[-1]
        if pad_len < 16:
            return data[:-pad_len]
    except:
        pass
    return data

# =========================
# TEST AES
# =========================

for key in keys:
    print("\n==============================")
    print("[+] Test avec clé :", key)

    # Ajuster la clé (16, 24, 32 bytes)
    for size in [16, 24, 32]:
        k = key.ljust(size, b'\x00')[:size]

        print(f"\n--- Taille clé : {size} ---")

        # ===== ECB =====
        try:
            cipher = AES.new(k, AES.MODE_ECB)
            pt = cipher.decrypt(data)
            pt_clean = unpad(pt)

            print("[ECB raw ]", pt)
            print("[ECB txt ]", pt_clean.decode(errors="ignore"))
        except:
            pass

        # ===== CBC IV = 0 =====
        try:
            iv = b"\x00" * 16
            cipher = AES.new(k, AES.MODE_CBC, iv)
            pt = cipher.decrypt(data)
            pt_clean = unpad(pt)

            print("[CBC 0 raw]", pt)
            print("[CBC 0 txt]", pt_clean.decode(errors="ignore"))
        except:
            pass

        # ===== CBC IV = début du ciphertext =====
        try:
            iv = data[:16]
            ct = data[16:]
            cipher = AES.new(k, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            pt_clean = unpad(pt)

            print("[CBC IV raw]", pt)
            print("[CBC IV txt]", pt_clean.decode(errors="ignore"))
        except:
            pass
