#!/usr/bin/env python3

from itertools import product

ciphertext_hex = "e29cde241a699057f58a50742bf7bcb584e979f2bbd7c4d3c0c74c7a8d43b55d9adea5faa3918a6a223315b4a43b67fd"
data = bytes.fromhex(ciphertext_hex)

base_key = b"akoma"
flag_prefix = b"EcowasCTF{"

# tester variantes simples
keys = [
    base_key,
    base_key.upper(),
    base_key[::-1],
    base_key + b"123",
    base_key + b"_key"
]

for key in keys:
    decoded = bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
    if flag_prefix in decoded:
        print("[✔] FLAG TROUVÉ :", decoded.decode())
        break
    else:
        print("[ ] Test avec", key, ":", decoded.decode(errors="ignore"))
