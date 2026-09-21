# Remplace ces valeurs par les 16 octets trouvés à DAT_00104010
donnees_attendues = [0xb9, 0x0f, 0x05, 0xd3, 0x78, 0x18, 0x56]

def solve():
    bVar3 = 0
    mot_de_passe = ""
    for i in range(16):
        cible = donnees_attendues[i]
        # 1. Inverser le XOR 0x33
        etape1 = cible ^ 0x33
        # 2. Inverser la multiplication par 2 (division entière)
        etape2 = etape1 // 2
        # 3. Inverser le XOR avec la clé tournante bVar3
        code_ascii = etape2 ^ bVar3
        mot_de_passe += chr(code_ascii & 0xFF)
        # Incrémenter la clé comme dans le code C
        bVar3 = (bVar3 + 7) & 0xFF

    print(f"Le mot de passe est : {mot_de_passe}")
solve()
