#!/usr/bin/env python3
"""
================================================
ARSENAL/CRYPTO — RSA Oracle Blinding Attack
================================================
Attaque : RSA Chosen Ciphertext (Blinding)
Contexte : Oracle déchiffre tout sauf c secret

Principe :
    1. Choisir r aléatoire tel que gcd(r, n) = 1
    2. c' = c * r^e  mod n  (masquage)
    3. Envoyer c' à l'oracle → m' = m * r  mod n
    4. m  = m' * r⁻¹  mod n  (démasquage)

Auteur : Xeno CTF Arsenal
================================================
"""

import socket
import random
import math

# ================================================
# CONFIGURATION — À MODIFIER SELON LE CHALLENGE
# ================================================

HOST = "HOST_NAME"
PORT = "PORT"

n = "COMPSANT1_PUBKEY"
e = "COMPOSANT2_PUBKEY"
C= "CIPHER_TEXT"

# ================================================
# ÉTAPE 1 — GÉNÉRER LE CIPHERTEXT MASQUÉ
# ================================================

def blind_ciphertext(c, e, n):
    """
    Masque c avec un r aléatoire.
    c' = c * r^e  mod n
    """
    print("[*] Génération du ciphertext masqué...")
    while True:
        r = random.randint(2, n - 1)
        if math.gcd(r, n) == 1:
            break
    r_e = pow(r, e, n)
    c_blind = (c * r_e) % n
    print(f"[+] r      = {r}")
    print(f"[+] c'     = {c_blind}")
    return c_blind, r

# ================================================
# ÉTAPE 2 — COMMUNIQUER AVEC L'ORACLE
# ================================================

def talk_to_oracle(host, port, c_blind):
    """
    Connexion TCP à l'oracle et envoi du ciphertext masqué.
    Retourne la réponse déchiffrée (m').
    """
    print(f"\n[*] Connexion à {host}:{port}...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.settimeout(10)
        
        # Lire le banner/prompt initial
        banner = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                banner += chunk
                # Stop si on a un prompt (: ou > ou \n)
                if b":" in chunk or b">" in chunk or b"$ " in chunk:
                    break
        except socket.timeout:
            pass
        
        print(f"[+] Oracle dit :\n{banner.decode(errors='ignore')}")
        
        # Envoyer le ciphertext masqué
        payload = str(c_blind).encode() + b"\n"
        print(f"\n[*] Envoi de c' à l'oracle...")
        s.send(payload)
        
        # Lire la réponse
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\n" in chunk:
                    break
        except socket.timeout:
            pass
        
        print(f"[+] Réponse oracle : {response.decode(errors='ignore')}")
        return response.decode(errors='ignore').strip()

# ================================================
# ÉTAPE 3 — EXTRAIRE m' DE LA RÉPONSE
# ================================================

def extract_m_prime(response):
    """
    Extrait la valeur numérique m' depuis la réponse de l'oracle.
    Adapte cette fonction selon le format de réponse.
    """
    import re
    # Cherche un grand nombre dans la réponse
    numbers = re.findall(r'\d{10,}', response)
    if numbers:
        # Prend le plus grand nombre trouvé
        m_prime = max(int(x) for x in numbers)
        print(f"[+] m' extrait : {m_prime}")
        return m_prime
    
    # Essaie de convertir directement
    try:
        return int(response.strip())
    except:
        print(f"[-] Impossible d'extraire m' depuis : {response}")
        return None

# ================================================
# ÉTAPE 4 — DÉMASQUER POUR OBTENIR m
# ================================================

def unblind(m_prime, r, n):
    """
    Retire le masque r pour obtenir m.
    m = m' * r⁻¹  mod n
    """
    print("\n[*] Démasquage...")
    r_inv = pow(r, -1, n)
    m = (m_prime * r_inv) % n
    print(f"[+] m (entier) = {m}")
    return m

# ================================================
# ÉTAPE 5 — CONVERTIR EN TEXTE
# ================================================

def int_to_text(m):
    """Convertit un entier en texte lisible."""
    print("\n[*] Conversion en texte...")
    try:
        # Méthode standard
        text = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
        print(f"[!!!] Message déchiffré : {text}")
        return text
    except UnicodeDecodeError:
        try:
            # Essaie latin-1
            text = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('latin-1')
            print(f"[!!!] Message déchiffré (latin-1) : {text}")
            return text
        except:
            # Affiche en hex
            hex_val = hex(m)
            print(f"[+] En hex : {hex_val}")
            return hex_val

# ================================================
# MAIN — FLOW COMPLET
# ================================================

def rsa_blinding_attack():
    print("=" * 55)
    print("  ARSENAL/CRYPTO — RSA Oracle Blinding Attack")
    print("=" * 55)
    print(f"\n[*] Paramètres RSA :")
    print(f"    n = {str(n)[:40]}...")
    print(f"    e = {e}")
    print(f"    c = {str(c)[:40]}...")

    # 1. Masquer c
    c_blind, r = blind_ciphertext(c, e, n)

    # 2. Envoyer à l'oracle
    response = talk_to_oracle(HOST, PORT, c_blind)

    # 3. Extraire m'
    m_prime = extract_m_prime(response)
    if m_prime is None:
        print("\n[!] Ajuste extract_m_prime() selon la réponse de l'oracle")
        print(f"[!] Réponse brute : {response}")
        return

    # 4. Démasquer
    m = unblind(m_prime, r, n)

    # 5. Convertir
    flag = int_to_text(m)
    return flag

# ================================================
# LANCEMENT
# ================================================

if __name__ == "__main__":
    rsa_blinding_attack()
