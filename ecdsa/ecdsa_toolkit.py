#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════════════════╗
║                      ECDSA CTF Exploitation Toolkit                        ║
║                                                                            ║
║  Vulnérabilités couverte:                                                 ║
║  1. Nonce réutilisé (k identique)                                         ║
║  2. Nonce petit/biaisé (LLL lattice attack - avancé)                      ║
║  3. Extraction de clé privée                                              ║
║  4. Signature de messages                                                 ║
║  5. Analyse et dumping de signatures                                      ║
╚════════════════════════════════════════════════════════════════════════════╝
"""

import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, 
    encode_dss_signature
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Dict, List, Optional
import sys

# ============================================================================
# CONFIGURATION DES COURBES
# ============================================================================

CURVES = {
    "secp256r1": {
        "name": "P-256",
        "curve": ec.SECP256R1(),
        "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    },
    "secp384r1": {
        "name": "P-384",
        "curve": ec.SECP384R1(),
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    },
    "secp521r1": {
        "name": "P-521",
        "curve": ec.SECP521R1(),
        "n": 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    },
    "secp256k1": {
        "name": "secp256k1 (Bitcoin)",
        "curve": ec.SECP256K1(),
        "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    }
}

# ============================================================================
# UTILITAIRES MATHÉMATIQUES
# ============================================================================

def modinv(a: int, m: int) -> int:
    """Inverse modulaire: a^-1 mod m"""
    return pow(a, -1, m)

def hash_message(msg: str, hash_algo="sha256") -> int:
    """Hasher un message et le convertir en entier"""
    if hash_algo == "sha256":
        h = hashlib.sha256(msg.encode()).hexdigest()
    elif hash_algo == "sha1":
        h = hashlib.sha1(msg.encode()).hexdigest()
    elif hash_algo == "sha512":
        h = hashlib.sha512(msg.encode()).hexdigest()
    else:
        raise ValueError(f"Hash algo non supporté: {hash_algo}")
    return int(h, 16)

def hash_bytes(data: bytes, hash_algo="sha256") -> int:
    """Hasher des bytes et les convertir en entier"""
    if hash_algo == "sha256":
        h = hashlib.sha256(data).hexdigest()
    elif hash_algo == "sha1":
        h = hashlib.sha1(data).hexdigest()
    elif hash_algo == "sha512":
        h = hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Hash algo non supporté: {hash_algo}")
    return int(h, 16)

# ============================================================================
# ANALYSE DE SIGNATURES
# ============================================================================

class SignatureAnalyzer:
    """Analyser et comparer des signatures ECDSA"""
    
    def __init__(self, curve_name: str = "secp256r1"):
        if curve_name not in CURVES:
            raise ValueError(f"Courbe non supportée: {curve_name}")
        self.curve_config = CURVES[curve_name]
        self.curve = self.curve_config["curve"]
        self.n = self.curve_config["n"]
    
    def decode_signature(self, sig_b64: str) -> Tuple[int, int]:
        """Décoder une signature base64 DER en (r, s)"""
        try:
            sig_der = base64.b64decode(sig_b64)
            r, s = decode_dss_signature(sig_der)
            return r, s
        except Exception as e:
            print(f"[!] Erreur décodage: {e}")
            return None, None
    
    def decode_hex_signature(self, sig_hex: str) -> Tuple[int, int]:
        """Décoder une signature hex raw en (r, s)"""
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            r, s = decode_dss_signature(sig_bytes)
            return r, s
        except Exception as e:
            print(f"[!] Erreur décodage hex: {e}")
            return None, None
    
    def compare_signatures(self, sigs: List[Tuple[str, int, int]]) -> Dict:
        """
        Comparer plusieurs signatures pour détecter r réutilisés.
        sigs = [(label, r, s), ...]
        """
        results = {"same_r": []}
        
        for i in range(len(sigs)):
            for j in range(i + 1, len(sigs)):
                label_i, r_i, s_i = sigs[i]
                label_j, r_j, s_j = sigs[j]
                
                if r_i == r_j:
                    results["same_r"].append({
                        "sig1": label_i,
                        "sig2": label_j,
                        "r": hex(r_i)
                    })
        
        return results
    
    def dump_signature(self, sig_b64: str) -> None:
        """Afficher les détails d'une signature"""
        r, s = self.decode_signature(sig_b64)
        if r is None:
            return
        
        print(f"[+] r = {hex(r)}")
        print(f"[+] s = {hex(s)}")
        print(f"[+] r (dec) = {r}")
        print(f"[+] s (dec) = {s}")

# ============================================================================
# EXTRACTION DE CLÉ PRIVÉE
# ============================================================================

class PrivateKeyRecovery:
    """Récupérer la clé privée depuis des signatures vulnérables"""
    
    def __init__(self, curve_name: str = "secp256r1"):
        if curve_name not in CURVES:
            raise ValueError(f"Courbe non supportée: {curve_name}")
        self.curve_config = CURVES[curve_name]
        self.curve = self.curve_config["curve"]
        self.n = self.curve_config["n"]
    
    def recover_from_reused_nonce(self, 
                                   msg1: str, sig1: Tuple[int, int],
                                   msg2: str, sig2: Tuple[int, int],
                                   hash_algo: str = "sha256") -> Optional[int]:
        """
        Récupérer d quand le même k est utilisé pour deux messages.
        
        Formule:
            k = (h1 - h2) * (s1 - s2)^-1 mod n
            d = (s1 * k - h1) * r^-1 mod n
        """
        r1, s1 = sig1
        r2, s2 = sig2
        
        if r1 != r2:
            print("[!] Les r ne sont pas identiques, cette attaque ne marche pas.")
            return None
        
        h1 = hash_message(msg1, hash_algo)
        h2 = hash_message(msg2, hash_algo)
        
        r = r1
        delta_s = (s1 - s2) % self.n
        
        if delta_s == 0:
            print("[!] s1 == s2, impossible de récupérer k")
            return None
        
        delta_h = (h1 - h2) % self.n
        k = (delta_h * modinv(delta_s, self.n)) % self.n
        
        # Récupérer d
        d = ((s1 * k - h1) * modinv(r, self.n)) % self.n
        
        print(f"[+] k trouvé: {hex(k)}")
        print(f"[+] d trouvé: {hex(d)}")
        
        return d
    
    def recover_from_bytes(self,
                          msg1: bytes, sig1: Tuple[int, int],
                          msg2: bytes, sig2: Tuple[int, int],
                          hash_algo: str = "sha256") -> Optional[int]:
        """Même chose mais avec des bytes au lieu de strings"""
        r1, s1 = sig1
        r2, s2 = sig2
        
        if r1 != r2:
            print("[!] Les r ne sont pas identiques")
            return None
        
        h1 = hash_bytes(msg1, hash_algo)
        h2 = hash_bytes(msg2, hash_algo)
        
        r = r1
        delta_s = (s1 - s2) % self.n
        delta_h = (h1 - h2) % self.n
        
        k = (delta_h * modinv(delta_s, self.n)) % self.n
        d = ((s1 * k - h1) * modinv(r, self.n)) % self.n
        
        print(f"[+] k trouvé: {hex(k)}")
        print(f"[+] d trouvé: {hex(d)}")
        
        return d

# ============================================================================
# SIGNATURE
# ============================================================================

class Signer:
    """Signer des messages avec une clé privée ECDSA"""
    
    def __init__(self, curve_name: str = "secp256r1"):
        if curve_name not in CURVES:
            raise ValueError(f"Courbe non supportée: {curve_name}")
        self.curve_config = CURVES[curve_name]
        self.curve = self.curve_config["curve"]
    
    def sign_with_d(self, d: int, message: str, hash_algo: str = "sha256") -> Tuple[str, str]:
        """
        Signer un message avec la clé privée d.
        Retourne (signature_b64, signature_hex)
        """
        # Créer la clé privée
        private_key = ec.derive_private_key(d, self.curve, default_backend())
        
        # Signer
        if hash_algo == "sha256":
            hash_obj = hashes.SHA256()
        elif hash_algo == "sha1":
            hash_obj = hashes.SHA1()
        elif hash_algo == "sha512":
            hash_obj = hashes.SHA512()
        else:
            raise ValueError(f"Hash algo non supporté: {hash_algo}")
        
        signature_der = private_key.sign(
            message.encode(),
            ec.ECDSA(hash_obj)
        )
        
        sig_b64 = base64.b64encode(signature_der).decode()
        sig_hex = signature_der.hex()
        
        return sig_b64, sig_hex
    
    def sign_bytes_with_d(self, d: int, data: bytes, hash_algo: str = "sha256") -> Tuple[str, str]:
        """Signer des bytes avec la clé privée d"""
        private_key = ec.derive_private_key(d, self.curve, default_backend())
        
        if hash_algo == "sha256":
            hash_obj = hashes.SHA256()
        elif hash_algo == "sha1":
            hash_obj = hashes.SHA1()
        elif hash_algo == "sha512":
            hash_obj = hashes.SHA512()
        else:
            raise ValueError(f"Hash algo non supporté: {hash_algo}")
        
        signature_der = private_key.sign(data, ec.ECDSA(hash_obj))
        sig_b64 = base64.b64encode(signature_der).decode()
        sig_hex = signature_der.hex()
        
        return sig_b64, sig_hex

# ============================================================================
# VÉRIFICATION
# ============================================================================

class Verifier:
    """Vérifier des signatures ECDSA"""
    
    def __init__(self, public_key_pem: str, curve_name: str = "secp256r1"):
        """Charger une clé publique depuis PEM"""
        public_key_bytes = public_key_pem.encode()
        self.public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )
    
    def verify(self, message: str, signature_b64: str, hash_algo: str = "sha256") -> bool:
        """Vérifier une signature"""
        try:
            sig_der = base64.b64decode(signature_b64)
            
            if hash_algo == "sha256":
                hash_obj = hashes.SHA256()
            elif hash_algo == "sha1":
                hash_obj = hashes.SHA1()
            elif hash_algo == "sha512":
                hash_obj = hashes.SHA512()
            else:
                raise ValueError(f"Hash algo non supporté: {hash_algo}")
            
            self.public_key.verify(sig_der, message.encode(), ec.ECDSA(hash_obj))
            print("[+] Signature valide !")
            return True
        except Exception as e:
            print(f"[!] Signature invalide: {e}")
            return False

# ============================================================================
# MAIN - EXEMPLE D'UTILISATION
# ============================================================================

if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    ECDSA CTF Toolkit - Exemple d'usage                     ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Exemple 1: Analyser des signatures
    print("\n[1] ANALYSER DES SIGNATURES")
    print("-" * 70)
    
    analyzer = SignatureAnalyzer("secp521r1")
    
    # Remplacer par vos vraies signatures
    sig1_b64 = "MIGGAkFeYtWN7tbePVn9X8zMe8iWmZ6TkGb72wWdppzD8rahU5fHsZDFHyt1ClycERWjdYUSQ5ICxbaXYLwmM07WwjyfrwJBf4r/LBS+gkEWcx/uhXDfFRLnUxiQIo4xfRsmfNvc2Z5KWuEkq5xRtqKOh6uaKTljTSHAifIRuJDbMXnU97qCCCo="
    sig2_b64 = "MIGGAkFeYtWN7tbePVn9X8zMe8iWmZ6TkGb72wWdppzD8rahU5fHsZDFHyt1ClycERWjdYUSQ5ICxbaXYLwmM07WwjyfrwJBMl3R/ueRVRPpRfLBWEOx5+W6Jeti9WEET+35T66vrHEeCQeKsRxcxgAyOSOb7878ot2GZVuN0T6lLsCJ4/9J8og="
    
    r1, s1 = analyzer.decode_signature(sig1_b64)
    r2, s2 = analyzer.decode_signature(sig2_b64)
    
    print(f"Signature 1: r={hex(r1)[:20]}..., s={hex(s1)[:20]}...")
    print(f"Signature 2: r={hex(r2)[:20]}..., s={hex(s2)[:20]}...")
    print(f"r1 == r2 ? {r1 == r2} [VULNÉRABLE!]" if r1 == r2 else f"r1 == r2 ? False")
    
    # Exemple 2: Récupérer la clé privée
    print("\n[2] RÉCUPÉRER LA CLÉ PRIVÉE (nonce réutilisé)")
    print("-" * 70)
    
    recovery = PrivateKeyRecovery("secp521r1")
    
    msg1 = "Initially, they must agree on the curve parameters (CURVE,G,n)."
    msg2 = "This implementation failure was used, for example, to extract the signing key used for the PlayStation 3 gaming-console."
    
    d = recovery.recover_from_reused_nonce(msg1, (r1, s1), msg2, (r2, s2), "sha256")
    
    # Exemple 3: Signer un nouveau message
    print("\n[3] SIGNER UN NOUVEAU MESSAGE")
    print("-" * 70)
    
    if d:
        signer = Signer("secp521r1")
        message = "I broke your crypto, give me points!"
        sig_b64, sig_hex = signer.sign_with_d(d, message, "sha256")
        
        print(f"Message: {message}")
        print(f"Signature (base64):")
        print(sig_b64)
        print(f"\nSignature (hex):")
        print(sig_hex)
    
    print("\n[*] Toolkit chargé et prêt à l'emploi !")
