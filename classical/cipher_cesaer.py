def cipher_cesaer(words, keys): 
    cipher_word = ""
    # En Python, on peut itérer directement sur les lettres !
    for char in words:
        if char.islower():
            # (Lettre - 'a' + clé) le tout modulo 26, puis on revient à 'a'
            nouveau_code = (ord(char) - ord('a') + keys) % 26 + ord('a')
            cipher_word += chr(nouveau_code)
        elif char.isupper(): 
            nouveau_code = (ord(char) - ord('A') + keys) % 26 + ord('A')
            cipher_word += chr(nouveau_code)
        else:
            # Si c'est un espace, un chiffre ou \n, on l'ajoute tel quel
            cipher_word += char
    return cipher_word
print("======= cipher cesaer ========")
word = input("Entrez le mot a chiffré : ")
while True :
    try :
        key = int(input(("Entrez la clé de chiffrement : ")))
        if key < 0 or key > 26 :
            print("la clé doit entre comprise entre 0 et 26\n")
        else :
            break
    except ValueError :
        print("Entrez une clé de chiffrement valide\n")
print(f'Le chiffrement César de "{word}" est : "{cipher_cesaer(word, key)}"')
input("Appuyez sur Entrée pour quitter...")