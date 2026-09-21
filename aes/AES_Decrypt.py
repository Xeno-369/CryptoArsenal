
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import binascii

key = b"cyb3r_club_ipn3t"
iv_hex = "7a86f8a5e543f0dd20204b0c92b46691"
data_b64 = "1LfZTpV0WStTvRtVse1wKHnDe04V78JqCI/4QydaymhQZ3pfXGoqsKu0jAgv1HuA"

iv = binascii.unhexlify(iv_hex)
ciphertext = base64.b64decode(data_b64)

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print(plaintext.decode('utf-8'))

