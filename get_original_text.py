"""
    Get the original text from the cipher text
"""

from fms_attack import *
from rc4 import *

s_box = list(range(256))
n_bits = 8
n = 256

key = getKey()
print("OGT: " + str(key))
key = bin(int(key, base=16))[2:].zfill(64)
print("Binary key: " + str(key))
key_list = [key[i:i + n_bits] for i in range(0, len(key), n_bits)]
key_list = convert_to_decimal(key_list)

diff = int(n-len(key_list))
if diff != 0:
    for i in range(0, diff):
        key_list.append(key_list[i])

print("Key list: " + str(key_list))

hex_text = ''
with open('encrypted-text.txt', 'r', encoding='utf-8') as f:
    hex_text = f.read().strip()

encrypted_text = [byte for byte in bytes.fromhex(hex_text)]
print("DECIMAL LIST: " + str(encrypted_text))

# encrypted_text = encryption(s_box, key_list, n, n_bits, plaintext)

original_text = decryprtion(key_list, n, n_bits, encrypted_text)

with open("original-text.txt", "w", encoding='utf-8') as file:
    file.write(original_text)
