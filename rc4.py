"""
Implementation of rc4 algorithm

"""
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name


def convert_to_decimal(binary_stream):
    decimal_stream = []
    for binary_string in binary_stream:
        decimal_stream.append(int(binary_string, 2))
    return decimal_stream


def initialize():
    pt = ''
    key = ''
    # key = "".join(str(random.randint(0, 1)) for i in range(16))
    # key = "101001000001"
    # pt = "001010010010"
    n_bits = 8  # N bits considered at time
    s_box = list(range(2**n_bits))
    n = len(s_box)

    with open('key-hex.txt', 'r', encoding='utf-8') as f:
        key = f.read().strip()

    with open('plaintext.txt', 'r', encoding='utf-8') as f:
        pt = f.read()

    # Convert the plain text message to binary stream
    pt = "".join(format(ord(char), '08b') for char in pt)
    
    # Convert key to binary
    key = bin(int(key, base=16))[2:].zfill(64)

    # Convert Key to KeyList, each element has 4 bits
    key_list = [key[i:i + n_bits] for i in range(0, len(key), n_bits)]
    plaintext = [pt[i:i + n_bits] for i in range(0, len(pt), n_bits)]

    # Convert key_list and plaintext to decimal
    key_list = convert_to_decimal(key_list)
    plaintext = convert_to_decimal(plaintext)
   
    # Make the key as long as the s-box
    diff = int(len(s_box)-len(key_list))
    if diff != 0:
        for i in range(0, diff):
            key_list.append(key_list[i])

    print("SBOX: " + str(s_box))
    print("n bits at time: " + str(n_bits))
    print("key list: " + str(key_list))
    print("plaintext: " + str(plaintext))
    print("S-box length: " + str(n))
    return s_box, n, key_list, plaintext, n_bits

# Key Scheduling Algorithm
def ksa(s_box, key_list, n):

    j = 0

    for i in range(0, n):
        j = (j + s_box[i] + key_list[i % len(key_list)]) % n
        s_box[i], s_box[j] = s_box[j], s_box[i]

    print("Initial permutation array (after ksa) : " + str(s_box))  # Initial permutation of the s-box


def prga(key_stream, s_box, plaintext, n):

    i = j = 0
    # Iterate over [0, length of plaintext]
    for k in range(0, len(plaintext)):
        i = (i + 1) % n
        j = (j + s_box[i]) % n

        # Update S[i] and S[j]
        s_box[i], s_box[j] = s_box[j], s_box[i]
        print(k, " ", end="")
        print(s_box)
        t = (s_box[i]+s_box[j]) % n
        key_stream.append(s_box[t])

    print("KEY STREAM: " + str(key_stream))
    return key_stream


def xor(text_arg, key_stream):
    print("TEXT_ARG: " + str(text_arg))
    print("KEY_STREAM: " + str((key_stream))) 
    text = []
    for i, k in enumerate(text_arg):
        c = key_stream[i] ^ k
        text.append(c)
    return text


def result(n_bits, cipher_text):
    encrypted_to_bits = ""
    for i, k in enumerate(cipher_text):
        encrypted_to_bits += '0' * \
            (n_bits-len(bin(k)[2:]))+bin(k)[2:]
    return encrypted_to_bits


def encryption(s_box, key_list, n, n_bits, plaintext):
    key_stream = []
    ksa(s_box, key_list, n)
    key_stream = prga(key_stream, s_box, plaintext, n)
    cipher_text = xor(plaintext, key_stream)
    # print(cipher_text)
    res = result(n_bits, cipher_text)
    print("Encrypted: " + str(res))
    bytes_list = [res[i:i+8] for i in range(0, len(res), 8)]
    res = convert_to_decimal(bytes_list)
    print("ENCRYPTED DECIMAL LIST: " + str(res))

    # print("ENCRYPTED BYTE LIST: " + str(bytes_list))
    return res


def decryprtion(key_list, n, n_bits, cipher_text):
    print("CIPHERRRRRRRRRRRRRRRRRRRR TEXXXXXXXXXXXXXXXXXXXXXXXXXXXT : " + str(cipher_text))
    key_stream = []
    s_box = list(range(2**n_bits))
    ksa(s_box, key_list, n)
    key_stream = prga(key_stream, s_box, cipher_text, n)
    original_text = xor(cipher_text, key_stream)
    res = result(n_bits, original_text)
    print("Decrypted: " + res)

    bytes_list = [res[i:i+8] for i in range(0, len(res), 8)]
    ascii_string = ''.join([chr(int(byte, 2)) for byte in bytes_list])

    print("Original sentence: " + str(ascii_string))

    return ascii_string


if __name__ == '__main__':
    global N, KEY_LIST, N_BITS
    global CIPHER_TEXT
    S_BOX, N, KEY_LIST, plaintext, N_BITS = initialize()
    cipher_decimal_list = encryption(S_BOX, KEY_LIST, N, N_BITS, plaintext)
    CIPHER_TEXT = ""
    for decimal in cipher_decimal_list:
        CIPHER_TEXT += hex(decimal)[2:].zfill(2)

    with open("encrypted-text.txt", "w", encoding='utf-8') as file:
        file.write(CIPHER_TEXT)

    decryprtion(KEY_LIST, N, N_BITS, cipher_decimal_list)
