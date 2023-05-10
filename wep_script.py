"""
    Create wep encrypted packages
"""

import sys
from rc4 import *

# the key should be in hex, this are the possible values for the input key
possibleByte = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 'A', 'B', 'C', 'D', 'E', 'F', \
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

# check if the user passes 2 arguments (the name of the script and the key)
if len(sys.argv) != 2:
    print("user input key (in hex) should be second argument")
    sys.exit()

RAWKEY = sys.argv[1]
# check if there are even charaters in the key
# because in hex 2 digits represent one number
if len(RAWKEY) % 2 != 0:
    print("key is not right, its length should be a multiple of 2")
    sys.exit()

# check if every character is valid
for i in RAWKEY:
    if i not in possibleByte:
        print(RAWKEY)
        print(i)
        print(type(i))
        print("key should only contains 0-9 and A-F.")
        sys.exit()

key = []
i = 0
while i < len(RAWKEY):
    key.append(int(RAWKEY[i] + RAWKEY[i+1], 16))
    i += 2

# Initial IV form.
iv = [3, 255, 0]
sessionKey = iv + key
PLAIN_SNAP = "aa"

# Clear out what is originally in the file.
WEP_OUTPUT_FILE = open("wep-output.csv", "w").close()
# Append possible IV and keyStreamByte.
WEP_OUTPUT_FILE = open("wep-output.csv", "a")

# A is the number of known key bytes, it starts from 0 to the length of key.
for A in range(len(key)):
    iv[0] = A + 3
    for thirdByte in range(256):
        iv[2] = thirdByte
        sessionKey = iv + key
        print("Session Key: " + str(sessionKey))
        box = list(range(256))
        ksa(box, sessionKey, 256)
        i = 0
        j = 0
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        keyStreamByte = box[(box[i] + box[j]) % 256]
        cipherByte = (int(PLAIN_SNAP, 16)) ^ keyStreamByte
        WEP_OUTPUT_FILE.write(str(iv[0]) + "," + str(iv[1]) + "," + str(iv[2]) + "," + str(cipherByte) + "\n")

print("WEPOutputSim.csv is generated sucessfully.")
