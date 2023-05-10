"""
    FMS attack implementation
"""

# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name

import csv

WEP_OUTPUT = "wep-output.csv"
rows = []
s_box = []
# In WEP, the header of SNAP is always 'aa'.
SNAP = "aa"

with open(WEP_OUTPUT, 'r', encoding='utf-8') as csv_file:
    csv_file = csv.reader(csv_file)
    for row in csv_file:
        rows.append(row)

keyLength = int(rows[-1][0]) - 2
print("keyLength is: " + str(keyLength))

key = [None] * 3
for A in range(keyLength):
    prob = [0] * 256
    for row in rows:
        key[0] = int(row[0])
        key[1] = int(row[1])
        key[2] = int(row[2])

        j = 0
        s_box = list(range(256))

        # Simulate the S-Box after KSA initialization.
        for i in range(A + 3):
            j = (j + s_box[i] + key[i]) % 256
            s_box[i], s_box[j] = s_box[j], s_box[i]
            # Record the original box[0] and box[1] value.
            if i == 1:
                original0 = s_box[0]
                original1 = s_box[1]

        i = A + 3
        z = s_box[1]
        # if resolved condition is possibly met.
        if z + s_box[z] == A + 3:
            # If the value of box[0] and box[1] has changed, discard this possibility.
            if (original0 != s_box[0] or original1 != s_box[1]):
                continue
            keyStreamByte = int(row[3]) ^ int(SNAP, 16)
            keyByte = (keyStreamByte - j - s_box[i]) % 256
            prob[keyByte] += 1
        # Assume that the most hit is the correct password.
        higherPossibility = prob.index(max(prob))
    key.append(higherPossibility)

# Get rid of first 24-bit initialization vector.
userInput = key[3:]
result = [format(key, 'x') for key in userInput]
KEY = ''.join(result).upper()
print(KEY)

def getKey():
    return KEY
