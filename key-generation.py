# Generate random key


import random

key = "".join(str(random.randint(0, 1)) for i in range(16))

print(key)