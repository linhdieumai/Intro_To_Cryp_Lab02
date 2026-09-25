import os

M1 = b"Send the final report to the dean before Friday noon."
M2 = b"The exam for the course starts at eight in room D9."
M3 = b"Lunch will be served in the main hall at half past twelve."
MSGS = [M1, M2, M3]

def random(size=16):
    return os.urandom(size)

def strxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(key, msg):
    if len(msg) > len(key):
        raise ValueError(
            f"Message ({len(msg)} bytes) is longer than key ({len(key)} bytes). "
            f"One-time pad requires key >= message."
        )
    c = strxor(key[:len(msg)], msg)
    print(c.hex())
    return c

def decrypt(key, ciphertext):
    if len(ciphertext) > len(key):
        raise ValueError(
            f"Ciphertext ({len(ciphertext)} bytes) is longer than key ({len(key)} bytes). "
            f"One-time pad requires key >= ciphertext."
        )
    return strxor(key[:len(ciphertext)], ciphertext).decode()

def main():
    key = random(1024)

    ciphertexts = []
    
    print("\nCiphertexts in hex:")
    for i, msg in enumerate(MSGS, 1):
        c = encrypt(key, msg)
        ciphertexts.append(c)

    print("\nPlaintexts:")
    for i, c in enumerate(ciphertexts, 1):
        print(f"M{i}: {decrypt(key, c)}")
        
    with open("ciphertexts.txt", "w") as f:
        for c in ciphertexts:
            f.write(c.hex() + "\n")
    print("\nSaved ciphertexts.txt")

main()

key = random(1024)
long_msg = b"A" * 1500

c = encrypt(key, long_msg)
print(len(c))
d = decrypt(key, c)
print(d,"\n",len(d))