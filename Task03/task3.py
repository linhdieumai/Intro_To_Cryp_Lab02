from task3 import G
import nacl.secret
import nacl.utils
import os

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(key, nonce, message):
    ks = G(key, nonce, len(message))
    return xor_bytes(message, ks)

def decrypt(key, nonce, ciphertext):
    return encrypt(key, nonce, ciphertext)

key   = os.urandom(32)
nonce = os.urandom(24)

ori_msg = b"PAY BOB 0100 USD"
ct1 = encrypt(key, nonce, ori_msg)
print(f"\nOriginal plaintext: {ori_msg.decode()}")
print(f"Original ciphertext (without nonce and tag version): {ct1.hex()}")

delta = xor_bytes(b"0100", b"9900")
print(f"\nDelta (XOR original part of message and this wrong version): {delta.hex()}")

forged1 = bytearray(ct1)
for i in range(len(delta)):
    forged1[8 + i] ^= delta[i]
forged1 = bytes(forged1)
print(f"Edited ciphertext (replace encrypted part of original message by ciphertext of delta): {forged1.hex()}")

pt1 = decrypt(key, nonce, forged1)
print(f"Decrypt: {pt1.decode()}")

box = nacl.secret.SecretBox(key)
encrypted = box.encrypt(ori_msg)
enc_bytes = bytes(encrypted)
print(f"\nCiphertext with using SecretBox: {enc_bytes.hex()}")

forged2 = bytearray(enc_bytes)
for i in range(len(delta)):
    forged2[48 + i] ^= delta[i]
forged2 = bytes(forged2)
print(f"Forged SecretBox: {forged2.hex()}")

print("\nCall box.decrypt(forged2):")
try:
    pt2 = box.decrypt(forged2)
    print(f"Decrypt: {pt2}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
    
