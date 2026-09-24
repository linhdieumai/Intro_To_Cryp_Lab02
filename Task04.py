import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time
import hashlib

CHUNK_SIZE = 1024 * 1024  # 1 MiB

def encrypt_book(input_path, output_path, key):
    # 1. Tạo prefix 16 bytes ngẫu nhiên
    prefix = os.urandom(16)
    first_16_plain = b""
    first_16_cipher = b""

    start_time = time.time()
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # 2. Ghi 16 bytes prefix vào đầu file book.enc
        f_out.write(prefix)
        
        chunk_idx = 0
        while True:
            # 3. Đọc từng chunk 1 MiB
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break

            if(chunk_idx==0):
                first_16_plain = chunk[:16]
              
            
            # 4. Tạo nonce/IV = prefix (16 bytes) || chunk_idx (8 bytes, Little-Endian)
            chunk_counter = chunk_idx.to_bytes(8, byteorder='little')
            nonce = prefix + chunk_counter

            keystream = generate_keystream(key,nonce,len(chunk))
            encrypted_chunk = fast_xor(chunk, keystream)

            if(chunk_idx==0):
                first_16_cipher = encrypted_chunk[:16]

            f_out.write(encrypted_chunk)
            chunk_idx += 1

    enc_time = time.time() - start_time
    return prefix, first_16_plain, first_16_cipher, enc_time


def decrypt_book(input_path, output_path, key):
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # 1. Đọc 16 bytes prefix đầu tiên từ file mã hóa
        prefix = f_in.read(16)
        
        if len(prefix) < 16:
            raise ValueError("File quá ngắn hoặc bị lỗi cấu trúc!")

        chunk_idx = 0
        while True:
            
            # 2. Đọc từng chunk 1 MiB dữ liệu đã mã hóa
            encrypted_chunk = f_in.read(CHUNK_SIZE)
            if not encrypted_chunk:
                break

            # 3. Tái tạo lại Nonce/IV = prefix (16 bytes) || chunk_idx (8 bytes, Little-Endian)
            chunk_counter = chunk_idx.to_bytes(8, byteorder='little')
            nonce = prefix + chunk_counter
            
            keystream = generate_keystream(key,nonce,len(encrypted_chunk))
            decrypted_chunk = fast_xor(encrypted_chunk, keystream)
            
            f_out.write(decrypted_chunk)
            chunk_idx += 1
            

def get_file_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()

def fast_xor(data_bytes: bytes, key_bytes: bytes) -> bytes:
    """Hàm XOR tối ưu tốc độ bằng cách chuyển sang int theo gợi ý đề bài"""
    # Ép kiểu dữ liệu sang int và thực hiện phép XOR
    int_data = int.from_bytes(data_bytes, "little")
    int_key = int.from_bytes(key_bytes, "little")
    int_res = int_data ^ int_key
    # Chuyển ngược về dạng bytes đúng độ dài ban đầu
    return int_res.to_bytes(len(data_bytes), "little")

def generate_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Tạo chuỗi keystream từ key và nonce sử dụng SHA-256 để mở rộng thành chuỗi byte có độ dài 'length'"""
    keystream = bytearray()
    counter = 0
    while len(keystream) < length:
        # Keystream block = SHA256(key || nonce || counter)
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, 'little')).digest()
        keystream.extend(block)
        counter += 1
    return bytes(keystream[:length])

# Phiên bản mã hóa bị lỗi (Cố định counter = 0)
def encrypt_buggy(input_path, enc_path, key):
    prefix = os.urandom(16)
    c0 = c1 = m0 = m1 = None

    with open(input_path, 'rb') as f_in, open(enc_path, 'wb') as f_out:
        f_out.write(prefix)

        # Fixed nonce cho TẤT CẢ các chunk
        fixed_nonce = prefix + (0).to_bytes(8, 'little')

        chunk_i = 0
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break

            keystream = generate_keystream(key, fixed_nonce, len(chunk))
            enc_chunk = fast_xor(chunk, keystream)
            f_out.write(enc_chunk)

            if chunk_i == 0:
                m0, c0 = chunk, enc_chunk
            elif chunk_i == 1:
                m1, c1 = chunk, enc_chunk

            chunk_i += 1

    if c0 is None or c1 is None or m0 is None or m1 is None:
        raise ValueError("Input file must be large enough to contain at least two chunks.")

    return c0, c1, m0, m1


if __name__ == "__main__":
    key = os.urandom(32)  # Khóa 32-byte ngẫu nhiên cho AES-256
    file_in = "book.pdf"
    file_enc = "book.enc"
    file_out = "book.dec.pdf"
    #encrypt
    prefix, first_16_plain, first_16_cipher, enc_time = encrypt_book(file_in,file_enc,key)
    #decrypt
    decrypt_book(file_enc,file_out,key)

    size_plain = os.path.getsize(file_in)
    size_enc = os.path.getsize(file_enc)

    sha256_plain = get_file_sha256(file_in)
    sha256_out = get_file_sha256(file_out)

    # Kiểm tra đẳng thức c0 ⊕ c1 == m0 ⊕ m1
    buggy_file = "book_buggy.enc"
    c0, c1, m0, m1 = encrypt_buggy(file_in, buggy_file, key)
    xor_c = fast_xor(c0, c1)
    xor_m = fast_xor(m0, m1)

    print(f"Key (hex): {key.hex()}")
    print(f"Size of book.pdf : {size_plain} bytes")
    print(f"Size of book.enc : {size_enc} bytes")
    print(f"First 16 bytes of Plaintext : {first_16_plain.hex()}")
    print(f"First 16 bytes of Cipher : {first_16_cipher.hex()}")
    print(f"SHA-256 of book.pdf : {sha256_plain}")
    print(f"SHA-256 of book.dec.pdf : {sha256_out}")
    print(f"Encryption time: {enc_time:.4f} seconds")
    print(f"c0 ⊕ c1 == m0 ⊕ m1 ? -> {xor_c == xor_m}") 


