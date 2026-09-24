import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK_SIZE = 1024 * 1024  # 1 MiB

def encrypt_book(input_path, output_path, key):
    # 1. Tạo prefix 16 bytes ngẫu nhiên
    prefix = os.urandom(16)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # 2. Ghi 16 bytes prefix vào đầu file book.enc
        f_out.write(prefix)
        
        chunk_idx = 0
        while True:
            # 3. Đọc từng chunk 1 MiB
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            
            # 4. Tạo nonce/IV = prefix (16 bytes) || chunk_idx (8 bytes, Big-Endian)
            chunk_counter = chunk_idx.to_bytes(8, byteorder='big')
            nonce = prefix + chunk_counter
            
            # 5. Khởi tạo bộ mã hóa (Ví dụ dùng AES-256 CTR với nonce 24-byte / ChaCha20)
            # LƯU Ý: Nếu thư viện AES chuẩn chỉ nhận IV 16 bytes, bạn dùng 16 bytes đầu của nonce 
            # hoặc truyền cả 24 bytes cho các thuật toán hỗ trợ như ChaCha20/XAES-CTR.
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce[:16]))
            encryptor = cipher.encryptor()
            
            # 6. Mã hóa chunk và ghi vào book.enc
            encrypted_chunk = encryptor.update(chunk) + encryptor.finalize()
            f_out.write(encrypted_chunk)
            
            chunk_idx += 1


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
            
            # 3. Tái tạo lại Nonce/IV = prefix (16 bytes) || chunk_idx (8 bytes, Big-Endian)
            chunk_counter = chunk_idx.to_bytes(8, byteorder='big')
            nonce = prefix + chunk_counter
            
            # 4. Khởi tạo cipher giải mã với Key và Nonce tương ứng
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce[:16]))
            decryptor = cipher.decryptor()
            
            # 5. Giải mã chunk và ghi ra file book.pdf
            decrypted_chunk = decryptor.update(encrypted_chunk) + decryptor.finalize()
            f_out.write(decrypted_chunk)
            
            chunk_idx += 1

# Sử dụng:
# key = <Khóa 32-byte đã dùng lúc mã hóa>
# decrypt_book('book.enc', 'restored_book.pdf', key)