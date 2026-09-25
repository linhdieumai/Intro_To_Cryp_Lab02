import random


def lfsr_step(register: int, taps: set[int], n: int):
    # Kiểm tra đầu vào cơ bản
    if n <= 0:
        raise ValueError("Bề rộng thanh ghi n phải lớn hơn 0.")
    if register < 0 or register >= (1 << n):
        raise ValueError("Giá trị thanh ghi nằm ngoài phạm vi n-bit cho phép.")

    # Bit đầu ra là bit phải cùng của thanh ghi
    output_bit = register & 1

    # Tính feedback bằng XOR của các bit ở các vị trí tap
    feedback = 0
    for pos in taps:
        if pos < 0 or pos >= n:
            raise ValueError(f"Vị trí tap {pos} nằm ngoài phạm vi cho n={n}.")
        feedback ^= (register >> pos) & 1

    # Dịch phải 1 bit, rồi chèn feedback vào bit trái nhất
    new_register = (register >> 1) | (feedback << (n - 1))
    return new_register, output_bit


def run_lfsr(seed: int, taps: set[int], n: int, steps: int):
    """Trả về các bit đầu ra đầu tiên của LFSR trong số `steps` bước."""
    # Seed không được bằng 0 vì khi thanh ghi bằng 0 thì nó sẽ ở mãi 0
    if seed == 0:
        raise ValueError("Seed không được bằng 0.")
    if seed >= (1 << n):
        raise ValueError("Seed không vừa với n bit.")

    reg = seed
    bits = []
    for _ in range(steps):
        reg, bit = lfsr_step(reg, taps, n)
        bits.append(bit)
    return bits


def cycle_length(seed: int, taps: set[int], n: int):
    """Trả về số bước cần thiết để thanh ghi quay lại trạng thái ban đầu."""
    if seed == 0:
        raise ValueError("Seed không được bằng 0.")

    reg = seed
    steps = 0
    while True:
        reg, _ = lfsr_step(reg, taps, n)
        steps += 1
        if reg == seed:
            return steps


def pack_bits_to_bytes(bits):
    """Gói các bit đầu ra thành byte, bit 0 được xét trước."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        out.append(byte)
    return bytes(out)


def encrypt_with_lfsr(message: bytes, seed: int, taps: set[int], n: int):
    """Mã hóa message bằng cách XOR với bit đầu ra của LFSR."""
    reg = seed
    keystream_bits = []
    total_bits_needed = len(message) * 8

    # Tạo keystream đủ cho toàn bộ message
    for _ in range(total_bits_needed):
        reg, bit = lfsr_step(reg, taps, n)
        keystream_bits.append(bit)

    cipher = bytearray()
    for i, byte in enumerate(message):
        value = 0
        for j in range(8):
            bit = keystream_bits[i * 8 + j]
            value |= bit << j
        cipher.append(byte ^ value)
    return bytes(cipher)


def bit_fraction(data: bytes):
    total_bits = len(data) * 8
    ones = sum(bin(b).count("1") for b in data)
    return ones / total_bits


if __name__ == "__main__":
    # 1. In ra 16 bit đầu tiên với n=4, taps {0,1}, seed 1001
    n1 = 4
    taps1 = {0, 1}
    seed1 = 0b1001
    bits1 = run_lfsr(seed1, taps1, n1, 16)
    print(f"1) 16 bit đầu ra đầu tiên: {''.join(str(b) for b in bits1)}")

    # 2. Kiểm tra độ dài chu kỳ của thanh ghi
    print("2) độ dài chu kỳ:")
    for n, taps, seed in [
        (4, {0, 1}, 0b1001),
        (16, {0, 2, 3, 5}, 1),
        (16, {0, 8}, 1),
    ]:
        print(f"   n={n}, taps={sorted(taps)}, seed={seed}: độ_dài_chu_kỳ = {cycle_length(seed, taps, n)}")

    # 3. Mã hóa thông điệp bằng LFSR, sau đó in seed, ciphertext và tỷ lệ bit 1
    n2 = 32
    taps2 = {0, 10, 30, 31}
    seed2 = random.getrandbits(32)
    while seed2 == 0:
        seed2 = random.getrandbits(32)

    message = (
        "From: exam-office@example.edu\n"
        "Subject: final exam\n"
        "Room B1-401, 8:00 on Monday."
    ).encode("utf-8")

    ciphertext = encrypt_with_lfsr(message, seed2, taps2, n2)
    print(f"3) seed = 0x{seed2:08x}")
    print(f"   ciphertext = {ciphertext.hex()}")

    # 64 KiB đầu ra, tính tỷ lệ bit 1
    out64 = run_lfsr(seed2, taps2, n2, 64 * 1024 * 8)
    out64_bytes = pack_bits_to_bytes(out64)
    density = bit_fraction(out64_bytes)
    print(f"   tỷ lệ bit 1 trong 64 KiB đầu ra = {density:.6f}")