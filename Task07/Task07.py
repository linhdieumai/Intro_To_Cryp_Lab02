N = 32
TAPS = {0, 10, 30, 31}
CIPHERTEXT_HEX = """3d5cae33120fe78d2359b8998d46d5230dc78741f3880d0e36e3fb4659976
4a5841c015c4e29f25bbdcb0f946993cd2af3984176325a968ab8ab6d07fda
f2f680eee88923ccc3178ce4c3c9962a5b92873b3064e64a69054def9c71331"""


def lfsr_step(register: int, taps: set[int], n: int):
    """Thực hiện một bước của LFSR.
    Bit đầu ra là bit phải cùng của thanh ghi trước khi dịch.
    """
    output_bit = register & 1
    feedback = 0
    for pos in taps:
        feedback ^= (register >> pos) & 1
    new_register = (register >> 1) | (feedback << (n - 1))
    return new_register, output_bit


def build_output_matrix(n: int, taps: set[int]):
    """Xây dựng ma trận hệ phương trình trên GF(2) cho output của LFSR."""
    matrix = []
    for bit_index in range(n):
        reg = 1 << bit_index
        outputs = []
        for _ in range(n):
            outputs.append(reg & 1)
            reg, _ = lfsr_step(reg, taps, n)
        matrix.append(outputs)
    return matrix


def solve_gf2(matrix, rhs):
    """Giải hệ A x = b trên trường GF(2) bằng khử Gauss."""
    rows = []
    for row_idx in range(len(matrix)):
        mask = 0
        for col_idx, value in enumerate(matrix[row_idx]):
            if value:
                mask |= 1 << col_idx
        rows.append((mask, rhs[row_idx]))

    row = 0
    col = 0
    while row < len(rows) and col < len(matrix[0]):
        pivot = None
        for r in range(row, len(rows)):
            if (rows[r][0] >> col) & 1:
                pivot = r
                break
        if pivot is None:
            col += 1
            continue
        if pivot != row:
            rows[row], rows[pivot] = rows[pivot], rows[row]
        for r in range(len(rows)):
            if r != row and ((rows[r][0] >> col) & 1):
                rows[r] = (rows[r][0] ^ rows[row][0], rows[r][1] ^ rows[row][1])
        row += 1
        col += 1

    solution = [0] * len(matrix[0])
    for r in range(len(rows)):
        pivot_col = None
        for c in range(len(matrix[0])):
            if (rows[r][0] >> c) & 1:
                pivot_col = c
                break
        if pivot_col is not None:
            solution[pivot_col] = rows[r][1]
    return sum(bit << i for i, bit in enumerate(solution))


def recover_seed_from_known_prefix(ciphertext: bytes, known_prefix: bytes, taps: set[int], n: int) -> int:
    """Khôi phục seed từ prefix plaintext đã biết bằng cách giải hệ tuyến tính GF(2)."""
    if len(known_prefix) > len(ciphertext):
        raise ValueError("Prefix dài hơn ciphertext.")

    # Lấy bit keystream từ mảng ciphertext XOR plaintext cho n bit đầu tiên
    known_bits = []
    for idx, ch in enumerate(known_prefix):
        x = ciphertext[idx] ^ ch
        for bit_index in range(8):
            known_bits.append((x >> bit_index) & 1)

    if len(known_bits) < n:
        raise ValueError(f"Cần ít nhất {n} bit keystream để xác định seed.")

    matrix = build_output_matrix(n, taps)
    rhs = known_bits[:n]
    return solve_gf2(matrix, rhs)


def decrypt_with_lfsr(ciphertext: bytes, seed: int, taps: set[int], n: int) -> bytes:
    """Giải mã ciphertext bằng keystream sinh ra từ seed của LFSR."""
    reg = seed
    keystream = []
    for _ in range(len(ciphertext) * 8):
        reg, bit = lfsr_step(reg, taps, n)
        keystream.append(bit)

    plain = bytearray()
    for i in range(len(ciphertext)):
        value = 0
        for j in range(8):
            value |= keystream[i * 8 + j] << j
        plain.append(ciphertext[i] ^ value)
    return bytes(plain)


if __name__ == "__main__":
    ciphertext = bytes.fromhex(CIPHERTEXT_HEX.replace("\n", ""))
    known_prefix = b"From: ex"

    seed = recover_seed_from_known_prefix(ciphertext, known_prefix, TAPS, N)
    plaintext = decrypt_with_lfsr(ciphertext, seed, TAPS, N)

    print(f"seed = 0x{seed:08x}")
    print("plaintext =")
    print(plaintext.decode("utf-8", errors="replace"))
