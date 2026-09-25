from pathlib import Path
import sys


CRIB = b" the "
TARGET = b"Nothing to see here."


def read_ciphertexts(path: Path) -> tuple[bytes, bytes]:
	"""Read two hexadecimal ciphertexts from the first two non-empty lines."""
	lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
	lines = [line for line in lines if line and not line.startswith("#")]
	if len(lines) < 2:
		raise ValueError("ciphertexts.txt must contain two hexadecimal ciphertexts.")

	try:
		ciphertexts = tuple(bytes.fromhex(line) for line in lines[:2])
	except ValueError as exc:
		raise ValueError("Ciphertexts must contain hexadecimal bytes.") from exc

	c1, c2 = ciphertexts
	if not c1 or not c2:
		raise ValueError("Ciphertexts must not be empty.")
	if len(c1) != len(c2):
		raise ValueError("c1 and c2 must have the same length for this task.")
	return c1, c2


def xor_bytes(left: bytes, right: bytes) -> bytes:
	if len(left) != len(right):
		raise ValueError("XOR operands must have the same length.")
	return bytes(a ^ b for a, b in zip(left, right))


def crib_drag(xor_ciphertexts: bytes, crib: bytes = CRIB) -> list[tuple[int, bytes]]:
	"""Return positions where crib XOR produces only lowercase letters/spaces."""
	results = []
	allowed = set(b"abcdefghijklmnopqrstuvwxyz ")
	for position in range(len(xor_ciphertexts) - len(crib) + 1):
		candidate = xor_bytes(
			xor_ciphertexts[position : position + len(crib)], crib
		)
		if all(byte in allowed for byte in candidate):
			results.append((position, candidate))
	return results


def main() -> None:
	input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("ciphertexts.txt")
	c1, c2 = read_ciphertexts(input_path)
	c1_xor_c2 = xor_bytes(c1, c2)

	print(f"c1 XOR c2 = {c1_xor_c2.hex()}")
	print("Crib-dragging results for ' the ':")
	candidates = crib_drag(c1_xor_c2)
	if candidates:
		for position, candidate in candidates:
			print(f"  position {position}: {candidate.decode('ascii')!r}")
	else:
		print("  no lowercase-letter/space candidates found")

	if len(TARGET) > len(c1):
		raise ValueError("c1 is shorter than the target plaintext.")
	padded_target = TARGET.ljust(len(c1), b" ")
	key_prime = xor_bytes(c1, padded_target)
	decrypted = xor_bytes(c1, key_prime)

	print(f"k' = {key_prime.hex()}")
	print(f"c1 decrypted with k' = {decrypted!r}")
	print(f"Check: c1 XOR k' == target = {decrypted == padded_target}")


if __name__ == "__main__":
	main()
