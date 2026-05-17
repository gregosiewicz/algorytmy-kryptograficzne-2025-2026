import os
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def count_collision_pairs(values: list[bytes]) -> int:
    counts = Counter(values)
    return sum(c * (c - 1) // 2 for c in counts.values())


def encrypt_blocks_for_range(key: bytes, n: int) -> list[bytes]:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    ciphertexts = []
    for i in range(n):
        block = i.to_bytes(16, byteorder="big")
        ciphertexts.append(encryptor.update(block))

    encryptor.finalize()
    return ciphertexts


if __name__ == "__main__":
    key = os.urandom(16)
    ns = [1000, 10000, 50000, 100000]

    print("N       kolizje 128-bitowe    kolizje po obcieciu do 32 bitow")

    for n in ns:
        ciphertexts = encrypt_blocks_for_range(key, n)
        truncated = [c[:4] for c in ciphertexts]

        full_collisions = count_collision_pairs(ciphertexts)
        truncated_collisions = count_collision_pairs(truncated)

        print(f"{n:<7} {full_collisions:<21} {truncated_collisions}")
