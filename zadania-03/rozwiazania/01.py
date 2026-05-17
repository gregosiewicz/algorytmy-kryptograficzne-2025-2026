import os
import random
import statistics
from collections import Counter

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encrypt_block_ecb(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def flip_one_random_bit(data: bytes) -> bytes:
    data = bytearray(data)
    bit_index = random.randrange(8 * len(data))
    byte_index = bit_index // 8
    bit_in_byte = bit_index % 8
    data[byte_index] ^= 1 << bit_in_byte
    return bytes(data)


def hamming_distance(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def run_plaintext_avalanche_experiment(trials: int = 1000) -> list[int]:
    key = os.urandom(16)
    distances = []

    for _ in range(trials):
        p1 = os.urandom(16)
        p2 = flip_one_random_bit(p1)

        c1 = aes_encrypt_block_ecb(key, p1)
        c2 = aes_encrypt_block_ecb(key, p2)

        distances.append(hamming_distance(c1, c2))

    return distances


def run_key_avalanche_experiment(trials: int = 1000) -> list[int]:
    distances = []

    for _ in range(trials):
        k1 = os.urandom(16)
        k2 = flip_one_random_bit(k1)
        p = os.urandom(16)

        c1 = aes_encrypt_block_ecb(k1, p)
        c2 = aes_encrypt_block_ecb(k2, p)

        distances.append(hamming_distance(c1, c2))

    return distances


def print_results(name: str, distances: list[int]) -> None:
    print(name)
    print("min:    ", min(distances))
    print("max:    ", max(distances))
    print("srednia:", statistics.mean(distances))
    print("mediana:", statistics.median(distances))

    print("histogram:")
    counts = Counter(distances)
    for distance in sorted(counts):
        bar = "#" * counts[distance]
        print(f"{distance:3}: {counts[distance]:4} {bar}")
    print()


if __name__ == "__main__":
    trials = 1000

    plaintext_distances = run_plaintext_avalanche_experiment(trials)
    key_distances = run_key_avalanche_experiment(trials)

    print_results("Eksperyment A: zmiana jednego bitu plaintextu", plaintext_distances)
    print_results("Eksperyment B: zmiana jednego bitu klucza", key_distances)
