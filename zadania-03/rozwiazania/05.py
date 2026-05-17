from oracle_padding import (
    get_challenge,
    padding_oracle,
    reset_query_count,
    get_query_count,
)


BLOCK_SIZE = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_unpad_local(data: bytes, block_size: int = 16) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("niepoprawny padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("niepoprawny padding")
    return data[:-pad_len]


def recover_intermediate_block(iv: bytes, c0: bytes) -> bytes:
    intermediate = bytearray(BLOCK_SIZE)

    for pad_len in range(1, BLOCK_SIZE + 1):
        index = BLOCK_SIZE - pad_len
        fake_iv = bytearray(BLOCK_SIZE)

        for j in range(index + 1, BLOCK_SIZE):
            fake_iv[j] = intermediate[j] ^ pad_len

        for guess in range(256):
            fake_iv[index] = guess

            if not padding_oracle(bytes(fake_iv) + c0):
                continue

            if pad_len == 1:
                test_iv = bytearray(fake_iv)
                test_iv[index - 1] ^= 1
                if not padding_oracle(bytes(test_iv) + c0):
                    continue

            intermediate[index] = guess ^ pad_len
            break
        else:
            raise RuntimeError("nie znaleziono bajtu")

    return bytes(intermediate)


def recover_plaintext(token: bytes) -> bytes:
    iv = token[:BLOCK_SIZE]
    c0 = token[BLOCK_SIZE:]

    intermediate = recover_intermediate_block(iv, c0)
    padded_plaintext = xor_bytes(intermediate, iv)
    return pkcs7_unpad_local(padded_plaintext)


if __name__ == "__main__":
    token = get_challenge()

    reset_query_count()
    plaintext = recover_plaintext(token)

    print(plaintext)
    print("Liczba zapytan:", get_query_count())
