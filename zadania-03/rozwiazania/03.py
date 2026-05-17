def split_blocks(data: bytes, block_size: int = 16) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def has_repeated_block(data: bytes, block_size: int = 16) -> bool:
    blocks = split_blocks(data, block_size)
    return len(blocks) != len(set(blocks))


def detect_mode(oracle) -> str:
    plaintext = b"A" * 32
    ciphertext = oracle(plaintext)

    if has_repeated_block(ciphertext):
        return "ECB"
    return "CBC"


def detect_mode_with_prefix(oracle) -> str:
    for pad_len in range(16):
        plaintext = b"B" * pad_len + b"A" * 64
        ciphertext = oracle(plaintext)

        if has_repeated_block(ciphertext):
            return "ECB"

    return "CBC"


if __name__ == "__main__":
    from oracle_ecb_cbc import check_detector

    correct, total = check_detector(detect_mode, with_prefix=False, trials=1000)
    print("bez prefiksu:", correct, "/", total)

    correct, total = check_detector(detect_mode_with_prefix, with_prefix=True, trials=1000)
    print("z prefiksem:", correct, "/", total)
