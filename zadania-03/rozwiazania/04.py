from oracle_cbc_bitflipping import encrypt_profile, is_admin


BLOCK_SIZE = 16
PREFIX_LEN = len(b"comment1=cooking%20MCs;userdata=")
BEFORE_FALSE = len(b";admin=")


def forge_admin_token() -> bytes:
    userdata = b""
    token = bytearray(encrypt_profile(userdata))

    false_pos = PREFIX_LEN + len(userdata) + BEFORE_FALSE
    block_index = false_pos // BLOCK_SIZE
    offset = false_pos % BLOCK_SIZE

    old = b"false"
    new = b"true;"

    previous_block_start = block_index * BLOCK_SIZE
    for i in range(len(old)):
        token[previous_block_start + offset + i] ^= old[i] ^ new[i]

    return bytes(token)


if __name__ == "__main__":
    token = forge_admin_token()
    print(is_admin(token))
    assert is_admin(token) is True
