## Zadanie 1

Tego samego klucza `k` użyto do zaszyfrowania ośmiu wiadomości szyfrem
jednorazowym (OTP). Odszyfruj wszystkie wiadomości.

*Wskazówka*: Wszystkie teksty jawne zawierają wyłącznie mały litery i
spacje. Zastanów się, co dzieje się z literami w kodzie ASCII, gdy
xorujemy je ze spacją. Wykorzystaj też fakt, że w tekstach angielskich
często pojawia się słowo `the`.

Szyfrogramy wiadomości w formacie szesnastkowym:
```
01:
fa313f179908743aeda9361b304d9aba31eaeb498908373869a362b303ba10b9
96a999ab61c4124f1efad632612f0d0f77dbd5729746

02:
f93c7a5b9e016168fde1324b2b5a8cbf74e1a51d9505727667bd36a00aad15b9
92a49aa92485155d0fed84667d22484762dbd56f80

03:
fa313f1789026527fbfd77042e1f81a431aeb85c8708632f2cbb24e316a01eb9
84b791a126c054491ee9952e6c2e0d137adf877698586aa5

04:
fe353f568802352afbe0390c604b9da974eaa45e9400723878a762b70de80ff1
83e597a327cc175e5bea93206638484766d2c23b944460a397632101dd078eeb

05:
fa313f179808742be1a9250e365690bb31eaeb49890837316db927e303a61fb9
92ad9dab61d11c5e5bfc9327646a5a0666d9cf7e9d0171bf9b2d3048cd0a84

06:
fa313f1788137a3ae4a9341e341f81a431aea754860563252cb536e316a01eb9
92ad9da435c0061b1ae692667d22484762d6c662d9446bb39b69

07:
ae2d3252db047d2defa9240e324990a874faa358c11e78237cf435ab0ba41eb9
92ad9de523c41a5f5bf89a27702f494773c8c86e974525a396686651c81d80

08:
ef3f2e5289477624e8fa244b345790ec27fabe59840363252ca437b742bc13fc
c6a797aa2ad6545215a8822e6c6a4106709ac97e985325a396686646c81b8e
```

## Zadanie 2

Zaimplementuj algorytm szyfrowania i deszyfrowania DES w oparciu o
[oficjalną specyfikację](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf).

Możesz wykorzystać szablon:
```python
from typing import List

IP = (
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
)

IP_INV = (
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9,  49, 17, 57, 25
)

E = (
    32, 1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
)

P = (
    16, 7,  20, 21,
    29, 12, 28, 17,
    1,  15, 23, 26,
    5,  18, 31, 10,
    2,  8,  24, 14,
    32, 27, 3,  9,
    19, 13, 30, 6,
    22, 11, 4,  25
)

S_BOXES = (
    # S1
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    # S2
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    # S3
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    # S4
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    # S5
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    # S6
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    # S7
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    # S8
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)

PC1 = (
    57, 49, 41, 33, 25, 17, 9,
    1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27,
    19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29,
    21, 13, 5,  28, 20, 12, 4
)

SHIFT_SCHEDULE = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

PC2 = (
    14, 17, 11, 24, 1,  5,
    3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,
    16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
)


def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def generate_subkeys(key64: int) -> List[int]:
    pass


def feistel(R: int, subkey48: int) -> int:
    pass


def des_encrypt_block(block64: int, key64: int) -> int:
    pass


def des_decrypt_block(block64: int, key64: int) -> int:
    pass



if __name__ == "__main__":
    key = 0x133457799BBCDFF1
    pt  = 0x0123456789ABCDEF
    ct_expected = 0x85E813540F0AB405

    ct = des_encrypt_block(pt, key)
    print(f"CT = {ct:016X} (oczekiwane {ct_expected:016X})")
    assert ct == ct_expected

    pt_back = des_decrypt_block(ct, key)
    assert pt_back == pt

    try:
        from Crypto.Cipher import DES
        import secrets

        for i in range(50):
            key_r = secrets.randbits(64)
            pt_r  = secrets.randbits(64)

            key_rb = int_to_bytes(key_r, 8)
            pt_rb  = int_to_bytes(pt_r, 8)

            ct_r = des_encrypt_block(pt_r, key_r)
            ct_r_lib = bytes_to_int(DES.new(key_rb, DES.MODE_ECB).encrypt(pt_rb))

            assert ct_r == ct_r_lib

            pt_r_back = des_decrypt_block(ct_r_lib, key_r)
            pt_r_back_lib  = bytes_to_int(
                DES.new(key_rb, DES.MODE_ECB).decrypt(int_to_bytes(ct_r, 8))
            )

            assert pt_r_back == pt_r == pt_r_back_lib

        print("Losowe testy OK.")

    except ImportError:
        print("Potrzebna biblioteka pycryptodome -> pip install pycryptodome.")

```

## Zadanie 3

Przeprowadź atak `meet-in-the-middle` na `2DES`. Dla uproszczenia,
obetniemy przestrzeń kluczy do $\\{0,1,2,...,2^{16}-1\\}$. W rozwiązaniu
możesz użyć implementacji `DES` z biblioteki `PyCryptodome`, natomiast
atak `meet-in-the-middle` zaimplementuj samodzielnie.

Każdy 16-bitowy klucz rozszerzamy do 64-bitowego klucza DES przez funkcję:
```python
import hashlib

from Crypto.Cipher import DES


KEY_BITS = 16


def _set_odd_parity(key: bytes) -> bytes:
    b = bytearray(key)
    for i in range(8):
        v = b[i] & 0xFE
        b[i] = v | ((v.bit_count() ^ 1) & 1)
    return bytes(b)


def seed_to_des64(seed: int) -> bytes:
    assert 0 <= seed < (1 << KEY_BITS)

    seed_bytes = seed.to_bytes((KEY_BITS + 7) // 8, "big")
    digest = hashlib.blake2s(
        seed_bytes,
        digest_size=7,
        person=b"DESMITM3",
    ).digest()

    key56 = int.from_bytes(digest, "big")
    out = bytearray(8)
    for i in range(8):
        seven_bits = (key56 >> (7 * (7 - i))) & 0x7F
        out[i] = seven_bits << 1

    return _set_odd_parity(bytes(out))


def int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def des_encrypt_block(block64: int, key64: bytes) -> int:
    return bytes_to_int(
        DES.new(key64, DES.MODE_ECB).encrypt(int_to_bytes(block64, 8))
    )


def des_decrypt_block(block64: int, key64: bytes) -> int:
    return bytes_to_int(
        DES.new(key64, DES.MODE_ECB).decrypt(int_to_bytes(block64, 8))
    )


def encrypt_2des(block64: int, seed1: int, seed2: int) -> int:
    key1 = seed_to_des64(seed1)
    key2 = seed_to_des64(seed2)
    return des_encrypt_block(des_encrypt_block(block64, key1), key2)

```
Wyznacz klucze, których użyto do szyfrowania `2DES` dla
```
Tekst jawny: 0x4D49544D61747461
Szyfrogram:  0x215F77069038052F
```
