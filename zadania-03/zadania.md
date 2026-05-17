W zadaniach korzystamy z AES jako gotowego prymitywu kryptograficznego
z pakietu `cryptography`. Nie implementujemy samodzielnie `SubBytes`,
`ShiftRows`, `MixColumns`, harmonogramu klucza ani całego AES-a.

Możesz wykorzystać wspólne funkcje pomocnicze:
```python
# aes_helpers.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

AES_BLOCK_SIZE = 16
AES_BLOCK_BITS = 128


def aes_encrypt_block_ecb(key: bytes, block: bytes) -> bytes:
    """
    Szyfruje pojedynczy blok AES w trybie ECB.

    ECB jest tutaj używany wyłącznie po to, aby dostać się do operacji
    szyfrowania pojedynczego bloku. Nie należy traktować ECB jako
    bezpiecznego trybu szyfrowania wiadomości.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def pkcs7_pad(data: bytes, block_bits: int = AES_BLOCK_BITS) -> bytes:
    padder = padding.PKCS7(block_bits).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes, block_bits: int = AES_BLOCK_BITS) -> bytes:
    unpadder = padding.PKCS7(block_bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_encrypt_cbc_raw(key: bytes, iv: bytes, padded_plaintext: bytes) -> bytes:
    """
    Szyfruje dane AES-CBC. Dane wejściowe muszą już mieć długość
    podzielną przez 16 bajtów.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def aes_decrypt_cbc_raw(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Deszyfruje dane AES-CBC. Wynik nadal zawiera padding.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
```

## Zadanie 1

Sprawdź eksperymentalnie efekt lawinowy AES. Traktuj AES-128 jako funkcję:
```text
blok 16 bajtów -> blok 16 bajtów
```
dla ustalonego klucza.

Wykonaj dwa eksperymenty po co najmniej `1000` prób.

Eksperyment A:
- wylosuj jeden klucz AES-128,
- w każdej próbie wylosuj blok plaintextu `P` o długości 16 bajtów,
- utwórz blok `P2`, który różni się od `P` dokładnie jednym bitem,
- zaszyfruj oba bloki tym samym kluczem,
- policz odległość Hamminga między szyfrogramami.

Eksperyment B:
- w każdej próbie wylosuj klucz `K` o długości 16 bajtów,
- utwórz klucz `K2`, który różni się od `K` dokładnie jednym bitem,
- wylosuj blok plaintextu `P` o długości 16 bajtów,
- zaszyfruj `P` pod kluczami `K` i `K2`,
- policz odległość Hamminga między szyfrogramami.

Dla obu eksperymentów oblicz minimum, maksimum, średnią, medianę oraz
histogram liczby zmienionych bitów. Histogram możesz narysować za
pomocą `matplotlib` albo wypisać tekstowo.

Zaimplementuj co najmniej:
```python
def flip_one_random_bit(data: bytes) -> bytes:
    """
    Zwraca kopię data, w której zmieniono dokładnie jeden losowy bit.
    """
    ...


def hamming_distance(a: bytes, b: bytes) -> int:
    """
    Zwraca liczbę bitów, na których a i b się różnią.
    """
    ...


def run_plaintext_avalanche_experiment(trials: int = 1000) -> list[int]:
    """
    Wykonuje eksperyment A i zwraca listę odległości Hamminga.
    """
    ...


def run_key_avalanche_experiment(trials: int = 1000) -> list[int]:
    """
    Wykonuje eksperyment B i zwraca listę odległości Hamminga.
    """
    ...
```

## Zadanie 2

Dla ustalonego losowego klucza AES-128 szyfruj bloki odpowiadające kolejnym
liczbom całkowitym:
```text
0, 1, 2, 3, ..., N - 1
```

Każdą liczbę zakoduj jako 16-bajtowy blok w porządku big-endian:
```python
block = i.to_bytes(16, byteorder="big")
```

Następnie zaszyfruj blok AES-em:
```python
ciphertext = aes_encrypt_block_ecb(key, block)
```

Wykonaj eksperyment dla kilku wartości `N`, na przykład:
```text
N = 1000
N = 10000
N = 50000
N = 100000
```

Dla każdej wartości `N` policz:
- liczbę kolizji w pełnych 16-bajtowych szyfrogramach,
- liczbę kolizji po obcięciu każdego szyfrogramu do pierwszych 4 bajtów.

Kolizje licz jako liczbę par różnych wejść, które dały ten sam wynik.
Jeżeli jakaś wartość wystąpiła `c` razy, to liczba par kolidujących wynosi:
```text
c * (c - 1) / 2
```

Zaimplementuj co najmniej:
```python
def count_collision_pairs(values: list[bytes]) -> int:
    """
    Liczy liczbę par kolidujących w liście wartości.
    """
    ...


def encrypt_blocks_for_range(key: bytes, n: int) -> list[bytes]:
    """
    Szyfruje bloki odpowiadające liczbom 0, 1, ..., n - 1.
    """
    ...
```

Przygotuj tabelę:
```text
N       kolizje 128-bitowe    kolizje po obcięciu do 32 bitów
1000    ...                   ...
10000   ...                   ...
50000   ...                   ...
100000  ...                   ...
```

## Zadanie 3

Napisz program, który rozpoznaje, czy dana funkcja szyfrująca używa
trybu ECB, czy CBC. Nie znasz klucza, trybu ani IV. Możesz jedynie
podawać własne dane wejściowe i obserwować szyfrogram.

```python
# oracle_ecb_cbc.py

import os
import random
from collections.abc import Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


AES_BLOCK_SIZE = 16
AES_BLOCK_BITS = 128


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    return padder.update(data) + padder.finalize()


def _aes_encrypt_ecb(key: bytes, padded_plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def _aes_encrypt_cbc(key: bytes, iv: bytes, padded_plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def _make_oracle(with_prefix: bool) -> tuple[Callable[[bytes], bytes], str]:
    """
    Zwraca parę:

        oracle, prawdziwy_tryb

    Funkcja jest przeznaczona do testów. Rozwiązanie nie powinno
    korzystać z wartości real_mode ani z prywatnego stanu oracle'a.
    """
    key = os.urandom(16)
    real_mode = random.choice(["ECB", "CBC"])

    if with_prefix:
        prefix = os.urandom(random.randint(0, 31))
    else:
        prefix = b""

    def oracle(user_data: bytes) -> bytes:
        if not isinstance(user_data, bytes):
            raise TypeError("oracle przyjmuje argument typu bytes")

        plaintext = prefix + user_data
        padded = _pkcs7_pad(plaintext)

        if real_mode == "ECB":
            return _aes_encrypt_ecb(key, padded)

        iv = os.urandom(AES_BLOCK_SIZE)
        return _aes_encrypt_cbc(key, iv, padded)

    return oracle, real_mode


def new_basic_oracle() -> Callable[[bytes], bytes]:
    """
    Zwraca oracle do wersji podstawowej.
    """
    oracle, _ = _make_oracle(with_prefix=False)
    return oracle


def new_prefixed_oracle() -> Callable[[bytes], bytes]:
    """
    Zwraca oracle do wersji z nieznanym prefiksem.
    """
    oracle, _ = _make_oracle(with_prefix=True)
    return oracle


def check_detector(detector: Callable[[Callable[[bytes], bytes]], str],
                   *,
                   with_prefix: bool,
                   trials: int = 1000) -> tuple[int, int]:
    """
    Testuje detektor i zwraca parę:

        liczba_poprawnych, liczba_testów
    """
    correct = 0

    for _ in range(trials):
        oracle, real_mode = _make_oracle(with_prefix=with_prefix)
        detected = detector(oracle)

        if detected not in {"ECB", "CBC"}:
            raise ValueError(f"detector zwrócił niepoprawną wartość: {detected!r}")

        if detected == real_mode:
            correct += 1

    return correct, trials
```

Funkcja `_make_oracle` jest funkcją pomocniczą w dostarczonym pliku.
Zwracany przez nią `oracle` to funkcja szyfrująca typu:
```python
Callable[[bytes], bytes]
```

Taki `oracle` przyjmuje dane użytkownika jako `bytes` i zwraca
szyfrogram jako `bytes`. Wewnątrz ma zapamiętany losowy klucz, tryb
szyfrowania oraz, w wariancie trudniejszym, losowy prefiks.

W rozwiązaniu traktuj `oracle` jak czarną skrzynkę. Nie wolno
korzystać z prywatnych zmiennych ani z wartości `real_mode`.

Zaimplementuj:
```python
def split_blocks(data: bytes, block_size: int = 16) -> list[bytes]:
    """
    Dzieli dane na bloki o długości block_size.
    """
    ...


def has_repeated_block(data: bytes, block_size: int = 16) -> bool:
    """
    Zwraca True, jeżeli w data występują co najmniej dwa identyczne bloki.
    """
    ...


def detect_mode(oracle) -> str:
    """
    Zwraca "ECB" albo "CBC".
    """
    ...
```

*Wskazówka*: tryb ECB szyfruje każdy blok niezależnie. Jeżeli dwa bloki
plaintextu są identyczne, to w ECB odpowiadające im bloki szyfrogramu
również będą identyczne. W CBC taka zależność nie powinna być widoczna.

Przetestuj rozwiązanie:
```python
from oracle_ecb_cbc import check_detector

correct, total = check_detector(detect_mode, with_prefix=False, trials=1000)
print(correct, "/", total)
```

W wariancie trudniejszym oracle przed Twoimi danymi dodaje losowy,
nieznany prefiks o długości od `0` do `31` bajtów. Dla danego oracle'a
prefiks jest stały, ale nie znasz jego treści ani długości.

*Wskazówka*: spróbuj różnych długości dopełnienia przed długim ciągiem
identycznych bajtów, aby dla jednej z nich uzyskać co najmniej dwa pełne
identyczne bloki ustawione na granicach bloków AES.

Zaimplementuj:
```python
def detect_mode_with_prefix(oracle) -> str:
    """
    Zwraca "ECB" albo "CBC", mimo że oracle dodaje nieznany prefiks.
    """
    ...
```

Przetestuj wariant trudniejszy:
```python
from oracle_ecb_cbc import check_detector

correct, total = check_detector(detect_mode_with_prefix, with_prefix=True, trials=1000)
print(correct, "/", total)
```

## Zadanie 4

Przeprowadź atak bit-flipping na CBC. Nie łamiesz AES-a ani nie
odzyskujesz klucza. Atak polega na modyfikacji szyfrogramu tak, aby po
odszyfrowaniu plaintext zawierał fragment:
```python
b";admin=true;"
```

```python
# oracle_cbc_bitflipping.py

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


AES_BLOCK_SIZE = 16
AES_BLOCK_BITS = 128

_KEY = os.urandom(16)

_PREFIX = b"comment1=cooking%20MCs;userdata="
_SUFFIX = b";admin=false;comment2=%20like%20a%20pound%20of%20bacon"


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _aes_encrypt_cbc(key: bytes, iv: bytes, padded_plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def _aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def sanitize(userdata: bytes) -> bytes:
    """
    Usuwa możliwość bezpośredniego wstawienia separatorów pól.
    """
    return userdata.replace(b";", b"%3B").replace(b"=", b"%3D")


def encrypt_profile(userdata: bytes) -> bytes:
    """
    Tworzy profil użytkownika, sanityzuje userdata, szyfruje całość
    AES-CBC i zwraca token w postaci IV || ciphertext.
    """
    if not isinstance(userdata, bytes):
        raise TypeError("userdata musi być typu bytes")

    plaintext = _PREFIX + sanitize(userdata) + _SUFFIX
    padded = _pkcs7_pad(plaintext)

    iv = os.urandom(AES_BLOCK_SIZE)
    ciphertext = _aes_encrypt_cbc(_KEY, iv, padded)

    return iv + ciphertext


def is_admin(token: bytes) -> bool:
    """
    Odszyfrowuje token i sprawdza, czy plaintext zawiera b";admin=true;".
    """
    if not isinstance(token, bytes):
        raise TypeError("token musi być typu bytes")

    if len(token) < 2 * AES_BLOCK_SIZE:
        return False

    if len(token) % AES_BLOCK_SIZE != 0:
        return False

    iv = token[:AES_BLOCK_SIZE]
    ciphertext = token[AES_BLOCK_SIZE:]

    try:
        padded_plaintext = _aes_decrypt_cbc(_KEY, iv, ciphertext)
        plaintext = _pkcs7_unpad(padded_plaintext)
    except ValueError:
        return False

    return b";admin=true;" in plaintext
```

W rozwiązaniu używaj tylko:
```python
from oracle_cbc_bitflipping import encrypt_profile, is_admin
```

Funkcja `sanitize` zamienia znaki `b";"` i `b"="`, więc nie możesz po
prostu przekazać `b";admin=true;"` jako `userdata`.

Zaimplementuj:
```python
def forge_admin_token() -> bytes:
    """
    Zwraca zmodyfikowany token, dla którego is_admin(token) == True.
    """
    ...
```

Warunek sukcesu:
```python
token = forge_admin_token()
assert is_admin(token) is True
```

*Przypomnienie*: w CBC deszyfrowanie bloku wygląda następująco:
```text
p_i = d_k(c_i) XOR c_{i-1}
```

Dla pierwszego bloku:
```text
p_0 = d_k(c_0) XOR IV
```

Jeżeli zmienisz jeden bajt w bloku `c_{i-1}`, to zmienisz
odpowiadający mu bajt w plaintextowym bloku `p_i`.

Dla pojedynczego bajtu możesz policzyć modyfikację tak:
```text
c'_{i-1}[j] = c_{i-1}[j] XOR stary_bajt_plaintextu XOR oczekiwany_bajt_plaintextu
```

Nie przygotowuj w `userdata` prawie gotowego fragmentu typu:
```python
b"XadminXtrueX"
```
tylko po to, aby potem zmienić znaki `X` na `;`, `=` oraz `;`.

Wykorzystaj istniejący fragment z sufiksu:
```python
b";admin=false;"
```
i zmień go tak, aby po odszyfrowaniu zawierał:
```python
b";admin=true;"
```

Możesz myśleć o tym jak o usunięciu wartości `false` i wstawieniu
w jej miejsce `true;`. Wtedy fragment:
```python
b";admin=false;"
```
może po modyfikacji szyfrogramu zmienić się w:
```python
b";admin=true;;"
```

Dobierz długość `userdata` tak, aby tekst `false` znalazł się w
wygodnym miejscu względem granic bloków AES, najlepiej w całości w
jednym bloku.

Nie wolno używać klucza AES, funkcji deszyfrującej, prywatnych
zmiennych z oracle'a, modyfikować kodu `encrypt_profile` ani
`is_admin`, ani przekazać bezpośrednio `b";admin=true;"` jako
`userdata`.

## Zadanie 5

Przeprowadź atak padding oracle na jeden blok szyfrogramu CBC. Nie
znasz klucza i nie korzystasz z funkcji deszyfrującej. Wykorzystujesz
wyłącznie informację, czy padding PKCS#7 po odszyfrowaniu jest
poprawny.

```python
# oracle_padding.py

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


AES_BLOCK_SIZE = 16
AES_BLOCK_BITS = 128

_KEY = os.urandom(16)
_QUERY_COUNT = 0

_ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-{}"


def _pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    return padder.update(data) + padder.finalize()


def _pkcs7_unpad(data: bytes) -> bytes:
    unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def _aes_encrypt_cbc(key: bytes, iv: bytes, padded_plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def _aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _random_short_plaintext() -> bytes:
    """
    Zwraca losowy plaintext o długości od 1 do 15 bajtów.
    Po dodaniu PKCS#7 dostaniemy dokładnie jeden blok plaintextu.
    """
    length = 1 + (os.urandom(1)[0] % 15)
    random_bytes = os.urandom(length)
    return bytes(_ALPHABET[b % len(_ALPHABET)] for b in random_bytes)


def get_challenge() -> bytes:
    """
    Zwraca szyfrogram postaci IV || c_0.
    Plaintext jest krótką losową wiadomością ASCII.
    """
    plaintext = _random_short_plaintext()
    padded = _pkcs7_pad(plaintext)

    if len(padded) != AES_BLOCK_SIZE:
        raise RuntimeError("Challenge powinien mieć dokładnie jeden blok.")

    iv = os.urandom(AES_BLOCK_SIZE)
    c0 = _aes_encrypt_cbc(_KEY, iv, padded)

    return iv + c0


def reset_query_count() -> None:
    """
    Zeruje licznik zapytań do oracle'a.
    """
    global _QUERY_COUNT
    _QUERY_COUNT = 0


def get_query_count() -> int:
    """
    Zwraca liczbę wywołań padding_oracle od ostatniego resetu.
    """
    return _QUERY_COUNT


def padding_oracle(token: bytes) -> bool:
    """
    Przyjmuje token IV || c_0 i zwraca True wtedy i tylko wtedy,
    gdy padding po odszyfrowaniu jest poprawny.
    """
    global _QUERY_COUNT
    _QUERY_COUNT += 1

    if not isinstance(token, bytes):
        raise TypeError("token musi być typu bytes")

    if len(token) != 2 * AES_BLOCK_SIZE:
        return False

    iv = token[:AES_BLOCK_SIZE]
    c0 = token[AES_BLOCK_SIZE:]

    try:
        padded_plaintext = _aes_decrypt_cbc(_KEY, iv, c0)
        _pkcs7_unpad(padded_plaintext)
    except ValueError:
        return False

    return True
```

W rozwiązaniu używaj tylko:
```python
from oracle_padding import (
    get_challenge,
    padding_oracle,
    reset_query_count,
    get_query_count,
)
```

Funkcja `get_challenge()` zwraca token:
```text
IV || c_0
```
gdzie IV ma 16 bajtów, a `c_0` jest jednym blokiem szyfrogramu AES-CBC.

Dla jednego bloku:
```text
p_0 = d_k(c_0) XOR IV
```

Modyfikując IV, możesz wpływać na bajty plaintextu `p_0` po
odszyfrowaniu. Oracle mówi tylko, czy wynikowy plaintext ma poprawny
padding PKCS#7.

Poprawny padding PKCS#7 dla bloku 16-bajtowego ma jedną z postaci:
```text
... 01
... 02 02
... 03 03 03
...
... 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10
```

Zaimplementuj:
```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Zwraca XOR dwóch obiektów bytes tej samej długości.
    """
    ...


def pkcs7_unpad_local(data: bytes, block_size: int = 16) -> bytes:
    """
    Usuwa poprawny padding PKCS#7 bez korzystania z funkcji oracle'a.
    """
    ...


def recover_intermediate_block(iv: bytes, c0: bytes) -> bytes:
    """
    Odzyskuje I_0 = d_k(c_0), korzystając z padding_oracle.
    """
    ...


def recover_plaintext(token: bytes) -> bytes:
    """
    Odzyskuje plaintext z tokenu IV || c_0.
    """
    ...
```

Następnie wykonaj:
```python
from oracle_padding import get_challenge, reset_query_count, get_query_count

token = get_challenge()

reset_query_count()
plaintext = recover_plaintext(token)

print(plaintext)
print("Liczba zapytań:", get_query_count())
```

*Wskazówka*: wprowadź wartość pośrednią:
```text
I_0 = d_k(c_0)
```

Wtedy:
```text
p_0 = I_0 XOR IV
```

Atakuj bajty od końca bloku do początku. Dla każdej długości paddingu
`pad_len` od `1` do `16`:
1. Przygotuj zmodyfikowany IV.
2. Bajty, które już odzyskałeś, ustaw tak, aby po odszyfrowaniu dawały
   padding `pad_len`.
3. Zgaduj kolejny bajt, wykonując maksymalnie `256` zapytań do oracle'a.
4. Gdy oracle zwróci `True`, zapisz odzyskaną wartość.
5. Przejdź do następnego bajtu.

Dla ostatniego bajtu mogą zdarzyć się fałszywe trafienia, gdy oracle
zwraca `True` z powodu oryginalnego poprawnego paddingu. Obsłuż taki
przypadek, na przykład dodatkowym zapytaniem, w którym zmieniasz
jeszcze jeden wcześniejszy bajt IV.

Nie wolno znać ani odgadywać klucza AES, korzystać z funkcji
deszyfrującej, modyfikować oracle'a ani używać prywatnych zmiennych i
funkcji z pliku `oracle_padding.py`.
