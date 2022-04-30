import random
import math


NUMS_DICT = {
    "Q": "10",
    "W": "11",
    "E": "12",
    "R": "13",
    "T": "14",
    "Y": "15",
    "U": "16",
    "I": "17",
    "O": "18",
    "P": "19",
    "A": "20",
    "S": "21",
    "D": "22",
    "F": "23",
    "G": "24",
    "H": "25",
    "J": "26",
    "K": "27",
    "L": "28",
    "Z": "29",
    "X": "30",
    "C": "31",
    "V": "32",
    "B": "33",
    "N": "34",
    "M": "35",
    "q": "36",
    "w": "37",
    "e": "38",
    "r": "39",
    "t": "40",
    "y": "41",
    "u": "42",
    "i": "43",
    "o": "44",
    "p": "45",
    "a": "46",
    "s": "47",
    "d": "48",
    "f": "49",
    "g": "50",
    "h": "51",
    "j": "52",
    "k": "53",
    "l": "54",
    "z": "55",
    "x": "56",
    "c": "57",
    "v": "58",
    "b": "59",
    "n": "60",
    "m": "61",
    " ": "62",
    ",": "63",
    ".": "64",
    "!": "65",
    "?": "66",
    "-": "67",
    "`": "68",
    "'": "69",
    '"': "70",
    ";": "71",
    ":": "72",
    "(": "73",
    ")": "74",
    "/": "75",
    "|": "76",
    "_": "77",
    "1": "78",
    "2": "79",
    "3": "80",
    "4": "81",
    "5": "82",
    "6": "83",
    "7": "84",
    "8": "85",
    "9": "86",
    "0": "87",
}


def primes(start: int, finish: int) -> list:
    """Return list of prime numbers that are in a given range.

    Args:
        start (int): Beginning, including.
        finish (int): End, excluding.

    Returns:
        list: Prime numbers.
    """
    primes = []
    for num in range(start, finish):
        isprime = True
        for dividor in range(2, math.ceil(math.sqrt(num))):
            if num % dividor == 0:
                isprime = False
        if isprime:
            primes.append(num)
    primes.remove(1) if 1 in primes else None
    return primes


def get_e(tmp: int) -> int:
    """Calculate E value of RSA public key.

    Args:
        tmp (int): Value of (p-1)*(q-1).

    Returns:
        int: E value.
    """
    choices = [x for x in range(1_000_000, 500_000, -1) if x // 2]
    for num in choices:
        if math.gcd(num, tmp) == 1:
            return num


def generate_keys() -> tuple[tuple | int]:
    """Return a pair of public and secret keys for RSA.

    Returns:
        tuple[tuple | int]: Keys for RSA.
    """
    prime_nums = primes(100_000, 150_000)
    p = random.choice(prime_nums)
    prime_nums.remove(p)
    q = random.choice(prime_nums)

    n = p * q
    e = get_e((p - 1) * (q - 1))
    d = pow(e, -1, (p - 1) * (q - 1))

    return (n, e), d


def rsa_encrypt(msg: str, public: tuple[int]) -> str:
    """Return encrypted message using RSA method.

    Args:
        msg (str): Message as a string to be encrypted.
        public (tuple[int]): Public key for encryption.

    Returns:
        str: Encrypted message as a string.
    """
    encrypted = ""
    blocks = _into_blocks(msg)
    for block in blocks:
        encrypted += str(_encrypt(int(block), public)) + "*"
    return encrypted[:-1]


def _into_blocks(msg: str) -> list[str]:
    """Return message as a list of blocks, each
    consisting of 3 characters (9 digits).
    Last block has <= 3 characters.

    Args:
        msg (str): Message to break.

    Returns:
        list[str]: List of blocks.
    """
    i = 2
    blocks = [NUMS_DICT[char] for char in msg]
    while i < len(blocks):
        blocks.insert(i, "*")
        i += 3
    blocks = "".join(blocks).split("*")
    return blocks


def _encrypt(block: int, public: tuple[int]) -> int:
    """Return encrypted block using RSA method.

    Args:
        block (int): Block to encrypt.
        public (tuple[int]): Public key for encryption.

    Returns:
        int: Encrypted block.
    """
    encrypted = pow(block, public[1], public[0])
    return encrypted


def rsa_decrypt(encrypted: str, secret: int, public: tuple) -> str:
    """Return decrypted message using RSA method.

    Args:
        encrypted (str): Encrypted message.
        secret (int): Secret key for decryption.
        public (tuple): Public key for encryption.

    Returns:
        str: Original message.
    """
    code = ""
    blocks = [int(block) for block in encrypted.split("*")]
    for block in blocks:
        code += str(_decrypt(block, secret, public))
    decrypted = _to_text(code)
    return decrypted


def _to_text(code: str) -> str:
    """Assemble original message string
    from decrypted sequence of numbers.

    Args:
        code (str): Decrypted message as a sequence of numbers.

    Returns:
        str: Original message.
    """
    text = ""
    char_dict = {NUMS_DICT[key]: key for key in NUMS_DICT}
    nums = list(code)
    i = 2
    while i < len(nums):
        nums.insert(i, "*")
        i += 3
    nums = "".join(nums).split("*")
    for num in nums:
        text += char_dict[num]
    return text


def _decrypt(block: int, secret: int, public: tuple[int]) -> int:
    """Return corresponding decrypted number
    block to encrypted block.

    Args:
        block (int): Encrypted block.
        secret (int): Secret key for decryption.
        public (tuple[int]): Public key for encryption.

    Returns:
        int: Decrypted block.
    """
    decrypted = pow(block, secret, public[0])
    return decrypted
