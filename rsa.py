import random
import math


def primes(start: int, finish: int) -> list:
    assert isinstance(start, int) and isinstance(
        finish, int) and start <= finish
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
    assert isinstance(tmp, int)
    choices = [x for x in range(3, 1000000) if x // 2]
    for num in list(reversed(choices)):
        if math.gcd(num, tmp) == 1:
            return num


def generate_keys():
    prime_nums = primes(100000, 150000)
    p = random.choice(prime_nums)
    prime_nums.remove(p)
    q = random.choice(prime_nums)
    n = p * q
    e = get_e((p - 1) * (q - 1))
    d = pow(e, -1, (p - 1) * (q - 1))
    return (n, e), d


def rsa_encrypt(msg: str, public: tuple[int]) -> int:
    # assert msg < public[0]
    try:
        msg = int(msg)
        assert msg < public[0], "secret must be less than public key"
    except Exception:
        print("Bad message")
        quit()
    encrypted = pow(msg, public[1], public[0])
    return encrypted


def rsa_decrypt(code: int, secret: int, public: tuple) -> int:
    decrypted = pow(code, secret, public[0])
    return decrypted
