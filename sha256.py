"""
An implementation of the SHA-256 cryptographic hash function as defined in FIPS
180-4. This implementation emphasizes simplicity and readability over
performance.
"""

# pylint: disable=invalid-name

import decimal
import itertools

def primes():
    """Generates prime numbers in order using the Sieve of Eratosthenes
    approach."""
    d = {}
    q = 2
    while True:
        if q not in d:
            yield q
            d[q * q] = [q]
        else:
            for p in d[q]:
                d.setdefault(p + q, []).append(p)
            del d[q]
        q += 1

def sha_256_constant(p, r):
    """Generates the value of a constant used for SHA-256 as defined by FIPS
    180-4. A constant is the first 32 bits of the fractional part of the r-th
    root of a prime p, i.e. frac(p ^ (1 / r)) * 2^32."""
    return int(decimal.Decimal(p) ** (decimal.Decimal(1) / r) % 1 * 2**32)

def rotate_right(x, n):
    """Right-rotates the bits in a 32-bit integer x by n bits. Defined in FIPS
    180-4 in section 3.2."""
    return (x >> n) | (x << 32 - n)

def choose(x, y, z):
    """The "Ch" function as defined in FIPS 180-4 equation (4.2). For each bit
    i in 32-bit words x, y, and z if x[i] is set then result[i] is y[i],
    otherwise result[i] is z[i]. In other words the bit in x determines if the
    result bit comes from y or z."""
    return (x & y) ^ (~x & z)

def majority(x, y, z):
    """The "Maj" function as defined in FIPS 180-4 equation (4.3). For each bit
    i in 32-bit words x, y, and z if the majority of x[i], y[i], and z[i] are
    set then result[i] is set, otherwise result[i] is not set."""
    return (x & y) ^ (x & z) ^ (y & z)

def Σ0(x):
    """The "Σ0" function as defined in FIPS 180-4 equation (4.4)."""
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)

def Σ1(x):
    """The "Σ1" function as defined in FIPS 180-4 equation (4.5)."""
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)

def σ0(x):
    """The "σ0" function as defined in FIPS 180-4 equation (4.6)."""
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3)

def σ1(x):
    """The "σ1" function as defined in FIPS 180-4 equation (4.7)."""
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10)

def preprocess_message(m):
    """Preprocesses a message as defined in FIPS 180-4 section 5. Specifically,
    adds padding to a SHA-256 message as defined in FIPS 180-4 section 5.1.1,
    and splits the message into 512-bit blocks as defined in FIPS 180-4 section
    5.2.1."""
    l = len(m)
    m += b'\x80'                              # Append 0b10000000.
    m += b'\x00' * (64 - (l + 9) % 64)        # Append sufficient padding.
    m += (l * 8).to_bytes(8, byteorder='big') # Append 64-bit length.
    return [[int.from_bytes(m[b * 64 + w * 4 : b * 64 + w * 4 + 4], 'big')
             for w in range(0, 16)] for b in range(0, len(m) // 64)]

def sha256(m):
    """Computes the SHA-256 hash of a given message. Defined by FIPS 108-4
    section 6.2.1."""
    H = IV.copy()
    for w in preprocess_message(m):
        a, b, c, d, e, f, g, h = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
        for t in range(0, 64):
            if t >= 16:
                w.append((σ1(w[t-2]) + w[t-7] + σ0(w[t-15]) + w[t-16]) % 2**32)
            t1 = (h + Σ1(e) + choose(e, f, g) + K[t] + w[t]) % 2**32
            t2 = (Σ0(a) + majority(a, b, c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32
        H = [(v[0] + v[1]) % 2**32 for v in zip([a, b, c, d, e, f, g, h], H)]
    return b''.join([h.to_bytes(4, 'big') for h in H])

# Initial hash values used by the SHA-256 algorithm. This is equivalent to the
# table defined in FIPS-180 section. 5.3.3. "... the first thirty-two bits of
# the frational parts of the square roots of the first eight prime numbers."
IV = [sha_256_constant(p, 2) for p in itertools.islice(primes(), 8)]

# Constants used by the SHA-256 algorithm. This is equivalent to the table
# defined in FIPS-180 section 4.2.2. "... the first thirty-two bits of the
# fractional parts of the cube roots of the first sixty-four prime numbers."
K = [sha_256_constant(p, 3) for p in itertools.islice(primes(), 64)]
