# Simple Python SHA-256

A simple implementation of SHA-256 in Python 3 for educational purposes. This
implementation should not be trusted in production, but it seems to produce the
right values for my simple test cases, and the code is very short and
(hopefully) easy to read and learn from.

Read the
[FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
specification for more details on the algorithm.

## Usage

Program:
```
import sha256
print(sha256.sha256('Hello\n'.encode('utf-8')).hex())
```

Output:
```
66a045b452102c59d840ec097d59d9467e13a3f34f6494e539ffd32c1bb35f18
```

This matches the value from `printf "Hello\n" | sha256sum`.
