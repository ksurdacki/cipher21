# Cipher21

Stream cipher application for 2021 year which uses
[XChaCha20-Poly1305](https://tools.ietf.org/html/draft-arciszewski-xchacha-03).

- `.c21` is a recommended file name extension
- `application/cipher21` ia a recommended internet media type

## 1. installation

`python3 -m pip install cipher21`

## 2. usage guide

- detailed parameters description: `cipher21 -h`
- encrypting a file with a hex key from a file: `cipher21 -e -k file:key.txt < plain.txt > encrypted.c21`
- encrypting a file with a hex key from env: `cipher21 -e -k env:KEY64 < plain.txt > encrypted.c21`
- decrypting a file with a hex key from a file: `cipher21 -d -k file:key.txt < encrypted.c21 > plain.txt`

## 3. stream format

### 3.1. stream structure

- Stream length must be always a multiple of M == 2^14 == 16384 bytes to hide the exact length of a payload.

```
 offset | len | description
--------+-----+---------------------------------------------------
      0 |   8 | stream signature: "c21\x1A\x00\xFF\x19\x82"
      8 |  24 | nonce
     32 |   E | XChaCha20-Poly1305 encrypted block (see below)
    -16 |  16 | MAC

constraints:
(8 + 24 + E + 16) % M == 0   =>   E % M == M - 48 == 16336
```

### 3.2. encrypted block

```
 offset | len | description
--------+-----+---------------------------------------------
      0 |   8 | little endian unsigned integer of an encryption time in nanoseconds
        |     | since the January 1, 1970, 00:00:00 (UTC), not counting leap seconds
      8 |   D | payload
 -2 - P |   P | randomized padding bytes
     -2 |   2 | little endian unsigned integer P - the padding length

constraints:
(8 + D + P + 2) % M == M - 48
    => (D + P) % M == M - 58
    => P % M == (M - 58 - D) % M
    => P == (2*M - 58 - (D % M)) % M
```
