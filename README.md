# Cipher21

Stream cipher simple application for 2021 year which uses
[XChaCha20-Poly1305](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03)

Using XChaCha20-Poly1305 cipher provides:
- [Data integrity](https://en.wikipedia.org/wiki/Data_integrity)
- [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
- [Confidentiality](https://en.wikipedia.org/wiki/Confidentiality)
- Allows [stream processing](https://en.wikipedia.org/wiki/Stream_processing)
- [three times faster](https://tools.ietf.org/html/rfc7539) then [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
  on platforms that lack specialized AES hardware
- 256-bit key
- 192-bit nonce lower the probability of a nonce misuse

## 1. Rationale

Lack of ready to use simple application for encryption with modern cipher.

## 2. Installation

- Installed [Python 3.6](https://www.python.org/) or higher is required. 
- Type in the console `pip3 install cipher21`.

## 3. Usage Guide

- detailed parameters description: `cipher21 -h`
- cipher21 supports 64 hexadecimals keys only which you may create via:
  - `> python -c "from os import urandom; print(urandom(32).hex())" > key.hex`
  - https://www.random.org/integers/?num=8&min=0&max=65535&col=8&base=16&format=html&rnd=new
- encrypting a file with a hex key fetch from a file: `cipher21 -e -k file:key.hex < plain.txt > encrypted.c21`
- encrypting a file with a hex key fetch from an env: `cipher21 -e -k env:KEY64 < plain.txt > encrypted.c21`
- decrypting a file with a hex key fetch from a file: `cipher21 -d -k file:key.hex < encrypted.c21 > plain.txt`
- compressing and encrypting: `mysqldump --all-databases | xz -zc | cipher21 -e -k file:key.hex > db-dump.sql.xz.c21`
- decrypting and decompressing: `cat db-dump.sql.xz.c21 | cipher21 -d -k file:key.hex | xz -dc | mysql`

## 4. Recommended Designations 

- `.c21` is a recommended file name extension
- `application/cipher21` ia a recommended internet media type

## 5. Technical details

### 5.1. Stream Structure

- Stream length must always be a multiple of M == 2^14 == 16384 bytes to hide the exact length of a payload.

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

### 5.2. Encrypted Block

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
