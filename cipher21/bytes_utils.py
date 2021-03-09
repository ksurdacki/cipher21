from random import SystemRandom
from typing import Union, Container


__all__ = (
    'clear_secret',
    'count_unique_bytes',
    'differentiate_bytes',
    'unhexlify',
)


_rng = SystemRandom()


def clear_secret(secret: Union[bytearray, memoryview]) -> None:
    for i in range(len(secret)):
        secret[i] = 0xFF
    for i in range(len(secret)):
        secret[i] = 0x00
    for i in range(len(secret)):
        secret[i] = _rng.getrandbits(8)


def count_unique_bytes(b: bytes) -> int:
    occurrences = bytearray(256)
    for x in b:
        occurrences[x] = 1
    result = sum(occurrences)
    clear_secret(occurrences)
    return result


def differentiate_bytes(b: bytes) -> bytearray:
    derivative = bytearray(len(b))
    p = bytearray(1)
    for i in range(len(b)):
        derivative[i] = (b[i] - p[0]) & 0xFF
        p[0] = b[i]
    clear_secret(p)
    return derivative


def unhexlify(hexes: bytes, ignored_bytes=frozenset(ord(c) for c in '\t\n\v\f\r .:')) \
        -> bytearray:
    return HexToBinSecureConverter(hexes, ignored_bytes).unhexlify()


class HexToBinSecureConverter:

    def __init__(self, hexes: bytes, ignored_bytes: Container[int]):
        self._hexes = hexes
        self.ignored_bytes = ignored_bytes
        self._x = bytearray(1)
        self._buffer = bytearray(len(hexes) // 2 + 1)
        self._buffer_idx = 0
        self._first_digit = True

    def unhexlify(self) -> bytearray:
        self._buffer_idx = 0
        self._first_digit = True
        try:
            self._unhexlify_to_buffer()
            if not self._first_digit:
                raise ValueError('Odd number of hexadecimal digits.')
            return bytearray(self._buffer[0:self._buffer_idx])
        finally:
            clear_secret(self._buffer)
            clear_secret(self._x)

    def _unhexlify_to_buffer(self) -> None:
        for hexes_idx in range(len(self._hexes)):
            if ord('0') <= self._hexes[hexes_idx] <= ord('9'):
                self._x[0] = self._hexes[hexes_idx] - ord('0')
            elif ord('A') <= self._hexes[hexes_idx] <= ord('F'):
                self._x[0] = self._hexes[hexes_idx] - ord('A') + 10
            elif ord('a') <= self._hexes[hexes_idx] <= ord('f'):
                self._x[0] = self._hexes[hexes_idx] - ord('a') + 10
            elif self._hexes[hexes_idx] in self.ignored_bytes:
                continue
            else:
                raise ValueError('Invalid hexadecimal symbol.')
            if self._first_digit:
                self._buffer[self._buffer_idx] = 16 * self._x[0]
            else:
                self._buffer[self._buffer_idx] += self._x[0]
                self._buffer_idx += 1
            self._first_digit = not self._first_digit
