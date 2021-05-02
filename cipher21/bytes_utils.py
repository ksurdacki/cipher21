from random import SystemRandom
from typing import Container

from .typing import Bytes, MutableBytes


__all__ = (
    'clear_secret',
    'count_unique_bytes',
    'differentiate_bytes',
    'unhexlify',
)


_rng = SystemRandom()


def clear_secret(secret: MutableBytes) -> None:
    for i in range(len(secret)):
        secret[i] = 0xFF
    for i in range(len(secret)):
        secret[i] = 0x00
    for i in range(len(secret)):
        secret[i] = _rng.getrandbits(8)


def count_unique_bytes(b: Bytes) -> int:
    occurrences = bytearray(256)
    for x in b:
        occurrences[x] = 1
    result = sum(occurrences)
    clear_secret(occurrences)
    return result


def differentiate_bytes(b: Bytes) -> bytearray:
    if not b:
        return bytearray()
    derivative = bytearray(len(b) - 1)
    for i in range(1, len(b)):
        derivative[i-1] = (b[i] - b[i-1]) & 0xFF
    return derivative


def unhexlify(hexes: Bytes, ignored_bytes=frozenset(ord(c) for c in '\t\n\v\f\r .,:;-')) \
        -> bytearray:
    return HexToBinSecureConverter(hexes, ignored_bytes).unhexlify()


class HexToBinSecureConverter:

    def __init__(self, hexes: Bytes, ignored_bytes: Container[int]):
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
