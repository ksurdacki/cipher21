from unittest import TestCase
from random import Random
from typing import Union
from os import PathLike

from .constants import KEY_LENGTH
from .bytes_utils import *


class Cipher21Key:

    __private_init_guard = object()

    def __init__(self, guard, data: bytearray):
        self.bytes = data
        try:
            assert guard is self.__private_init_guard, \
                "Cipher21Key should be created using one of the Cipher21Key.from_*() methods only."
            self.assess_key()
        except BaseException:
            self.clear()
            raise

    @staticmethod
    def from_bytes(b: bytes):
        return Cipher21Key(Cipher21Key.__private_init_guard, bytearray(b))

    @staticmethod
    def from_hexes(h: bytes):
        return Cipher21Key(Cipher21Key.__private_init_guard, unhexlify(h))

    @classmethod
    def from_bin_file(cls, file: Union[str, bytes, PathLike, int]):
        return Cipher21Key(Cipher21Key.__private_init_guard, cls._read_file(file))

    @classmethod
    def from_hex_file(cls, file: Union[str, bytes, PathLike, int]):
        hexes = cls._read_file(file)
        try:
            return cls.from_hexes(hexes)
        finally:
            clear_secret(hexes)

    @staticmethod
    def _read_file(file: Union[str, bytes, PathLike, int]) -> bytearray:
        with open(file, 'rb', buffering=0) as f:
            buffer = bytearray(4*KEY_LENGTH)
            try:
                length = f.readinto(buffer)
                return bytearray(buffer[:length])
            finally:
                clear_secret(buffer)

    def assess_key(self) -> None:
        if len(self.bytes) != KEY_LENGTH:
            raise ValueError('Key must be ' + str(KEY_LENGTH) + ' bytes long.')
        if count_unique_bytes(self.bytes) < 2 * KEY_LENGTH // 3:
            raise ValueError('Key has not enough unique bytes.')
        derivative = differentiate_bytes(self.bytes)
        unique = count_unique_bytes(derivative)
        clear_secret(derivative)
        if unique < 2 * KEY_LENGTH // 3:
            raise ValueError('Key has not enough unique differences between consecutive bytes.')

    def clear(self):
        clear_secret(self.bytes)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()

    def __del__(self):
        self.clear()


class AssessKeyTest(TestCase):

    @staticmethod
    def test_positive_cases():
        prng = Random()  # For test repetitiveness purpose only. Use SystemRandom ordinarily.
        prng.seed(0xbdc34fd75d0b49f5817b4038c45ec575, version=2)
        for t in range(10**4):
            Cipher21Key.from_bytes(prng.getrandbits(8) for _ in range(KEY_LENGTH))

    def test_negative_cases(self):
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(KEY_LENGTH*b'\x00')
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(range(KEY_LENGTH))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(range(KEY_LENGTH, 0, -1))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(range(0, 7*KEY_LENGTH, 7))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(2*bytes.fromhex('e521377823342e05bd6fe051a12a8820'))
