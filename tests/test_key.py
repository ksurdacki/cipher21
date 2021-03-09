from unittest import TestCase
from random import Random

from cipher21.key import Cipher21Key
from cipher21.constants import KEY_LENGTH


class AssessKeyTest(TestCase):

    def test_positive_cases(self):
        prng = Random()  # For test repetitiveness purpose only. Use SystemRandom ordinarily.
        prng.seed(0xBDC34FD75D0B49F5817B4038C45EC575, version=2)
        for t in range(10**4):
            with self.subTest(t=t):
                Cipher21Key.from_bytes(bytes(prng.getrandbits(8) for _ in range(KEY_LENGTH)))

    def test_negative_cases(self):
        key = KEY_LENGTH*b'\x00'
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(key)
        key = bytes(range(KEY_LENGTH))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(key)
        key = bytes(range(0, 5*KEY_LENGTH, 5))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(key)
        key = bytes(range(KEY_LENGTH, 0, -1))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(key)
        key = bytes(range(7*KEY_LENGTH, 0, -7))
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(key)
        key = 2*bytes.fromhex('e521377823342e05bd6fe051a12a8820')
        with self.assertRaises(ValueError):
            Cipher21Key.from_bytes(key)
