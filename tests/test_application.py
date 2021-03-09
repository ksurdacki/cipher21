import unittest
from random import Random
from itertools import chain
import subprocess
import sys
import os
import os.path
from copy import copy
from multiprocessing.pool import Pool

from cipher21.constants import *


class TestCase:

    PROJECT_DIR = os.path.dirname(os.path.dirname(__file__))

    def __init__(self, size: int, prng: Random):
        self.size = size
        self.prng = prng
        self.key = None
        self.plain = None
        self.encryption_result = None
        self.decryption_result = None
        self.tampered_result = None

    def run(self):
        self._generate_input()
        kwargs = self._create_common_kwargs()
        self.encryption_result = subprocess.run(
            (sys.executable, '-m', 'cipher21.application', '-e', '-k', 'env:KEY'),
            input=self.plain, **kwargs
        )
        self.decryption_result = subprocess.run(
            (sys.executable, '-m', 'cipher21.application', '-d', '-k', 'env:KEY'),
            input=self.encryption_result.stdout, **kwargs,
        )
        self.tampered_result = subprocess.run(
            (sys.executable, '-m', 'cipher21.application', '-d', '-k', 'env:KEY'),
            input=self._tamper_encrypted(self.encryption_result.stdout), **kwargs,
        )
        return self

    def _generate_input(self):
        self.key = bytes(self.prng.getrandbits(8) for _ in range(32))
        self.plain = bytes(self.prng.getrandbits(8) for _ in range(self.size))

    def _create_common_kwargs(self):
        env = copy(os.environ)
        env.update(KEY=self.key.hex())
        return {
            'stdout': subprocess.PIPE,
            'stderr': subprocess.PIPE,
            'env': env,
            'cwd': self.PROJECT_DIR,
        }

    def _tamper_encrypted(self, encrypted: bytes) -> bytearray:
        tampered = bytearray(encrypted)
        i = self.prng.randrange(STREAM_HEADER_LENGTH, len(encrypted))
        tampered[i] = tampered[i] ^ (1 << self.prng.randrange(8))
        return tampered


class ApplicationTest(unittest.TestCase):

    TEST_SIZE_ORIGINS \
        = tuple(range(1, 35, 3)) \
        + tuple((40, 48, 51, 64, 80, 96)) \
        + tuple(10 ** p for p in range(2, 8)) \
        + tuple(2 ** p for p in range(7, 26)) \
        + tuple(-STREAM_METADATA_LENGTH + i*STREAM_LENGTH_MULTIPLICAND for i in range(1, 21)) \
        + tuple(-STREAM_METADATA_LENGTH + 2**p * STREAM_LENGTH_MULTIPLICAND for p in range(5, 10))
    TEST_SIZES = tuple(sorted(chain(
        *((s - 1, s, s + 1) for s in TEST_SIZE_ORIGINS)
    )))

    def setUp(self) -> None:
        self.prng = Random()  # For test repetitiveness purpose only. Use SystemRandom ordinarily.
        self.prng.seed(0xACA6E99F3B7EE68594F51ED5DE7FD778, version=2)
        self.results = []

    def test(self):
        with Pool() as pool:
            self._fill_pool(pool)
            self._test_results()

    def _fill_pool(self, pool: Pool):
        for size in self.TEST_SIZES:
            prng = Random()
            prng.seed(self.prng.getrandbits(128), version=2)
            self.results.append(pool.apply_async(TestCase(size, prng).run))

    def _test_results(self):
        for i in range(len(self.TEST_SIZES)):
            with self.subTest(size=self.TEST_SIZES[i]):
                print('Testing {:,} random bytes'.format(self.TEST_SIZES[i]))
                case = self.results[i].get()
                self.assertEqual(0, case.encryption_result.returncode, case.encryption_result.stderr)
                self.assertEqual(0, len(case.encryption_result.stdout) % STREAM_LENGTH_MULTIPLICAND)
                self.assertEqual(0, case.decryption_result.returncode, case.decryption_result.stderr)
                self.assertEqual(len(case.plain), len(case.decryption_result.stdout))
                self.assertEqual(case.plain, case.decryption_result.stdout)
                self.assertEqual(1, case.tampered_result.returncode, case.tampered_result.stderr)
                self.assertIn(b'MAC check failed', case.tampered_result.stderr)
