from .constants import KEY_LENGTH
from .bytes_utils import *
from .typing import Bytes, MutableBytes, Openable


class Cipher21Key:

    __private_init_guard = object()

    def __init__(self, guard, data: MutableBytes):
        self.bytes = data
        try:
            assert guard is self.__private_init_guard, \
                "Cipher21Key should be created using one of the Cipher21Key.from_*() methods only."
            self.assess_key()
        except BaseException:
            self.clear()
            raise

    @staticmethod
    def from_bytes(b: Bytes):
        return Cipher21Key(Cipher21Key.__private_init_guard, bytearray(b))

    @staticmethod
    def from_hexes(h: Bytes):
        return Cipher21Key(Cipher21Key.__private_init_guard, unhexlify(h))

    @classmethod
    def from_bin_file(cls, file: Openable):
        return Cipher21Key(Cipher21Key.__private_init_guard, cls._read_file(file))

    @classmethod
    def from_hex_file(cls, file: Openable):
        hexes = cls._read_file(file)
        try:
            return cls.from_hexes(hexes)
        finally:
            clear_secret(hexes)

    @staticmethod
    def _read_file(file: Openable) -> memoryview:
        with open(file, 'rb', buffering=0) as f:
            buffer = bytearray(4*KEY_LENGTH)
            length = f.readinto(buffer)
            return memoryview(buffer)[:length]

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
