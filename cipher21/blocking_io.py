from time import sleep
from typing import Union
from io import RawIOBase


_SLEEP_INTERVAL = 1/32


def read_all(b: Union[bytearray, memoryview], f: RawIOBase) -> int:
    result = 0
    view = memoryview(b)
    while result < len(b):
        length = f.readinto(view[result:])
        if length is None:
            sleep(_SLEEP_INTERVAL)
        elif length == 0:
            return result
        else:
            assert length > 0, length
            result += length
    assert result == len(b), (result, len(b))
    return result


def write_all(f: RawIOBase, b: bytes) -> None:
    written = 0
    view = memoryview(b)
    while written < len(b):
        length = f.write(view[written:])
        if length is None:
            sleep(_SLEEP_INTERVAL)
        else:
            assert length > 0, length
            written += length
