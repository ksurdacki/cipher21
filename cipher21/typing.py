from typing import Union
from os import PathLike

MutableBytes = Union[bytearray, memoryview]
Bytes = Union[bytes, MutableBytes]

Openable = Union[str, Bytes, PathLike, int]
