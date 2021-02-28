from io import RawIOBase
from typing import Optional, List, Iterable


class NullStream(RawIOBase):

    def close(self) -> None:
        pass

    def fileno(self):
        raise FileNotFoundError()

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False

    def readable(self) -> bool:
        return True

    def readline(self, __size: Optional[int] = ...) -> bytes:
        return bytes()

    def readlines(self, __hint: int = ...) -> List[bytes]:
        return list()

    def seek(self, __offset: int, __whence: int = ...) -> int:
        return 0

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return 0

    def truncate(self, __size: Optional[int] = ...) -> int:
        return 0

    def writable(self) -> bool:
        return True

    def writelines(self, __lines: Iterable) -> None:
        pass

    def read(self, __size: int = ...) -> Optional[bytes]:
        return bytes()

    def readall(self) -> bytes:
        return bytes()

    def readinto(self, __buffer) -> Optional[int]:
        return 0

    def write(self, __b) -> Optional[int]:
        return len(__b)
