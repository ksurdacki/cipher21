import time
from secrets import token_bytes
from typing import Optional

from Crypto.Cipher import ChaCha20_Poly1305

from .constants import *


if hasattr(time, 'time_ns'):
    time_ns = time.time_ns
else:
    def time_ns() -> int:
        return int(1e9 * time.time())


class Encrypter:

    def __init__(self, key: bytes):
        self.key = key
        self.payload_length = 0
        self.cipher = None

    def initialize(self, nonce: Optional[bytes] = None) -> bytearray:
        assert not self.cipher
        nonce = nonce if nonce else token_bytes(NONCE_LENGTH)
        if len(nonce) != NONCE_LENGTH:
            raise ValueError('Nonce must be ' + str(NONCE_LENGTH) + ' bytes long.')
        stream_header = bytearray(STREAM_SIGNATURE + nonce + TIMESTAMP_LENGTH*b'0')
        self.cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        self.cipher.encrypt(
            time_ns().to_bytes(TIMESTAMP_LENGTH, 'little'),
            memoryview(stream_header)[-TIMESTAMP_LENGTH:]
        )
        self.payload_length = 0
        return stream_header

    def process_chunk(self, chunk: bytes) -> bytearray:
        assert self.cipher
        if not chunk:
            return bytearray()
        result = bytearray(len(chunk))
        self.cipher.encrypt(chunk, result)
        self.payload_length += len(chunk)
        return result

    def finalize(self) -> bytearray:
        assert self.cipher
        p = (2*M - STREAM_METADATA_LENGTH - (self.payload_length % M)) % M  # See README.md
        padding = token_bytes(p) + p.to_bytes(PADDING_LENGTH_LENGTH, 'little', signed=False)
        result = bytearray(len(padding) + MAC_LENGTH)
        self.cipher.encrypt(padding, memoryview(result)[:p+PADDING_LENGTH_LENGTH])
        result[-MAC_LENGTH:] = self.cipher.digest()
        self.cipher = None
        return result
