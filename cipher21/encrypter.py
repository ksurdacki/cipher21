import time
from secrets import token_bytes
from typing import Optional

from Crypto.Cipher import ChaCha20_Poly1305

from .constants import *
from .typing import Bytes, MutableBytes
from .stream_attributes import StreamAttributes


if hasattr(time, 'time_ns'):
    time_ns = time.time_ns
else:
    def time_ns() -> int:
        return int(1e9 * time.time())


class Encrypter(StreamAttributes):

    def initialize(self, nonce: Optional[Bytes] = None) -> bytearray:
        assert not self.cipher
        self.reset()
        self.nonce = nonce if nonce else token_bytes(NONCE_LENGTH)
        if len(self.nonce) != NONCE_LENGTH:
            raise ValueError('Nonce must be ' + str(NONCE_LENGTH) + ' bytes long.')
        stream_header = bytearray(STREAM_SIGNATURE + self.nonce + TIMESTAMP_LENGTH*b'\x00')
        self.cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        self.stream_timestamp_ns = time_ns()
        self.cipher.encrypt(
            self.stream_timestamp_ns.to_bytes(TIMESTAMP_LENGTH, 'little'),
            memoryview(stream_header)[-TIMESTAMP_LENGTH:]
        )
        self.payload_length = 0
        return stream_header

    def process_chunk(self, chunk: Bytes, output: Optional[MutableBytes] = None) -> bytearray:
        assert self.cipher
        if not chunk:
            return bytearray()
        if not output:
            output = bytearray(len(chunk))
        self.cipher.encrypt(chunk, output)
        self.payload_length += len(chunk)
        return output

    def finalize(self) -> bytearray:
        assert self.cipher
        # See README.md
        self.padding_length = (2*M - STREAM_METADATA_LENGTH - (self.payload_length % M)) % M
        padding = token_bytes(self.padding_length) \
                + self.padding_length.to_bytes(PADDING_LENGTH_LENGTH, 'little', signed=False)
        result = bytearray(len(padding) + MAC_LENGTH)
        self.cipher.encrypt(padding, memoryview(result)[:self.padding_length+PADDING_LENGTH_LENGTH])
        self.mac = self.cipher.digest()
        result[-MAC_LENGTH:] = self.mac
        self.cipher = None
        return result
