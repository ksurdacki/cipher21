from typing import Optional

from .constants import *
from .typing import Bytes, MutableBytes
from .stream_attributes import StreamAttributes

from Crypto.Cipher import ChaCha20_Poly1305


class DecryptingError(ValueError):
    pass


class Decrypter(StreamAttributes):

    @staticmethod
    def extract_nonce(stream_header: Bytes) -> memoryview:
        assert len(stream_header) == STREAM_HEADER_LENGTH, (len(stream_header), STREAM_HEADER_LENGTH)
        if not stream_header.startswith(STREAM_SIGNATURE):
            raise ValueError('Unrecognized Cipher21 header.')
        return memoryview(stream_header)[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH]

    def initialize(self, stream_header: Bytes) -> None:
        assert not self.cipher
        self.reset()
        assert len(stream_header) == STREAM_HEADER_LENGTH, (len(stream_header), STREAM_HEADER_LENGTH)
        if not stream_header.startswith(STREAM_SIGNATURE):
            raise ValueError('Unrecognized Cipher21 header.')
        self.nonce = bytes(stream_header[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH])
        self.cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        encrypted_timestamp_ns = stream_header[TIMESTAMP_OFFSET:TIMESTAMP_OFFSET+TIMESTAMP_LENGTH]
        self.stream_timestamp_ns = int.from_bytes(
            self.cipher.decrypt(encrypted_timestamp_ns), 'little'
        )
        self.payload_length = 0

    def process_chunk(self, chunk: Bytes, output: Optional[MutableBytes] = None) -> MutableBytes:
        assert self.cipher
        if not chunk:
            return bytearray()
        if not output:
            output = bytearray(len(chunk))
        self.cipher.decrypt(chunk, output)
        self.payload_length += len(chunk)
        return output

    def finalize(self, chunk: Bytes, output: Optional[MutableBytes] = None) -> memoryview:
        assert self.cipher
        assert len(chunk) >= STREAM_FOOTER_LENGTH, (len(chunk), STREAM_FOOTER_LENGTH)
        if output:
            output = memoryview(output)[:len(chunk) - MAC_LENGTH]
        else:
            output = bytearray(len(chunk) - MAC_LENGTH)
        self.cipher.decrypt(chunk[:-MAC_LENGTH], output)
        self.mac = chunk[-MAC_LENGTH:]
        try:
            self.cipher.verify(self.mac)
        except ValueError as e:
            raise DecryptingError('MAC check failed') from e
        self.padding_length = int.from_bytes(output[-PADDING_LENGTH_LENGTH:], 'little')
        if self.padding_length >= STREAM_LENGTH_MULTIPLICAND:
            raise DecryptingError('Invalid padding')
        payload_tail_length = len(chunk) - MAC_LENGTH - PADDING_LENGTH_LENGTH - self.padding_length
        if payload_tail_length < 0:
            raise ValueError('The final stream chunk is too small to properly cut off the padding.')
        output = memoryview(output)[:payload_tail_length]
        self.payload_length += len(output)
        return output
