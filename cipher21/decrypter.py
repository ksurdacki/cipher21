from typing import Optional, Union

from .constants import *

from Crypto.Cipher import ChaCha20_Poly1305


class DecryptingError(ValueError):
    pass


class Decrypter:

    def __init__(self, key: bytes):
        self.key = key
        self.nonce = None
        self.cipher = None
        self.stream_timestamp_ns = None
        self.padding_length = None

    @staticmethod
    def extract_nonce(stream_header: bytes) -> bytes:
        assert len(stream_header) == STREAM_HEADER_LENGTH, (len(stream_header), STREAM_HEADER_LENGTH)
        if not stream_header.startswith(STREAM_SIGNATURE):
            raise ValueError('Unrecognized Cipher21 header.')
        return bytes(stream_header[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH])

    def initialize(self, stream_header: bytes) -> None:
        assert not self.cipher
        assert len(stream_header) == STREAM_HEADER_LENGTH, (len(stream_header), STREAM_HEADER_LENGTH)
        if not stream_header.startswith(STREAM_SIGNATURE):
            raise ValueError('Unrecognized Cipher21 header.')
        self.nonce = bytes(stream_header[NONCE_OFFSET:NONCE_OFFSET+NONCE_LENGTH])
        self.cipher = ChaCha20_Poly1305.new(key=self.key, nonce=self.nonce)
        encrypted_timestamp_ns = stream_header[TIMESTAMP_OFFSET:TIMESTAMP_OFFSET+TIMESTAMP_LENGTH]
        self.stream_timestamp_ns = int.from_bytes(
            self.cipher.decrypt(encrypted_timestamp_ns), 'little'
        )

    def process_chunk(self, chunk: bytes, output: Union[None, bytearray, memoryview] = None) \
            -> Union[bytearray, memoryview]:
        assert self.cipher
        if not chunk:
            return bytearray()
        if not output:
            output = bytearray(len(chunk))
        self.cipher.decrypt(chunk, output)
        return output

    def finalize(self, chunk: bytes, output: Optional[bytes] = None) -> memoryview:
        assert self.cipher
        assert len(chunk) >= FOOTER_LENGTH, (len(chunk), FOOTER_LENGTH)
        if not output:
            output = bytearray(len(chunk) - MAC_LENGTH)
        self.cipher.decrypt(chunk[:-MAC_LENGTH], output)
        self.padding_length = int.from_bytes(output[-PADDING_LENGTH_LENGTH:], 'little')
        if self.padding_length >= STREAM_LENGTH_MULTIPLICAND:
            raise DecryptingError()
        payload_tail_length = len(chunk) - MAC_LENGTH - PADDING_LENGTH_LENGTH - self.padding_length
        if payload_tail_length < 0:
            raise ValueError('The final stream chunk is too small to properly cut off the padding.')
        output = memoryview(output)[:payload_tail_length]
        try:
            self.cipher.verify(chunk[-MAC_LENGTH:])
        except ValueError as e:
            raise DecryptingError() from e
        return output
