from time import sleep
from io import RawIOBase

from .constants import STREAM_HEADER_LENGTH, STREAM_LENGTH_MULTIPLICAND
from .encrypter import Encrypter
from .decrypter import Decrypter
from .bytes_utils import clear_secret
from .typing import Bytes, MutableBytes


__all__ = (
    'encrypt_stream',
    'decrypt_stream',
)


def encrypt_stream(output_stream: RawIOBase, input_stream: RawIOBase, key: bytes) -> Encrypter:
    input_buffer = bytearray(BUFFER_SIZE)
    input_view = memoryview(input_buffer)
    output_buffer = bytearray(BUFFER_SIZE)
    output_view = memoryview(output_buffer)
    try:
        length = read_all(input_buffer, input_stream)
        encrypter = Encrypter(key)
        write_all(output_stream, encrypter.initialize())
        while length:
            write_all(
                output_stream,
                encrypter.process_chunk(input_view[:length], output_view[:length])
            )
            length = read_all(input_buffer, input_stream)
    finally:
        clear_secret(input_buffer)
    write_all(output_stream, encrypter.finalize())
    return encrypter


def decrypt_stream(output_stream: RawIOBase, input_stream: RawIOBase, key: bytes) -> Decrypter:
    decrypter = _create_decrypter(input_stream, key)
    prev_buffer = bytearray(BUFFER_SIZE)
    prev_length = read_all(prev_buffer, input_stream)
    next_buffer = bytearray(BUFFER_SIZE)
    next_length = read_all(next_buffer, input_stream)
    out_buffer = bytearray(BUFFER_SIZE)
    try:
        while next_length == len(next_buffer):
            assert prev_length == next_length, (prev_length, next_length)
            decrypter.process_chunk(prev_buffer, out_buffer)
            write_all(output_stream, out_buffer)
            prev_buffer, next_buffer = next_buffer, prev_buffer
            next_length = read_all(next_buffer, input_stream)
        clear_secret(out_buffer)
        out_buffer = decrypter.finalize(prev_buffer[:prev_length] + next_buffer[:next_length])
        write_all(output_stream, out_buffer)
    finally:
        clear_secret(out_buffer)
    return decrypter


def _create_decrypter(input_stream: RawIOBase, key: bytes) -> Decrypter:
    buffer = bytearray(STREAM_HEADER_LENGTH)
    length = read_all(buffer, input_stream)
    if length != STREAM_HEADER_LENGTH:
        raise ValueError('Not enough data.')
    decrypted = Decrypter(key)
    decrypted.initialize(buffer)
    return decrypted


BUFFER_SIZE = 2 * STREAM_LENGTH_MULTIPLICAND
SLEEP_INTERVAL = 1 / 32


def read_all(b: MutableBytes, f: RawIOBase) -> int:
    result = 0
    view = memoryview(b)
    while result < len(b):
        length = f.readinto(view[result:])
        if length is None:
            sleep(SLEEP_INTERVAL)
        elif length == 0:
            return result
        else:
            assert length > 0, length
            result += length
    assert result == len(b), (result, len(b))
    return result


def write_all(f: RawIOBase, b: Bytes) -> None:
    written = 0
    view = memoryview(b)
    while written < len(b):
        length = f.write(view[written:])
        if length is None:
            sleep(SLEEP_INTERVAL)
        else:
            assert length > 0, length
            written += length


