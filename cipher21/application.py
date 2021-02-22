import sys
import logging
import argparse
from typing import Sequence, MutableSequence, Optional

from .arguments_parser import ArgumentsParser
from .operation_mode import OperationMode
from .bytes_utils import clear_secret
from .blocking_io import read_all, write_all
from .constants import STREAM_HEADER_LENGTH, FOOTER_LENGTH, STREAM_LENGTH_MULTIPLICAND
from .encrypter import Encrypter
from .decrypter import Decrypter


logger = logging.getLogger('cipher21')


class Application:

    buffer_size = 2**16

    def __init__(self, args: Sequence[str]):
        args = list(args)
        self.args_parser = ArgumentsParser()
        logging_level = logging.DEBUG if self.pop_debug_arg(args) else logging.INFO
        logging.basicConfig(format='%(message)s', level=logging_level)
        self.parsed_args = self.args_parser.parse(args)

    @staticmethod
    def pop_debug_arg(args: MutableSequence[str]) -> Optional[str]:
        try:
            return args.pop(args.index('--debug'))
        except ValueError:
            return None

    def run(self):
        if self.parsed_args.help:
            sys.stdout.write(self.args_parser.format_help())
        elif self.parsed_args.operation_mode is OperationMode.ENCRYPTION:
            self.encrypt()
        elif self.parsed_args.operation_mode in (
                OperationMode.VERIFICATION, OperationMode.DECRYPTION
        ):
            self.decrypt()
        else:
            assert False

    def encrypt(self) -> None:
        buffer = bytearray(self.buffer_size)
        view = memoryview(buffer)
        try:
            length = read_all(buffer, self.parsed_args.input)
            encrypter = Encrypter(self.parsed_args.key.bytes)
            write_all(self.parsed_args.output, encrypter.initialize())
            while length:
                write_all(self.parsed_args.output, encrypter.process_chunk(view[:length]))
                length = read_all(buffer, self.parsed_args.input)
        finally:
            clear_secret(buffer)
        write_all(self.parsed_args.output, encrypter.finalize())

    def decrypt(self) -> None:
        decrypter = self.create_decrypter()
        if decrypter.stream_timestamp_ns <= self.parsed_args.after_ns:
            raise ValueError('Not encrypted --after ' + self.parsed_args.after + '.')
        self.do_decrypt(decrypter)

    def create_decrypter(self) -> Decrypter:
        buffer = bytearray(STREAM_HEADER_LENGTH)
        length = read_all(buffer, self.parsed_args.input)
        if length != STREAM_HEADER_LENGTH:
            raise ValueError('Not enough data.')
        decrypted = Decrypter(self.parsed_args.key.bytes)
        decrypted.initialize(buffer)
        return decrypted

    def do_decrypt(self, decrypter: Decrypter) -> None:
        assert self.buffer_size > STREAM_LENGTH_MULTIPLICAND + FOOTER_LENGTH, self.buffer_size
        prev_buffer = bytearray(self.buffer_size)
        prev_length = read_all(prev_buffer, self.parsed_args.input)
        next_buffer = bytearray(self.buffer_size)
        next_length = read_all(next_buffer, self.parsed_args.input)
        out_buffer = bytearray(self.buffer_size)
        try:
            while next_length == len(next_buffer):
                assert prev_length == next_length, (prev_length, next_length)
                decrypter.process_chunk(prev_buffer, out_buffer)
                write_all(self.parsed_args.output, out_buffer)
                temp = prev_buffer
                prev_buffer = next_buffer
                next_buffer = temp
                next_length = read_all(next_buffer, self.parsed_args.input)
            clear_secret(out_buffer)
            out_buffer = decrypter.finalize(prev_buffer[:prev_length] + next_buffer[:next_length])
            write_all(self.parsed_args.output, out_buffer)
        finally:
            clear_secret(out_buffer)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()

    def __del__(self):
        self.clear()

    def clear(self):
        if hasattr(self, 'parsed_args') and hasattr(self.parsed_args, 'key'):
            self.parsed_args.key.clear()


if __name__ == '__main__':
    try:
        with Application(sys.argv[1:]) as app:
            app.run()
    except Exception as e:
        logger.error(str(e), exc_info=logger.isEnabledFor(logging.DEBUG))
        sys.exit(2 if isinstance(e, argparse.ArgumentError) else 1)
    except KeyboardInterrupt as e:
        logger.error('Process externally interrupted.')
        sys.exit(1)
