import sys
import logging
import argparse
from datetime import datetime, timezone
from typing import Sequence, MutableSequence, Optional

from .arguments_parser import ArgumentsParser
from .operation_mode import OperationMode
from .blocking_io import encrypt_stream, decrypt_stream
from .stream_attributes import StreamAttributes


logger = logging.getLogger(__name__)


class Application:

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

    def run(self) -> None:
        if self.parsed_args.help:
            sys.stdout.write(self.args_parser.format_help())
        elif self.parsed_args.operation_mode is OperationMode.ENCRYPTION:
            self.encrypt()
        elif self.parsed_args.operation_mode in (OperationMode.VERIFICATION, OperationMode.DECRYPTION):
            self.decrypt()
        else:
            assert False, self.parsed_args

    def encrypt(self) -> None:
        encrypter = encrypt_stream(
            self.parsed_args.output, self.parsed_args.input, self.parsed_args.key.bytes
        )
        self.log_stream_attributes(encrypter)

    def decrypt(self) -> None:
        decrypter = decrypt_stream(
            self.parsed_args.output, self.parsed_args.input, self.parsed_args.key.bytes
        )
        self.log_stream_attributes(decrypter)
        if decrypter.stream_timestamp_ns <= self.parsed_args.after_ns:
            raise ValueError('Not encrypted --after ' + self.parsed_args.after + '.')

    def log_stream_attributes(self, attrs: StreamAttributes) -> None:
        logging.info('encryption timestamp [ISO 8601]: '
                     + self.format_timestamp_ns(attrs.stream_timestamp_ns))
        logging.info('encryption timestamp [ns since Unix epoch]: {}'
                     .format(attrs.stream_timestamp_ns))
        logging.info('payload length [bytes]: {}'.format(attrs.payload_length))
        logging.info('MAC: ' + attrs.mac.hex())

    @staticmethod
    def format_timestamp_ns(ns: int) -> str:
        ts, ns = divmod(ns, 10**9)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%Y-%m%dT%H:%M:%S') + '.{:09}Z'.format(ns)

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
