import os
import re
import os.path
from datetime import datetime, timezone
import sys
from typing import Sequence
import argparse

from .operation_mode import OperationMode
from .key import Cipher21Key
from .null_stream import NullStream


class ArgumentsParser:

    def __init__(self, **kwargs):
        self.parser = self._create_argument_parser(**kwargs)
        self.parser.error = self.handle_error
        self._add_mode_arguments()
        self._add_key_argument()
        self._add_after_argument()

    def parse(self, args: Sequence[str]) -> argparse.Namespace:
        parsed_args = self.parser.parse_args(args)
        self._verify_args(parsed_args)
        parsed_args.after_ns = self.parse_date_time_into_ns(parsed_args.after)
        if parsed_args.key_location:
            parsed_args.key = self.fetch_key(parsed_args.key_location)
            parsed_args.input = sys.stdin.buffer
            if parsed_args.operation_mode is OperationMode.VERIFICATION:
                parsed_args.output = NullStream()
            else:
                parsed_args.output = sys.stdout.buffer
        return parsed_args

    def format_help(self) -> str:
        return self.parser.format_help()

    def fetch_key(self, reference: str) -> Cipher21Key:
        reference = reference.split(':', 1)
        if len(reference) != 2:
            raise argparse.ArgumentError(
                None, 'No --key LOCATION scheme. Use env: or file: or fd: prefix.'
            )
        if reference[0] == 'env':
            return self.fetch_key_from_env(reference[1])
        elif reference[0] in ('file', 'fd'):
            return self.fetch_key_from_file(reference[1])
        else:
            raise argparse.ArgumentError(None, 'Unsupported secret source scheme `' + reference[0] + ':`.')

    DATE_TIME_RE = re.compile(
        '(?P<year>20[0-9]{2})-(?P<month>0[1-9]|1[012])-(?P<day>0[1-9]|[12][0-9]|3[01])T'
        '(?P<hour>[01][0-9]|2[0123])'
        '(:(?P<minute>[0-5][0-9])'
            '(:(?P<second>[0-5][0-9])'
                '(\\.(?P<fraction>[0-9]{1,9}))?'
            ')?'
        ')?Z'
    )

    def parse_date_time_into_ns(self, text) -> int:
        match = self.DATE_TIME_RE.fullmatch(text)
        if not match:
            raise argparse.ArgumentError(None, 'Malformed --after date and time value.')
        components = {
            key: int(val) for key, val in match.groupdict(default='0').items() if key != 'fraction'
        }
        try:
            result = datetime(**components, tzinfo=timezone.utc)
        except ValueError:
            raise argparse.ArgumentError(None, 'Invalid --after date value.')
        result = result - datetime(1970, 1, 1, tzinfo=timezone.utc)
        result = 10**9 * (3600*24*result.days + result.seconds)
        fraction = match.group('fraction')
        if not fraction:
            return result
        return result + int(fraction.ljust(9, '0'))

    @staticmethod
    def fetch_key_from_env(env_name: str) -> Cipher21Key:
        hex_key = os.environ.get(env_name)
        if not hex_key:
            raise argparse.ArgumentError(None, 'No value under ' + env_name + ' environment variable.')
        try:
            return Cipher21Key.from_hexes(hex_key.encode('UTF-8'))
        except Exception as error:
            raise argparse.ArgumentError(
                None, 'Error occurred while reading key from ' + env_name
                      + ' environment variable: ' + str(error)
            )

    @staticmethod
    def fetch_key_from_file(file) -> Cipher21Key:
        try:
            return Cipher21Key.from_hex_file(file)
        except Exception as error:
            raise argparse.ArgumentError(
                None, 'Error occurred while reading ' + str(file) + ' file: ' + str(error)
            )

    @staticmethod
    def _create_argument_parser(**kwargs) -> argparse.ArgumentParser:
        kwargs.setdefault('prog', 'cipher21')
        kwargs.setdefault('add_help', False)
        kwargs.setdefault('description', 'Stream authenticated encryption for year 2021.')
        kwargs.setdefault('allow_abbrev', False)
        kwargs.setdefault('epilog', '')
        kwargs.setdefault('formatter_class', argparse.RawDescriptionHelpFormatter)
        return argparse.ArgumentParser(**kwargs)

    def handle_error(self, message: str):
        raise argparse.ArgumentError(None, message)

    def _add_mode_arguments(self):
        group = self.parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            '-h', '--help', help='Show this help message and exit.', action='store_true'
        )
        group.add_argument(
            '-e', '--encrypt', help='Encryption mode.',
            dest='operation_mode', action='store_const', const=OperationMode.ENCRYPTION,
        )
        group.add_argument(
            '-v', '--verify', help='Verification mode.',
            dest='operation_mode', action='store_const', const=OperationMode.VERIFICATION,
        )
        group.add_argument(
            '-d', '--decrypt', help='Decryption mode.',
            dest='operation_mode', action='store_const', const=OperationMode.DECRYPTION,
        )

    def _add_key_argument(self):
        self.parser.add_argument(
            '-k', '--key', help='64 hexadecimal key location.',
            dest='key_location', metavar='LOCATION'
        )
        self.parser.epilog += (
            'The --key LOCATION has to be specified in one from the following forms:\n'
            ' - file:FILE_PATH\n'
            ' - env:ENVIRONMENT_VARIABLE_NAME\n'
            ' - fd:FILE_DESCRIPTION_NUMBER\n'
            '\n'
            'Example: --key file:path/to/my/secret.key'
        )

    def _add_after_argument(self):
        self.parser.add_argument(
            '-a', '--after', default='2021-01-01T00Z',
            help='Check encryption timestamp. Value must be in ISO 8601-1:2019 combined '
                 'date and time representation with a Z at the end. '
                 'Default: 2021-01-01T00Z',
            metavar='DATE_TIME')

    @staticmethod
    def _verify_args(args: argparse.Namespace) -> None:
        if args.operation_mode and not args.key_location:
            raise argparse.ArgumentError(
                None, 'Encryption, verification and decryption require a --key.'
            )


if __name__ == '__main__':
    parser = ArgumentsParser()
    args = parser.parse(sys.argv[1:])
    if args.help:
        print(parser.format_help())
