import os
import io
import re
import os.path
from datetime import datetime, timezone
import sys
from typing import Sequence
import argparse

from cipher20.operation_mode import OperationMode


class ArgumentsParser:

    def __init__(self, **kwargs):
        kwargs.setdefault('add_help', False)
        kwargs.setdefault('description', 'Stream authenticated encryption for 2020.')
        kwargs.setdefault('allow_abbrev', False)
        kwargs.setdefault('epilog', '')
        kwargs.setdefault('formatter_class', argparse.RawDescriptionHelpFormatter)
        self.parser = argparse.ArgumentParser(**kwargs)
        self.parser.error = self.handle_error
        self._add_mode_arguments()
        self._add_secret_arguments()
        self.parser.add_argument('-a', '--after', default='2020-10-10T20:20:10.10Z',
                                 help='Check encryption timestamp. '
                                 'Value must be in ISO 8601-1:2019 combined date and time '
                                 'representation with a Z at the end. '
                                 'Default: 2020-10-10T20:20:10.10Z.',
                                 metavar='DATE_TIME')

    def parse(self, args: Sequence[str]) -> argparse.Namespace:
        parsed_args = self.parser.parse_args(args)
        self._verify_args(parsed_args)
        parsed_args.after = self.parse_date_time_into_ns(parsed_args.after)
        if parsed_args.password:
            parsed_args.password = self.fetch_secret(parsed_args.password)
        elif parsed_args.hex_key:
            parsed_args.hex_key = self.fetch_secret(parsed_args.hex_key)
        elif parsed_args.raw_key:
            parsed_args.raw_key = self.fetch_secret(parsed_args.raw_key)
        return parsed_args

    def format_help(self) -> str:
        return self.parser.format_help()

    def fetch_secret(self, reference: str) -> bytearray:
        reference = reference.split(':', 1)
        if len(reference) != 2:
            raise argparse.ArgumentError(None, 'No secret source scheme. Use env: or file: or fd: prefix.')
        if reference == 'env':
            return self.fetch_secret_from_env(reference[1])
        elif reference == 'file':
            return self.fetch_secret_from_file_path(reference[1])
        elif reference == 'fd':
            return self.fetch_secret_from_fd(reference[1])
        else:
            raise argparse.ArgumentError(None, 'Unsupported secret source scheme ' + reference[0] + ':.')

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
            raise argparse.ArgumentError(None, 'Invalid --after date and time value.')
        result = result - datetime(1970, 1, 1, tzinfo=timezone.utc)
        result = 10**9 * (3600*24*result.days + result.seconds)
        fraction = match.group('fraction')
        if not fraction:
            return result
        return result + int(fraction.ljust(9, '0'))

    @staticmethod
    def fetch_secret_from_env(env_name: str) -> bytearray:
        secret = os.environ.get(env_name)
        if not secret:
            raise argparse.ArgumentError(None, 'No value under ' + env_name + ' environment variable.')
        return bytearray(secret.encode('UTF-8'))

    def fetch_secret_from_file_path(self, file_path: str) -> bytearray:
        if not os.path.isfile(file_path):
            raise argparse.ArgumentError(None, file_path + ' is not a regular file.')
        try:
            with open(file_path, 'rb', buffering=0) as f:
                return self._read_secret_from_file(f)
        except OSError as error:
            raise argparse.ArgumentError(None, 'Error occurred while reading ' + file_path + ': ' + str(error))

    def fetch_secret_from_fd(self, fd_str: str) -> bytearray:
        try:
            fd = int(fd_str)
            if not 0 <= fd < 2**31:
                raise ValueError()
        except ValueError:
            raise argparse.ArgumentError(None, 'Invalid file descriptor number: ' + fd_str + '.')
        try:
            with open(fd, 'rb', buffering=0) as f:
                return self._read_secret_from_file(f)
        except (ValueError, OSError) as error:
            raise argparse.ArgumentError(None, 'Error occurred while reading ' + fd_str + ': ' + str(error))

    @staticmethod
    def _read_secret_from_file(f: io.RawIOBase) -> bytearray:
        buffer = bytearray(1024)
        length = f.readinto(buffer)
        result = bytearray(buffer[:length])
        for i in range(length):
            buffer[i] = 0
        return result

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

    def _add_secret_arguments(self):
        group = self.parser.add_mutually_exclusive_group(required=False)
        group.add_argument('-p', '--password', help='Password location.', metavar='LOCATION')
        group.add_argument('-k', '--hex-key', help='64 hexadecimals key location.', metavar='LOCATION')
        group.add_argument('-K', '--raw-key', help='32 bytes key location.', metavar='LOCATION')
        self.parser.epilog += (
            'Secret LOCATION have to be specified in one from the following forms:\n'
            ' - file:FILE_PATH\n'
            ' - env:ENVIRONMENT_VARIABLE_NAME\n'
            ' - fd:FILE_DESCRIPTION_NUMBER'
        )

    @staticmethod
    def _verify_args(args: argparse.Namespace) -> None:
        if args.operation_mode and not args.password and not args.hex_key and not args.raw_key:
            raise argparse.ArgumentError(
                None, 'Encryption, verification and decryption require a password or a key.'
            )


if __name__ == '__main__':
    parser = ArgumentsParser()
    args = parser.parse(sys.argv[1:])
    if args.help:
        print(parser.format_help())
