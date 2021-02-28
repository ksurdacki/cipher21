from .typing import Bytes


class StreamAttributes:

    def __init__(self, key: Bytes):
        self.key = key
        self.cipher = None
        self.nonce = None
        self.stream_timestamp_ns = None
        self.payload_length = None
        self.padding_length = None
        self.mac = None

    def reset(self):
        self.cipher = None
        self.nonce = None
        self.stream_timestamp_ns = None
        self.payload_length = None
        self.padding_length = None
        self.mac = None
