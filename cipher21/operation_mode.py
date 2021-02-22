from enum import Enum


class OperationMode(Enum):
    ENCRYPTION = 'encryption'
    VERIFICATION = 'verification'
    DECRYPTION = 'decryption'
