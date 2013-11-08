"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase

These are the definitions of the data structures, the exceptions and other tools
used across the codebase.
"""

import hashlib
import six
import binascii
import sys
from six.moves import zip
from collections import namedtuple
if sys.version_info < (3, 4):
    import sha3


MAGIC_BYTES = binascii.unhexlify(b'1c94d7de')


## DATA STRUCTURES
Cipher = namedtuple('Cipher', ['name', 'implementation', 'overhead_size', 'key_size'])
MAC = namedtuple('MAC', ['name', 'implementation', 'key_size', 'output_size'])
KDF = namedtuple('KDF', ['name', 'implementation', 'parameters'])
Scrypt_params = namedtuple('Scrypt_params', ['N', 'r', 'p'])
PBKDF2_params = namedtuple('PBKDF2', ['i', 'PRF'])
Constants = namedtuple('Constants', ['header', 'salt_size', 'MACs', 'ciphers', 'KDF'])


### EXCEPTIONS
class TripleSecError(Exception):
    """Generic TripleSec-related error"""
    pass

class TripleSecDecryptionError(TripleSecError):
    """Error during encrypted data decryption or authentication"""
    pass

class TripleSecFailedAssertion(TripleSecError):
    """
    Error representing a failed self-test inside TripleSec.
    Should never happen and definitively means a bug.
    """
    pass


### UTILITIES
def _constant_time_compare(a, b):
    if len(a) != len(b): return False
    result = 0
    for x, y in zip(six.iterbytes(a), six.iterbytes(b)):
        result |= x ^ y
    return (result == 0)

class new_sha3_512:
    block_size = 72
    digest_size = 64
    def __init__(self, string=b''):
        self._obj = hashlib.sha3_512()
        self._obj.update(string)
    def digest(self):
        return self._obj.digest()
    def hexdigest(self):
        return self._obj.hexdigest()
    def update(self, string):
        return self._obj.update(string)
    def copy(self):
        copy = new_sha3_512()
        copy._obj = self._obj.copy()
        return copy
sha3_512 = lambda s=b'': new_sha3_512(s)
