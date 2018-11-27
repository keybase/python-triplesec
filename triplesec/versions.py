"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase

These are the definitions of the different versions specifications
"""

from __future__ import absolute_import

import struct

from .utils import (
    MAGIC_BYTES,
    Cipher,
    MAC,
    KDF,
    Scrypt_params,
    PBKDF2_params,
    Constants
)
from .crypto import (
    Scrypt,
    PBKDF2,
    HMAC_SHA512,
    HMAC_SHA3,
    HMAC_KECCAK,
    XOR_HMAC_SHA3_SHA512,
    XOR_HMAC_KECCAK_SHA512,
    XSalsa20,
    XSalsa20Reversed,
    Twofish,
    AES
)

LATEST_VERSION = 4

_versions = {}
_versions[4] = lambda compatibility: Constants(
    header = [ MAGIC_BYTES, struct.pack(">I", 4) ],
    salt_size = 16,

    KDF = KDF(name = 'scrypt',
              implementation = Scrypt,
              parameters = Scrypt_params(N = 2**15,
                                         r = 8,
                                         p = 1)),

    MACs = [ MAC(name = 'HMAC-SHA-512',
                 implementation = HMAC_SHA512,
                 key_size = 48,
                 output_size = 64),
             MAC(name = 'HMAC-SHA3',
                 implementation = HMAC_SHA3,
                 key_size = 48,
                 output_size = 64) ],

    ciphers = [ Cipher(name = 'XSalsa20',
                       implementation = XSalsa20,
                       overhead_size = XSalsa20.iv_size,
                       key_size = XSalsa20.key_size),
                Cipher(name = 'AES-256-CTR',
                       implementation = AES,
                       overhead_size = AES.block_size,
                       key_size = AES.key_size) ])

_versions[3] = lambda compatibility: Constants(
    header = [ MAGIC_BYTES, struct.pack(">I", 3) ],
    salt_size = 16,

    KDF = KDF(name = 'scrypt',
              implementation = Scrypt,
              parameters = Scrypt_params(N = 2**15,
                                         r = 8,
                                         p = 1)),

    MACs = [ MAC(name = 'HMAC-SHA-512',
                 implementation = HMAC_SHA512,
                 key_size = 48,
                 output_size = 64),
             MAC(name = 'HMAC-SHA3',
                 implementation = (HMAC_KECCAK if compatibility else HMAC_SHA3),
                 key_size = 48,
                 output_size = 64) ],

    ciphers = [ Cipher(name = 'XSalsa20',
                       implementation = XSalsa20,
                       overhead_size = XSalsa20.iv_size,
                       key_size = XSalsa20.key_size),
                Cipher(name = 'Twofish-CTR',
                       implementation = Twofish,
                       overhead_size = Twofish.block_size,
                       key_size = Twofish.key_size),
                Cipher(name = 'AES-256-CTR',
                       implementation = AES,
                       overhead_size = AES.block_size,
                       key_size = AES.key_size) ])


_versions[1] = lambda compatibility: Constants(
    header = [ MAGIC_BYTES, struct.pack(">I", 1) ],
    salt_size = 8,

    KDF = KDF(name = 'pbkdf2',
              implementation = PBKDF2,
              parameters = PBKDF2_params(i = 1024,
                                         PRF = (XOR_HMAC_KECCAK_SHA512 if compatibility else XOR_HMAC_SHA3_SHA512))),

    MACs = [ MAC(name = 'HMAC-SHA-512',
                 implementation = HMAC_SHA512,
                 key_size = 48,
                 output_size = 64),
             MAC(name = 'HMAC-SHA3',
                 implementation = (HMAC_KECCAK if compatibility else HMAC_SHA3),
                 key_size = 48,
                 output_size = 64) ],

    ciphers = [ Cipher(name = 'XSalsa20',
                       implementation = XSalsa20Reversed if compatibility else XSalsa20,
                       overhead_size = XSalsa20.iv_size,
                       key_size = XSalsa20.key_size),
                Cipher(name = 'Twofish-CTR',
                       implementation = Twofish,
                       overhead_size = Twofish.block_size,
                       key_size = Twofish.key_size),
                Cipher(name = 'AES-256-CTR',
                       implementation = AES,
                       overhead_size = AES.block_size,
                       key_size = AES.key_size) ])

def get_version(version_number, compatibility):
    if compatibility and version_number >= 4:
        compatibility = False
    return _versions[version_number](compatibility)

def valid_version(version):
    return version in _versions
