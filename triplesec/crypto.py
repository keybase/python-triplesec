"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase

These are the definitions of the ciphers and the MACs.
"""

import binascii
import scrypt
import struct
import hmac
import hashlib
import twofish
import salsa20
from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES as Crypto_AES
from Crypto.Protocol.KDF import PBKDF2 as Crypto_PBKDF2
from Crypto import Random
rndfile = Random.new()

from .utils import (
    TripleSecFailedAssertion,
    TripleSecError,
    sha3_512
)

class AES:
    key_size = 32
    block_size = 16

    @classmethod
    def encrypt(cls, data, key):
        if len(key) != cls.key_size:
            raise TripleSecFailedAssertion(u"Wrong AES key size")

        iv = rndfile.read(cls.block_size)
        ctr = Counter.new(cls.block_size*8, initial_value=int(binascii.hexlify(iv), 16))

        ciphertext = Crypto_AES.new(key, Crypto_AES.MODE_CTR,
            counter=ctr).encrypt(data)
        return iv + ciphertext

    @classmethod
    def decrypt(cls, data, key):
        if len(key) != cls.key_size:
            raise TripleSecFailedAssertion(u"Wrong AES key size")

        iv = data[:cls.block_size]
        ctr = Counter.new(cls.block_size*8, initial_value=int(binascii.hexlify(iv), 16))

        return Crypto_AES.new(key, Crypto_AES.MODE_CTR,
            counter=ctr).decrypt(data[cls.block_size:])

class Twofish:
    key_size = 32
    block_size = 16

    @classmethod
    def _gen_keystream(cls, length, T, ctr):
        req_blocks = length // cls.block_size + 1
        keystream = b''
        for _ in range(req_blocks):
            keystream += T.encrypt(ctr())
        return keystream[:length]

    @classmethod
    def encrypt(cls, data, key):
        if len(key) != cls.key_size:
            raise TripleSecFailedAssertion(u"Wrong Twofish key size")

        iv = rndfile.read(cls.block_size)
        ctr = Counter.new(cls.block_size*8, initial_value=int(binascii.hexlify(iv), 16))

        T = twofish.Twofish(key)
        ciphertext = strxor(data, cls._gen_keystream(len(data), T, ctr))
        return iv + ciphertext

    @classmethod
    def decrypt(cls, data, key):
        if len(key) != cls.key_size:
            raise TripleSecFailedAssertion(u"Wrong Twofish key size")

        iv = data[:cls.block_size]
        ctr = Counter.new(cls.block_size*8, initial_value=int(binascii.hexlify(iv), 16))

        T = twofish.Twofish(key)
        return strxor(data[cls.block_size:], cls._gen_keystream(len(data[cls.block_size:]), T, ctr))

class XSalsa20:
    key_size = 32
    iv_size = 24

    @classmethod
    def encrypt(cls, data, key):
        if len(key) != cls.key_size:
            raise TripleSecFailedAssertion(u"Wrong XSalsa20 key size")

        iv = rndfile.read(cls.iv_size)

        ciphertext = salsa20.XSalsa20_xor(data, iv, key)
        return iv + ciphertext

    @classmethod
    def decrypt(cls, data, key):
        if len(key) != cls.key_size:
            raise TripleSecFailedAssertion(u"Wrong XSalsa20 key size")

        iv = data[:cls.iv_size]

        return salsa20.XSalsa20_xor(data[cls.iv_size:], iv, key)

def HMAC_SHA512(data, key):
    return hmac.new(key, data, hashlib.sha512).digest()

def HMAC_SHA3(data, key):
    return hmac.new(key, data, sha3_512).digest()

def Scrypt(key, salt, length, parameters):
    try:
        return scrypt.hash(key, salt, parameters.N, parameters.r, parameters.p, length)
    except scrypt.error:
        raise TripleSecError(u"scrypt error")

def XOR_HMAC_SHA3_SHA512(data, key):
    h0 = struct.pack(">I", 0)
    h1 = struct.pack(">I", 1)
    return strxor(HMAC_SHA512(h0 + data, key), HMAC_SHA3(h1 + data, key))

def PBKDF2(key, salt, length, parameters):
    prf = lambda key, msg: parameters.PRF(msg, key)  # Our convention is different
    return Crypto_PBKDF2(key, salt, length, parameters.i, prf)
