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
import sha3
import twofish
import salsa20
from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES as Crypto_AES
from Crypto.Protocol.KDF import PBKDF2 as Crypto_PBKDF2
from Crypto import Random

from .utils import (
    TripleSecFailedAssertion,
    TripleSecError,
    word_byteswap
)

def validate_key_size(key, key_size, algorithm):
    if len(key) != key_size:
        raise TripleSecFailedAssertion(u"Wrong {algo} key size"
                                       .format(algo=algorithm))

def check_and_increment_counter(ctr):
    # This function is adapted from pycryptodome's source code at
    # https://github.com/Legrandin/pycryptodome/blob/39626a5b01ce5c1cf51d022be166ad0aea722177/lib/Crypto/Cipher/_mode_ctr.py#L366
    counter_len = ctr["counter_len"]
    prefix = ctr["prefix"]
    suffix = ctr["suffix"]
    initial_value = ctr["initial_value"]
    little_endian = ctr["little_endian"]
    words = []
    while initial_value > 0:
        words.append(struct.pack('B', initial_value & 255))
        initial_value >>= 8
    words += [ b'\x00' ] * max(0, counter_len - len(words))
    if not little_endian:
        words.reverse()
    counter_block = prefix + b"".join(words) + suffix
    ctr["initial_value"] += 1
    return counter_block

class BlockCipher(object):

    @classmethod
    def generate_counter(cls, block_size, iv):
        ctr = Counter.new(block_size * 8,
                          initial_value=int(binascii.hexlify(iv), 16))
        return ctr

    @classmethod
    def generate_encrypt_iv_counter(cls, block_size, rndstream):
        iv = rndstream.read(block_size)
        ctr = cls.generate_counter(block_size, iv)

        return iv, ctr

    @classmethod
    def generate_decrypt_counter(cls, data, block_size):
        iv = data[:block_size]
        ctr = cls.generate_counter(block_size, iv)

        return ctr


class AES(object):
    key_size = 32
    block_size = 16

    @classmethod
    def generate_iv_data(cls, rndstream):
        return BlockCipher.generate_encrypt_iv_counter(cls.block_size, rndstream)

    @classmethod
    def encrypt(cls, data, key, iv_data):
        validate_key_size(key, cls.key_size, "AES")

        iv, ctr = iv_data
        ciphertext = Crypto_AES.new(key, Crypto_AES.MODE_CTR,
                                    counter=ctr).encrypt(data)
        return iv + ciphertext

    @classmethod
    def decrypt(cls, data, key):
        validate_key_size(key, cls.key_size, "AES")

        ctr = BlockCipher.generate_decrypt_counter(data, cls.block_size)

        return Crypto_AES.new(key, Crypto_AES.MODE_CTR,
                              counter=ctr).decrypt(data[cls.block_size:])

class Twofish(object):
    key_size = 32
    block_size = 16

    @classmethod
    def generate_iv_data(cls, rndstream):
        return BlockCipher.generate_encrypt_iv_counter(cls.block_size, rndstream)

    @classmethod
    def _gen_keystream(cls, length, tfish, ctr):
        req_blocks = length // cls.block_size + 1
        keystream = b''
        for _ in range(req_blocks):
            keystream += tfish.encrypt(check_and_increment_counter(ctr))
        return keystream[:length]

    @classmethod
    def encrypt(cls, data, key, iv_data):
        validate_key_size(key, cls.key_size, "Twofish")

        iv, ctr = iv_data
        tfish = twofish.Twofish(key)
        ciphertext = strxor(data, cls._gen_keystream(len(data), tfish, ctr))

        return iv + ciphertext

    @classmethod
    def decrypt(cls, data, key):
        validate_key_size(key, cls.key_size, "Twofish")

        ctr = BlockCipher.generate_decrypt_counter(data, cls.block_size)
        tfish = twofish.Twofish(key)

        return strxor(data[cls.block_size:],
                      cls._gen_keystream(len(data[cls.block_size:]), tfish, ctr))

class XSalsa20(object):
    key_size = 32
    iv_size = 24

    @classmethod
    def generate_iv_data(cls, rndstream):
        return rndstream.read(cls.iv_size)

    @classmethod
    def encrypt(cls, data, key, iv_data, reverse_endianness=False):
        validate_key_size(key, cls.key_size, "XSalsa20")
        if reverse_endianness:
            key = word_byteswap(key)

        iv = iv_data
        if reverse_endianness:
            iv = word_byteswap(iv)
        ciphertext = salsa20.XSalsa20_xor(data, iv, key)
        if reverse_endianness:
            iv = word_byteswap(iv)

        return iv + ciphertext

    @classmethod
    def decrypt(cls, data, key, reverse_endianness=False):
        validate_key_size(key, cls.key_size, "XSalsa20")
        if reverse_endianness:
            key = word_byteswap(key)

        iv = data[:cls.iv_size]
        if reverse_endianness:
            iv = word_byteswap(iv)

        return salsa20.XSalsa20_xor(data[cls.iv_size:], iv, key)

class XSalsa20Reversed(XSalsa20):
    @classmethod
    def encrypt(cls, data, key, iv_data):
        return super(XSalsa20Reversed, cls).encrypt(data, key, iv_data, reverse_endianness=True)

    @classmethod
    def decrypt(cls, data, key):
        return super(XSalsa20Reversed, cls).decrypt(data, key, reverse_endianness=True)

def HMAC_SHA512(data, key):
    return hmac.new(key, data, hashlib.sha512).digest()

def HMAC_SHA3(data, key):
    return hmac.new(key, data, hashlib.sha3_512).digest()

def HMAC_KECCAK(data, key):
    return hmac.new(key, data, sha3.keccak_512).digest()

def Scrypt(key, salt, length, parameters):
    try:
        return scrypt.hash(key, salt, parameters.N, parameters.r, parameters.p, length)
    except scrypt.error:
        raise TripleSecError(u"scrypt error")

def XOR_HMAC_SHA3_SHA512(data, key):
    h0 = struct.pack(">I", 0)
    h1 = struct.pack(">I", 1)
    return strxor(HMAC_SHA512(h0 + data, key), HMAC_SHA3(h1 + data, key))

def XOR_HMAC_KECCAK_SHA512(data, key):
    h0 = struct.pack(">I", 0)
    h1 = struct.pack(">I", 1)
    return strxor(HMAC_SHA512(h0 + data, key), HMAC_KECCAK(h1 + data, key))

def PBKDF2(key, salt, length, parameters):
    prf = lambda key, msg: parameters.PRF(msg, key)  # Our convention is different
    return Crypto_PBKDF2(key, salt, length, parameters.i, prf)
