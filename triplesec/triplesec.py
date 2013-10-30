#!/usr/bin/env python
#-*- coding:utf-8 -*-

import binascii
import Crypto
import scrypt
import struct
import six
from six.moves import zip

from Crypto import Random
rndfile = Random.new()


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
    for x, y in zip(a, b):
        result |= six.byte2int(x) ^ six.byte2int(y)
    return (result == 0)


### MAIN CLASS
class TripleSec():
    LATEST_VERSION = 3
    MAGIC_BYTES = binascii.unhexlify(b'1c94d7de')

    _versions_implementations = {}

    @staticmethod
    def _check_key_type(key):
        if key is not None and not isinstance(key, six.binary_types):
            raise TripleSecError(u"The key needs needs to be a binary string (str() in Python 2 and bytes() in Python 3)")

    @staticmethod
    def _check_data_type(data):
        if not isinstance(data, six.binary_type):
            raise TripleSecError(u"The input data needs to be a binary string (str() in Python 2 and bytes() in Python 3)")

    @staticmethod
    def _check_output_type(data):
        if not isinstance(data, six.binary_type):
            raise TripleSecFailedAssertion(u"The return value was not binary")

    def __init__(self, key=None):
        self._check_key_type(key)
        self.key = key

    def encrypt(self, data, key=None):
        self._check_data_type(data)
        self._check_key_type(key)
        if key is None and self.key is None:
            raise TripleSecError(u"You didn't initialize TripleSec with a key, so you need to specify one")

        implementation = self._versions_implementations[self.LATEST_VERSION]()
        result = implementation._encrypt(data, key)

        self._check_output_type(result)
        return result

    def _encrypt(self, data, key):
        """This should be defined in versions implementation subclasses"""
        pass

    def decrypt(self, data, key=None):
        self._check_data_type(data)
        self._check_key_type(key)
        if key is None and self.key is None:
            raise TripleSecError(u"You didn't initialize TripleSec with a key, so you need to specify one")

        if len(data) < 8 or data[:4] != self.MAGIC_BYTES:
            raise TripleSecError(u"This does not look like a TripleSec ciphertext")

        version = struct.unpack("<I", data[4:8])[0]
        if version not in self._versions_implementations:
            raise TripleSecError(u"Unimplemented version")

        implementation = self._versions_implementations[version]()
        result = implementation._decrypt(data, key)

        self._check_output_type(result)
        return result

    def _decrypt(self, data, key):
        """This should be defined in versions implementation subclasses"""
        pass


### VERSIONS IMPLEMENTATIONS
class TripleSec_v3():
    VERSION = 3

    @staticmethod
    def _key_stretching(key, salt):
        try:
            return scrypt.hash(key, salt, N=1 << 13, r=8, p=1)
        except scrypt.error:
            raise TripleSecError(u"scrypt error")

    def _salsa20_encrypt(data, key):
        pass
    def _salsa20_decrypt(data, key):
        pass

    def _twofish_encrypt(data, key):
        pass
    def _twofish_decrypt(data, key):
        pass

    def _aes_encrypt(data, key):
        pass
    def _aes_decrypt(data, key):
        pass

    def _hmac_sha256(data, key):
        pass

    def _hmac_sha3(data, key):
        pass

    def _encrypt(self, data, key):
        salt = rndfile.read(16)
        stretched_key = self._key_stretching(key, salt)

        first_step = self._salsa20_encrypt(data, stretched_key[0])
        second_step = self._twofish_encrypt(first_step, stretched_key[1])
        encrypted_material = self._aes_encrypt(second_step, stretched_key[2])

        header = TripleSec.MAGIC_BYTES + struct.pack("<I", self.VERSION)

        hmac_sha2 = self._hmac_sha256(header + salt + encrypted_material, stretched_key[3])
        hmac_sha3 = self._hmac_sha3(header + salt + encrypted_material, stretched_key[4])

        result = header + salt + hmac_sha2 + hmac_sha3 + encrypted_material

        if len(result) != 208 + len(data):
            raise TripleSecFailedAssertion(u"Wrong encrypt output length")
        return result

    def _decrypt(self, data, key):
        if len(data) < 208:
            raise TripleSecDecryptionError(u"Input does not look like a TripleSec ciphertext")

        header, salt, hmac_sha2, hmac_sha3, encrypted_material = \
            data[:8], data[8:24], data[24:88], data[88:152], data[152:]

        stretched_key = self._key_stretching(key, salt)

        generated_hmac_sha2 = self._hmac_sha256(header + salt + encrypted_material, stretched_key[3])
        generated_hmac_sha3 = self._hmac_sha3(header + salt + encrypted_material, stretched_key[4])

        if not _constant_time_compare(generated_hmac_sha2, hmac_sha2) or \
           not _constant_time_compare(generated_hmac_sha3, hmac_sha3):
            raise TripleSecDecryptionError(u"Failed authentication of the data")

        second_step = self._aes_decrypt(encrypted_material, stretched_key[2])
        first_step = self._twofish_decrypt(second_step, stretched_key[1])
        result = self._salsa20_decrypt(first_step, stretched_key[0])

        if len(result) != len(data) - 208:
            raise TripleSecFailedAssertion(u"Wrong decrypt output length")
        return result


TripleSec._versions_implementations[TripleSec_v3.VERSION] = TripleSec_v3


# Expose encrypt() and decrypt() shortcuts
_t = TripleSec()
encrypt = _t.encrypt
decrypt = _t.decrypt
