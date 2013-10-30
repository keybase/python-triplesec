#!/usr/bin/env python
#-*- coding:utf-8 -*-

import binascii
import Crypto
import scrypt
import six
import struct


class TripleSecError(Exception):
    """Generic TripleSec-related error"""
    pass

class TripleSecFailedAssertion(TripleSecError):
    """
    Error representing a failed self-test inside TripleSec.
    Should never happen and definitively means a bug.
    """
    pass


class TripleSec():
    LATEST_VERSION = 3
    MAGIC_BYTES = binascii.unhexlify(b'1c94d7de')

    _versions_implementations = {}

    @staticmethod
    def _check_key_type(key):
        if key is not None and not isinstance(key, six.string_types):
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

        implementation = self._versions_implementations[self.LATEST_VERSION]
        result = implementation._encrypt(data, key)

        self._check_output_type(result)
        return result

    def _encrypt(self, data, key):
        """This should be defined in versions implementations subclasses"""
        pass

    def decrypt(self, data, key=None):
        self._check_data_type(data)
        self._check_key_type(key)
        if key is None and self.key is None:
            raise TripleSecError(u"You didn't initialize TripleSec with a key, so you need to specify one")

        if len(data) < 8 or data[:4] != self.MAGIC_BYTES:
            raise TripleSecError(u"This does not look like a TripleSec ciphertext")

        version = struct.unpack("<I", data[4:8])
        if version not in self._versions_implementations:
            raise TripleSecError(u"Unimplemented version")

        implementation = self._versions_implementations[version]
        result = implementation._decrypt(data, key)

        self._check_output_type(result)
        return result

    def _decrypt(self, data, key):
        """This should be defined in versions implementations subclasses"""
        pass


class TripleSec_v3(TripleSec):
    VERSION = 3
    pass


TripleSec._versions_implementations = {3: TripleSec_v3}


# Expose encrypt() and decrypt() shortcuts
_t = TripleSec()
encrypt = _t.encrypt
decrypt = _t.decrypt
