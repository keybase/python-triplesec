#!/usr/bin/env python

"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
"""

from __future__ import absolute_import

import binascii
import getpass
import struct
import six
import sys

from Crypto import Random
rndfile = Random.new()

from .utils import (
    MAGIC_BYTES,
    TripleSecFailedAssertion,
    TripleSecDecryptionError,
    TripleSecError,
    _constant_time_compare,
    win32_utf8_argv
)
from .versions import VERSIONS


### MAIN CLASS
class TripleSec():
    LATEST_VERSION = 3
    MAGIC_BYTES = MAGIC_BYTES

    VERSIONS = VERSIONS

    @staticmethod
    def _check_key(key):
        if key is None: return
        if not isinstance(key, six.binary_type):
            raise TripleSecError(u"The key needs to be a binary string (str() in Python 2 and bytes() in Python 3)")
        if len(key) == 0:
            raise TripleSecError(u"Invalid key length - key cannot be empty")

    @staticmethod
    def _check_data(data):
        if not isinstance(data, six.binary_type):
            raise TripleSecError(u"The input data needs to be a binary string (str() in Python 2 and bytes() in Python 3)")
        if len(data) == 0:
            raise TripleSecError(u"Invalid message length - message cannot be empty")

    @staticmethod
    def _check_output_type(data):
        if not isinstance(data, six.binary_type):
            raise TripleSecFailedAssertion(u"The return value was not binary")

    def __init__(self, key=None):
        self._check_key(key)
        self.key = key
        self._extra_bytes = None

    @staticmethod
    def _key_stretching(key, salt, version, extra_bytes=0):
        total_keys_size = sum(x.key_size for x in version.MACs + version.ciphers) + extra_bytes
        key_material = version.KDF.implementation(key, salt, total_keys_size, version.KDF.parameters)

        i = 0
        mac_keys = []
        for m in version.MACs:
            mac_keys.append(key_material[i:i + m.key_size])
            i += m.key_size
        cipher_keys = []
        for c in version.ciphers:
            cipher_keys.append(key_material[i:i + c.key_size])
            i += c.key_size
        cipher_keys.reverse()  # The first key is that of the outermost cipher
                               # This is the opposite of how we order them in Constants
        extra = key_material[i:]

        return mac_keys, cipher_keys, extra

    @staticmethod
    def _calc_overhead(version):
        tot = 0
        tot += sum(map(len, version.header))
        tot += version.salt_size
        tot += sum(m.output_size for m in version.MACs)
        tot += sum(c.overhead_size for c in version.ciphers)
        return tot

    def encrypt(self, data, key=None, v=None, extra_bytes=0):
        self._check_data(data)
        self._check_key(key)
        if key is None and self.key is None:
            raise TripleSecError(u"You didn't initialize TripleSec with a key, so you need to specify one")
        if key is None: key = self.key

        if not v: v = self.LATEST_VERSION
        version = self.VERSIONS[v]
        result, extra = self._encrypt(data, key, version, extra_bytes)

        self._check_output_type(result)
        self._check_output_type(extra)
        self._extra_bytes = extra or None
        return result

    def _encrypt(self, data, key, version, extra_bytes):
        salt = rndfile.read(version.salt_size)
        mac_keys, cipher_keys, extra = self._key_stretching(key, salt, version, extra_bytes)

        encrypted_material = self._encrypt_data(data, cipher_keys, version)

        header = b''.join(version.header)

        authenticated_data = header + salt + encrypted_material
        macs = self._generate_macs(authenticated_data, mac_keys, version)

        result = header + salt + b''.join(macs) + encrypted_material

        if len(result) != self._calc_overhead(version) + len(data):
            raise TripleSecFailedAssertion(u"Wrong encrypt output length")
        return result, extra

    @staticmethod
    def _generate_macs(authenticated_data, mac_keys, version):
        result = []
        for n, m in enumerate(version.MACs):
            mac = m.implementation(authenticated_data, mac_keys[n])
            result.append(mac)
        return result

    @staticmethod
    def _encrypt_data(data, cipher_keys, version):
        for n, c in enumerate(version.ciphers):
            # the keys order is from the outermost to the innermost
            key = cipher_keys[n]
            data = c.implementation.encrypt(data, key)
        return data

    def decrypt(self, data, key=None):
        self._check_data(data)
        self._check_key(key)
        if key is None and self.key is None:
            raise TripleSecError(u"You didn't initialize TripleSec with a key, so you need to specify one")
        if key is None: key = self.key

        if len(data) < 8 or data[:4] != self.MAGIC_BYTES:
            raise TripleSecError(u"This does not look like a TripleSec ciphertext")

        header_version = struct.unpack(">I", data[4:8])[0]
        if header_version not in self.VERSIONS:
            raise TripleSecError(u"Unimplemented version: " + str(header_version))

        version = self.VERSIONS[header_version]
        result = self._decrypt(data, key, version)

        self._check_output_type(result)
        return result

    def _decrypt(self, data, key, version):
        if len(data) < self._calc_overhead(version):
            raise TripleSecError(u"Input does not look like a TripleSec ciphertext")

        header, salt, macs, encrypted_material = \
            self._split_ciphertext(data, version)

        mac_keys, cipher_keys, _ = self._key_stretching(key, salt, version)

        authenticated_data = header + salt + encrypted_material
        if not self._check_macs(authenticated_data, macs, mac_keys, version):
            raise TripleSecDecryptionError(u"Failed authentication of the data")

        result = self._decrypt_data(encrypted_material, cipher_keys, version)

        if len(result) != len(data) - self._calc_overhead(version):
            raise TripleSecFailedAssertion(u"Wrong decrypt output length")
        return result

    def _split_ciphertext(self, data, version):
        i = 0

        header_size = sum(map(len, version.header))
        header = data[i:i + header_size]
        i += header_size

        salt = data[i:i + version.salt_size]
        i += version.salt_size

        macs = []
        for m in version.MACs:
            macs.append(data[i:i + m.output_size])
            i += m.output_size

        encrypted_material = data[i:]

        return header, salt, macs, encrypted_material

    def _check_macs(self, authenticated_data, macs, mac_keys, version):
        expected_macs = self._generate_macs(authenticated_data, mac_keys, version)

        result = True

        for expected, actual in zip(expected_macs, macs):
            result = _constant_time_compare(expected, actual) and result

        return result

    def _decrypt_data(self, encrypted_material, cipher_keys, version):
        data = encrypted_material
        for n, c in enumerate(reversed(version.ciphers)):
            # the keys order is from the outermost to the innermost
            key = tuple(reversed(cipher_keys))[n]
            data = c.implementation.decrypt(data, key)
        return data

    def extra_bytes(self):
        return self._extra_bytes


# Expose encrypt() and decrypt() shortcuts
_t = TripleSec()
encrypt = _t.encrypt
decrypt = _t.decrypt
extra_bytes = _t.extra_bytes

def main():
    argv = win32_utf8_argv() or sys.argv
    if argv and not isinstance(argv[0], six.text_type):
        argv = [arg.decode(sys.stdin.encoding) for arg in argv]

    if len(argv) < 3 or argv[1] not in ('enc', 'dec'):
        print('Command-line TripleSec encryption-decryption tool')
        print('')
        print('Usage: %s {enc|dec} [key] {message|ciphertext}' % argv[0])
        print('')
        print('Both the key and the message can be specified as text or as hex if prepended with 0x')
        print('The key, if omitted, will be requested')
        sys.exit(1)

    if len(argv) == 3:
        key = getpass.getpass('Key (will not be printed): ').decode(sys.stdin.encoding)
        data = argv[2]
    else:
        key = argv[2]
        data = argv[3]

    key = key.encode('utf-8')
    data = data.encode('utf-8')

    if key.startswith(b'0x'):
        key = binascii.unhexlify(key[2:])
    if data.startswith(b'0x') and argv[1] == 'enc':
        data = binascii.unhexlify(data[2:])

    try:
        if argv[1] == 'enc':
            print(binascii.hexlify(encrypt(data, key)).decode())
        if argv[1] == 'dec':
            print(decrypt(binascii.unhexlify(data), key).decode(sys.stdout.encoding))
    except TripleSecError as e:
        sys.stderr.write('ERROR: ')
        sys.stderr.write(e.args[0])
        sys.stderr.write('\n')
        sys.exit(1)

