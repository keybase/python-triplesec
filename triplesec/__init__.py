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

    def encrypt_ascii(self, data, key=None, v=None, extra_bytes=0,
                      digest="hex"):
        """
        Encrypt data and return as ascii string. Hexadecimal digest as default.

        Avaiable digests:
            hex: Hexadecimal
            base64: Base 64
            hqx: hexbin4
        """
        digests = {"hex": binascii.b2a_hex,
                   "base64": binascii.b2a_base64,
                   "hqx": binascii.b2a_hqx}
        digestor = digests.get(digest)
        if not digestor:
            TripleSecError(u"Digestor not supported.")

        binary_result = self.encrypt(data, key, v, extra_bytes)
        result = digestor(binary_result)
        return result

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

    def decrypt_ascii(self, ascii_string, key=None, digest="hex"):
        """
        Receive ascii string and return decrypted data.

        Avaiable digests:
            hex: Hexadecimal
            base64: Base 64
            hqx: hexbin4
        """
        digests = {"hex": binascii.a2b_hex,
                   "base64": binascii.a2b_base64,
                   "hqx": binascii.a2b_hqx}
        digestor = digests.get(digest)
        if not digestor:
            TripleSecError(u"Digestor not supported.")

        binary_string = digestor(ascii_string)
        result = self.decrypt(binary_string, key)
        return result

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
encrypt_ascii = _t.encrypt_ascii
decrypt_ascii = _t.decrypt_ascii
extra_bytes = _t.extra_bytes


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser('triplesec')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--binary', action='store_true',
        help="consider all input (key, plaintext, ciphertext) to be plain binary data "
        "and output everything as binary data - this turns off smart decoding/encoding "
        "- if you pipe data, you should use this")
    group.add_argument('--hex', action='store_true',
        help="consider all input (key, plaintext, ciphertext) to be hex encoded; "
        "hex encode all output")

    parser.add_argument('-k', '--key', help="the TripleSec key; "
        "if not specified will check the TRIPLESEC_KEY env variable, "
        "then prompt the user for it")

    parser.add_argument('_command', choices=['enc', 'dec'], metavar='{enc|dec}',
        help='enc: encrypt and sign a message with TripleSec; '
             "by default output a hex encoded ciphertext (see -b and --hex) -- "
             'dec: decrypt and verify a TripleSec ciphertext')


    parser.add_argument('data', help='the TripleSec message or ciphertext; '
        'if not specified it will be read from stdin; '
        'by default ciphertexts will be considered hex encoded '
        '(see -b and --hex)', nargs='?')

    args = parser.parse_args()

    stdin_encoding = sys.stdin.encoding or 'utf-8'

    if args.binary or args.hex:
        # Patch various stuff to be binary cross-Python-versions
        if six.PY3:
            if args.key: args.key = os.fsencode(args.key)
            if args.data: args.data = os.fsencode(args.data)
        stdin = getattr(sys.stdin, 'buffer', sys.stdin)
        getenvb = getattr(os, 'getenvb', os.getenv)

        key = args.key or getenvb(b'TRIPLESEC_KEY') or getpass.getpass('Key (will not be printed): ')
        if isinstance(key, six.text_type): key = key.encode(stdin_encoding, 'surrogateescape')

        if args.hex: key = binascii.unhexlify(key.strip())

        data = args.data or stdin.read()
        assert isinstance(data, six.binary_type)

        if args.hex and not args._command == 'dec': data = binascii.unhexlify(data.strip())

    else:
        # Try to get Unicode objects and encode them in utf-8
        argv = win32_utf8_argv() or sys.argv
        if argv and not isinstance(argv[0], six.text_type):
            argv = [arg.decode(stdin_encoding) for arg in argv]

        args = parser.parse_args(argv[1:])

        if args.key:
            key = args.key
        elif os.getenv('TRIPLESEC_KEY'):
            key = os.getenv('TRIPLESEC_KEY')
            if not isinstance(key, six.text_type):
                key = key.decode(sys.getfilesystemencoding(), 'replace')
        else:
            key = getpass.getpass('Key (will not be printed): ')
            if not isinstance(key, six.text_type):
                key = key.decode(stdin_encoding, 'replace')

        assert isinstance(key, six.text_type)
        key = key.encode('utf-8')

        if args.data:
            data = args.data
        else:
            data = sys.stdin.read()
            if not isinstance(data, six.text_type):
                data = data.decode(stdin_encoding, 'replace')

        assert isinstance(data, six.text_type)
        data = data.encode('utf-8')

    try:
        if args._command == 'dec':
            ciphertext = data if args.binary else binascii.unhexlify(data.strip())
            plaintext = decrypt(ciphertext, key)
            if args.binary:
                getattr(sys.stdout, 'buffer', sys.stdout).write(plaintext)
            elif args.hex:
                print(binascii.hexlify(plaintext).decode())
            else:
                print(plaintext.decode('utf-8', 'replace'))

        elif args._command == 'enc':
            plaintext = data
            ciphertext = encrypt(plaintext, key)
            stdout = getattr(sys.stdout, 'buffer', sys.stdout)
            stdout.write(ciphertext if args.binary else binascii.hexlify(ciphertext) + b'\n')

    except TripleSecError as e:
        sys.stderr.write(u'ERROR: ')
        sys.stderr.write(e.args[0])
        sys.stderr.write(u'\n')
        sys.exit(1)
