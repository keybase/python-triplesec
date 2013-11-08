#!/usr/bin/env python
#-*- coding:utf-8 -*-

import binascii
import scrypt
import struct
import hmac
import hashlib
import six
import sys
import twofish
import salsa20
from six.moves import zip
from collections import namedtuple
from Crypto.Util import Counter
from Crypto.Util.strxor import strxor
from Crypto.Cipher import AES as Crypto_AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
rndfile = Random.new()
if sys.version_info < (3, 4):
    import sha3


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
    # All this just to add blocksize
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


# Needed for calling PBKDF2-HMAC-SHA256-SHA3

def pbkdf2_hmac_sha512_sha3 (password, salt, dkLen, count):
    print("key: "+ binascii.hexlify(password))
    def prf (key, data):
        print("key: " + binascii.hexlify(key))
        print("data: " + binascii.hexlify(data))
        h2 = hmac.new(key,struct.pack(">I",0)+data,hashlib.sha512).digest()
        h3 = hmac.new(key,struct.pack(">I",1)+data,sha3_512).digest()
        ret = strxor(h2, h3)
        print("h2: " + binascii.hexlify(h2))
        print("h3: " + binascii.hexlify(h3))
        print("ret:" + binascii.hexlify(ret))
        return ret
    return PBKDF2(password, salt, dkLen, count, prf)

### DATA STRUCTURES
Cipher = namedtuple('Cipher', ['name', 'implementation', 'overhead_size', 'key_size'])
MAC = namedtuple('MAC', ['name', 'implementation', 'key_size', 'output_size'])
KDF = namedtuple('KDF', ['name', 'implementation', 'parameters'])
Scrypt_params = namedtuple('Scrypt_params', ['N', 'r', 'p'])
Constants = namedtuple('Constants', ['header', 'salt_size', 'MACs', 'ciphers', 'KDF'])


### CIPHERS AND HMAC IMPLEMENTATIONS
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


### MAIN CLASS
class TripleSec():
    LATEST_VERSION = 3
    MAGIC_BYTES = binascii.unhexlify(b'1c94d7de')

    VERSIONS = {}

    @staticmethod
    def _check_key_type(key):
        if key is not None and not isinstance(key, six.binary_type):
            raise TripleSecError(u"The key needs to be a binary string (str() in Python 2 and bytes() in Python 3)")

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
        self._extra_bytes = None

    def _key_stretching(self, key, salt, version, extra_bytes=0):
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

    def _calc_overhead(self, version):
        tot = 0
        tot += sum(map(len, version.header))
        tot += version.salt_size
        tot += sum(m.output_size for m in version.MACs)
        tot += sum(c.overhead_size for c in version.ciphers)
        return tot

    def encrypt(self, data, key=None, v=None, extra_bytes=0):
        self._check_data_type(data)
        self._check_key_type(key)
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

    def _generate_macs(self, authenticated_data, mac_keys, version):
        result = []
        for n, m in enumerate(version.MACs):
            mac = m.implementation(authenticated_data, mac_keys[n])
            result.append(mac)
        return result

    def _encrypt_data(self, data, cipher_keys, version):
        for n, c in enumerate(version.ciphers):
            # the keys order is from the outermost to the innermost
            key = cipher_keys[n]
            data = c.implementation.encrypt(data, key)
        return data

    def decrypt(self, data, key=None):
        self._check_data_type(data)
        self._check_key_type(key)
        if key is None and self.key is None:
            raise TripleSecError(u"You didn't initialize TripleSec with a key, so you need to specify one")
        if key is None: key = self.key

        if len(data) < 8 or data[:4] != self.MAGIC_BYTES:
            raise TripleSecError(u"This does not look like a TripleSec ciphertext")

        header_version = struct.unpack("<I", data[4:8])[0]
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


### VERSIONS DEFINITIONS
TripleSec.VERSIONS[3] = Constants(
    header = [ TripleSec.MAGIC_BYTES, struct.pack("<I", 3) ],
    salt_size = 16,

    KDF = KDF(name = 'scrypt',
              implementation = Scrypt,
              parameters = Scrypt_params(N = 2**13,
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
                Cipher(name = 'Twofish-CTR',
                       implementation = Twofish,
                       overhead_size = Twofish.block_size,
                       key_size = Twofish.key_size),
                Cipher(name = 'AES-256-CTR',
                       implementation = AES,
                       overhead_size = AES.block_size,
                       key_size = AES.key_size) ])


# Expose encrypt() and decrypt() shortcuts
_t = TripleSec()
encrypt = _t.encrypt
decrypt = _t.decrypt
extra_bytes = _t.extra_bytes
