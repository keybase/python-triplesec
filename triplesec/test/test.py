import sys
if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest
from binascii import unhexlify as unhex
import json
import os.path
import six
import struct

import triplesec
from triplesec import TripleSec, TripleSecError


path = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))
vectors = json.load(open(os.path.join(path, 'vectors.json')))
for v in vectors:
    for k in v:
        v[k] = v[k].encode('ascii') # JSON insists to decode the loaded objects
        if v[k].startswith(b'0x'): v[k] = unhex(v[k][2:])
    if 'extra' in v: v['extra'] = unhex(v['extra'])
    v['ciphertext'] = unhex(v['ciphertext'])

# A generic vector for various tests
VECTOR = vectors[0]
assert 'disabled' not in VECTOR


class TripleSec_tests(unittest.TestCase):
    def _test_encrypt(self, encrypt, plaintext, key, pass_key=True):
        if pass_key: ciphertext = encrypt(plaintext, key)
        else: ciphertext = encrypt(plaintext)

        self.assertEqual(plaintext, triplesec.decrypt(ciphertext, key))

    def test_missing_key(self):
        T = TripleSec()
        regex = 'You didn\'t initialize TripleSec with a key'
        self.assertRaisesRegexp(TripleSecError, regex, lambda: T.encrypt(b'xxx'))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: T.decrypt(b'xxx'))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.encrypt(b'xxx'))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(b'xxx'))

    def test_initialized_behavior(self):
        T = TripleSec(VECTOR['key'])
        self._test_encrypt(T.encrypt, VECTOR['plaintext'], VECTOR['key'], pass_key=False)
        self.assertEqual(T.decrypt(VECTOR['ciphertext']), VECTOR['plaintext'])

    def test_uninitialized_behavior(self):
        T = TripleSec()
        self._test_encrypt(T.encrypt, VECTOR['plaintext'], VECTOR['key'])
        self.assertEqual(T.decrypt(VECTOR['ciphertext'], VECTOR['key']), VECTOR['plaintext'])

        T = TripleSec(b'foo')
        self._test_encrypt(T.encrypt, VECTOR['plaintext'], VECTOR['key'])
        self.assertEqual(T.decrypt(VECTOR['ciphertext'], VECTOR['key']), VECTOR['plaintext'])

    def test_shortcuts(self):
        self._test_encrypt(triplesec.encrypt, VECTOR['plaintext'], VECTOR['key'])
        self.assertEqual(triplesec.decrypt(VECTOR['ciphertext'], VECTOR['key']), VECTOR['plaintext'])

    def test_data_type(self):
        T = TripleSec(VECTOR['key'])
        regex = r'The input data needs to be a binary string'
        for d in (u'xxx', 12, [12, 13]):
            self.assertRaisesRegexp(TripleSecError, regex, lambda: T.decrypt(d))
            self.assertRaisesRegexp(TripleSecError, regex, lambda: T.encrypt(d))

    def test_key_type(self):
        regex = r'The key needs to be a binary string'
        for k in (u'xxx', 12, [12, 13]):
            self.assertRaisesRegexp(TripleSecError, regex, lambda: TripleSec(k))
            self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(b'foo', k))
            self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.encrypt(b'foo', k))

    def test_decrypt_invalid_data(self):
        regex = r'does not look like a TripleSec ciphertext'
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(b'foo', b'xxx'))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(unhex(b'1c94d7de00000003abcdef'), b'xxx'))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(b'12345678901235'*100, b'xxx'))

    def test_decrypt_invalid_version(self):
        regex = r'Unimplemented version'
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(unhex(b'1c94d7de01200000abcdef'), b'xxx'))

    def test_zero_length(self):
        regex = r'Invalid message length - message cannot be empty'
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.encrypt(b'', b'xxx'))
        regex = r'Invalid key length - key cannot be empty'
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.encrypt(b'foo', b''))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(b'foo', b''))

    def test_extra_bytes(self):
        extra_vectors = tuple(v for v in vectors if 'extra' in v)
        self.assertTrue(len(extra_vectors))
        for VECTOR in extra_vectors:
            T = TripleSec()
            self._test_encrypt(T.encrypt, VECTOR['plaintext'], VECTOR['key'])
            self.assertEqual(None, T.extra_bytes())
            data = VECTOR['ciphertext']
            header_version = struct.unpack(">I", data[4:8])[0]
            version = T.VERSIONS[header_version]
            header, salt, macs, encrypted_material = T._split_ciphertext(data, version)
            mac_keys, cipher_keys, extra = T._key_stretching(VECTOR['key'], salt, version, len(VECTOR['extra']))
            self.assertEqual(VECTOR['extra'], extra)
            T.encrypt(VECTOR['plaintext'], VECTOR['key'], extra_bytes=len(VECTOR['extra']))
            self.assertTrue(T.extra_bytes())
            self._test_encrypt(T.encrypt, VECTOR['plaintext'], VECTOR['key'])
            self.assertEqual(None, T.extra_bytes())

    def test_random_encryption(self):
        for i in range(500 // 20):
            p = triplesec.rndfile.read(i * 20 + 1)
            k = triplesec.rndfile.read((i * 20 - 300) % 500 + 1)
            c = triplesec.encrypt(p, k)
            self.assertEqual(p, triplesec.decrypt(c, k), i)

    def test_external_vectors(self):
        for V in vectors:
            if 'disabled' in V: continue
            self._test_encrypt(triplesec.encrypt, V['plaintext'], V['key'])
            self.assertEqual(triplesec.decrypt(V['ciphertext'], V['key']), V['plaintext'])

    def test_tampered_data(self):
        regex = r'Failed authentication of the data'
        c = VECTOR['ciphertext']
        c = c[:-2] + six.int2byte(six.indexbytes(c, -2) ^ 25) + six.int2byte(six.indexbytes(c, -1))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(c, VECTOR['key']))

    def test_ciphers(self):
        s = triplesec.rndfile.read(100)
        k = triplesec.rndfile.read(32)
        for c in (triplesec.crypto.XSalsa20, triplesec.crypto.AES, triplesec.crypto.Twofish):
            self.assertEqual(s, c.decrypt(c.encrypt(s, k), k), c.__name__)

        ciphertext = b'24-byte nonce for xsalsa' + unhex('002d4513843fc240c401e541')
        self.assertEqual(b'Hello world!', triplesec.crypto.XSalsa20.decrypt(ciphertext,
            b'this is 32-byte key for xsalsa20'))

        ciphertext = b'24-byte nonce for xsalsa' + unhex(
            '4848297feb1fb52fb66d81609bd547fabcbe7026edc8b5e5e449d088bfa69c088f5d8da1d791267c2c195a7f8cae9c4b4050d08ce6d3a151ec265f3a58e47648')
        self.assertEqual(b'\x00' * 64, triplesec.crypto.XSalsa20.decrypt(ciphertext,
            b'this is 32-byte key for xsalsa20'))
