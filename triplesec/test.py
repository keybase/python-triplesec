from __future__ import absolute_import

try:
    import unittest2 as unittest
except ImportError:
    import unittest
import binascii
from collections import namedtuple

import triplesec
from triplesec import TripleSec, TripleSecError

Vector = namedtuple('Vector', ['key', 'plaintext', 'ciphertext', 'extra'])

VECTOR = Vector(b'key', # TODO - FAKE VECTORS
           b'plaintext',
           b'\x1c\x94\xd7\xde\x03\x00\x00\x00\x02~1\xb6\xff\x1c\xed\x82\xb4\xbc\xf3&~\xde\x0f\xce\x92n\x19\xe9\x90\x99#o<NU\x1e\xd73\xd8q\x9c\xc8\x13\xe1\n\xa7\xa9\xd2\xeb\xa8{\xd1~;\xb0\xde\xfb\x0b\xd0\x94.\xae\xf6\xd6\x08~n\xdd\xa6\xa7Wgm\xce?bm\xaa\x97\x8fg\x05BA\x15bF\x1d\xdf\xcb\x94Om\x1e\x7f\r&\xf0\xed\xdb\xe4\xa0\x99\xf6d\xbf\xc6\xe9\x9fJ\x83i\xfa\x0c\xa89y\x17K\x17\xba\xd3g\xc31\xb1Ff\x05 \xa9\x9e\x14;\x94<\xf7yX\xca\x9eC\x96f\xa5Tg"Wl\x06\xd7\xcc\xc4\xa7\xc1\xc2\x96J\xd5\x99\xe3\n\xb9\'\xe0\xb4\xc2\xc7\xaa\x80&\x10\x83\xd8\xbb\n\x9dD\xa1\x01.\x858jt\xfa\xf4=W\xfac\x0f6\xab\x89:\xc9\xc7\x93\xbe[\x00\x10\x8e\x88Nc\xd8\xf2P\x84\xdcO\xd9\x0ct',
           b'\xb2\x8ax@%R\xcc\x10\x87&\x0b\x1e\x1b\xc4\x1e\x90\x8aZ\x13\xb1t\x82\xac\xa35\x1fn\xb0\x01\r.\xa1\xbe(\xfe\xd8\x88\xf3\x13s\xe2\x08)^\xe9Bs\xab\xc7j')


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
        T = TripleSec(VECTOR.key)
        self._test_encrypt(T.encrypt, VECTOR.plaintext, VECTOR.key, pass_key=False)
        self.assertEqual(T.decrypt(VECTOR.ciphertext), VECTOR.plaintext)

    def test_uninitialized_behavior(self):
        T = TripleSec()
        self._test_encrypt(T.encrypt, VECTOR.plaintext, VECTOR.key)
        self.assertEqual(T.decrypt(VECTOR.ciphertext, VECTOR.key), VECTOR.plaintext)

        T = TripleSec(b'foo')
        self._test_encrypt(T.encrypt, VECTOR.plaintext, VECTOR.key)
        self.assertEqual(T.decrypt(VECTOR.ciphertext, VECTOR.key), VECTOR.plaintext)

    def test_shortcuts(self):
        self._test_encrypt(triplesec.encrypt, VECTOR.plaintext, VECTOR.key)
        self.assertEqual(triplesec.decrypt(VECTOR.ciphertext, VECTOR.key), VECTOR.plaintext)

    def test_data_type(self):
        T = TripleSec(VECTOR.key)
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
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(binascii.unhexlify(b'1c94d7de03000000abcdef'), b'xxx'))
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(b'12345678901235'*100, b'xxx'))

    def test_decrypt_invalid_version(self):
        regex = r'Unimplemented version'
        self.assertRaisesRegexp(TripleSecError, regex, lambda: triplesec.decrypt(binascii.unhexlify(b'1c94d7de01000000abcdef'), b'xxx'))

    def test_extra_bytes(self):
        pass

    def test_random_encryption(self):
        pass

    def test_external_vectors(self):
        pass

    def test_empty_plaintext(self):
        pass

    def test_tampered_data(self):
        pass

    def test_randomness(self):
        pass

    def test_randomness_of_ciphertext(self):
        pass

    def test_ciphers(self):
        s = triplesec.rndfile.read(100)
        k = triplesec.rndfile.read(32)
        for c in (triplesec.XSalsa20, triplesec.AES, triplesec.Twofish):
            self.assertEqual(s, c.decrypt(c.encrypt(s, k), k), c.__name__)
