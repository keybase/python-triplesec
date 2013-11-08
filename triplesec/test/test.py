try:
    import unittest2 as unittest
except ImportError:
    import unittest
from binascii import unhexlify as unhex
from collections import namedtuple

import triplesec
from triplesec import TripleSec, TripleSecError

Vector = namedtuple('Vector', ['key', 'plaintext', 'ciphertext', 'extra'])

VECTOR = Vector(b'key', # TODO - FAKE VECTORS
           b'plaintext',
           b'\x1c\x94\xd7\xde\x03\x00\x00\x00\x02~1\xb6\xff\x1c\xed\x82\xb4\xbc\xf3&~\xde\x0f\xce\x92n\x19\xe9\x90\x99#o<NU\x1e\xd73\xd8q\x9c\xc8\x13\xe1\n\xa7\xa9\xd2\xeb\xa8{\xd1~;\xb0\xde\xfb\x0b\xd0\x94.\xae\xf6\xd6\x08~n\xdd\xa6\xa7Wgm\xce?bm\xaa\x97\x8fg\x05BA\x15bF\x1d\xdf\xcb\x94Om\x1e\x7f\r&\xf0\xed\xdb\xe4\xa0\x99\xf6d\xbf\xc6\xe9\x9fJ\x83i\xfa\x0c\xa89y\x17K\x17\xba\xd3g\xc31\xb1Ff\x05 \xa9\x9e\x14;\x94<\xf7yX\xca\x9eC\x96f\xa5Tg"Wl\x06\xd7\xcc\xc4\xa7\xc1\xc2\x96J\xd5\x99\xe3\n\xb9\'\xe0\xb4\xc2\xc7\xaa\x80&\x10\x83\xd8\xbb\n\x9dD\xa1\x01.\x858jt\xfa\xf4=W\xfac\x0f6\xab\x89:\xc9\xc7\x93\xbe[\x00\x10\x8e\x88Nc\xd8\xf2P\x84\xdcO\xd9\x0ct',
           b'\xb2\x8ax@%R\xcc\x10\x87&\x0b\x1e\x1b\xc4\x1e\x90\x8aZ\x13\xb1t\x82\xac\xa35\x1fn\xb0\x01\r.\xa1\xbe(\xfe\xd8\x88\xf3\x13s\xe2\x08)^\xe9Bs\xab\xc7j')

VECTOR_1 = Vector(b'ANNA', b'=)',
            unhex(b'1c94d7de000000016ea9b9afa82bb3c8f08ea7bb1b86e57224480ce0f1fc4412316811f75fdaaedbc9442a24222b3f770ac79fa9bd08c93aaa8118333fe4e176ee72262c85b415818626128f31e590e6b50c300dd949a44d6427c2630efeed93352003e4cee9ade95b62725403b9350b1bed594ed59e55d9d63396e24a21be42b52996f73e1bbcdbd1042914166c4866483f715496ce586a3e7788b9bf0fd4cbf89db4b3b249573e360e3571b0957c07c1474137963465197a3e486ea4be069708431e0e1b38e92eac31'), b'')


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
        T = TripleSec(VECTOR_1.key)
        self._test_encrypt(T.encrypt, VECTOR_1.plaintext, VECTOR_1.key, pass_key=False)
        self.assertEqual(T.decrypt(VECTOR_1.ciphertext), VECTOR_1.plaintext)

    def test_uninitialized_behavior(self):
        T = TripleSec()
        self._test_encrypt(T.encrypt, VECTOR_1.plaintext, VECTOR_1.key)
        self.assertEqual(T.decrypt(VECTOR_1.ciphertext, VECTOR_1.key), VECTOR_1.plaintext)

        T = TripleSec(b'foo')
        self._test_encrypt(T.encrypt, VECTOR_1.plaintext, VECTOR_1.key)
        self.assertEqual(T.decrypt(VECTOR_1.ciphertext, VECTOR_1.key), VECTOR_1.plaintext)

    def test_shortcuts(self):
        self._test_encrypt(triplesec.encrypt, VECTOR_1.plaintext, VECTOR_1.key)
        self.assertEqual(triplesec.decrypt(VECTOR_1.ciphertext, VECTOR_1.key), VECTOR_1.plaintext)

    def test_data_type(self):
        T = TripleSec(VECTOR_1.key)
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

    def test_keys_generation(self):
        version = TripleSec.VERSIONS[1]
        key = b'ANNA'
        salt = unhex(b'4789c5f5902226eb')
        mac_keys, cipher_keys, extra = TripleSec._key_stretching(key, salt, version)
        self.assertEqual(cipher_keys[0], unhex(b'2d1bb2ab4593da2fea6c8d022438d2f26610714363f7ceb210b9c1a7331efd6c'))
        self.assertEqual(cipher_keys[0], unhex(b'd5ad42540d876027ba414d968466030ad25c136040c2abe8d1fcbcfdf93b71e2'))
        self.assertEqual(cipher_keys[0], unhex(b'3c03e6f366f29f3cce0b526081c3d541fa8fcb8aa000e7ec336ac72e49db8e74'))

    def test_signatures_v1(self):
        inp = unhex('1c94d7de000000019f1d6915ca8035e207292f3f4f88237da9876505dee100dfbda9fd1cd278d3590840109465e5ed347fdeb6fc2ca8c25fa5cf6e317d977f6c5209f46c30055f5c531c')
        key = unhex('1ee5eec12cfbf3cc311b855ddfddf913cff40b3a7dce058c4e46b5ba9026ba971a973144cbf180ceca7d35e1600048d414f7d5399b4ae46732c34d898fa68fbb0dbcea10d84201734e83c824d0f66207cf6f1b6a2ba13b9285329707facbc060')
        out = unhex('aa761d7d39c1503e3f4601f1e331787dca67794357650d76f6408fb9ea37f9eede1f45fcc741a3ec06e9d23be97eb1fbbcbe64bc6b2c010827469a8a0abbb008b11effefe95ddd558026dd2ce83838d7a087e71d8a98e5cbee59f9f788e99dbe7f9032912a4384af760c56da8d7a40ab057796ded052be17a69a6d14e703a621')

        version = TripleSec.VERSIONS[1]

        self.assertEqual(out, b''.join(TripleSec._generate_macs(inp, [key[:48], key[48:]], version)))

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
        self.assertEqual('\x00' * 64, triplesec.crypto.XSalsa20.decrypt(ciphertext,
            b'this is 32-byte key for xsalsa20'))
