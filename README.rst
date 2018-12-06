python-triplesec
================

.. image:: https://travis-ci.org/keybase/python-triplesec.png
   :alt: Build Status
   :target: https://travis-ci.org/keybase/python-triplesec

.. image:: https://coveralls.io/repos/keybase/python-triplesec/badge.png
   :alt: Coverage Status
   :target: https://coveralls.io/r/keybase/python-triplesec

.. image:: https://pypip.in/v/TripleSec/badge.png
   :alt: PyPi version
   :target: https://crate.io/packages/TripleSec

.. image:: https://pypip.in/d/TripleSec/badge.png
   :alt: PyPi downloads
   :target: https://crate.io/packages/TripleSec


A Python port of the TripleSec_ library. See also the JS implementation_.

Compatible with Python 2.7 and 3.6+.

.. _TripleSec: https://keybase.io/triplesec/
.. _implementation: https://github.com/keybase/triplesec/


Installation
------------

::

  pip install TripleSec

Usage
-----

Instantiate a ``triplesec.TripleSec(key=None)`` object, with or without a key (if omitted it will have to be specified at each use), then use the ``encrypt(message, key=None)`` and ``decrypt(ciphertext, key=None)`` methods.

All values must be binary strings (``str`` on Python 2, ``bytes`` on Python 3)

Shortcuts
~~~~~~~~~

The (unkeyed) functions ``encrypt`` and ``decrypt`` are exposed at the module level.

Command line tool
-----------------

TripleSec offers a ``triplesec`` command line tool to encrypt and decrypt messages from the terminal.

Here is the help::

  Command-line TripleSec encryption-decryption tool

  usage: triplesec [-h] [-b | --hex] [-k KEY] {enc|dec} [data]

  positional arguments:
    {enc|dec}          enc: encrypt and sign a message with TripleSec; by
                       default output a hex encoded ciphertext (see -b and
                       --hex) -- dec: decrypt and verify a TripleSec ciphertext
    data               the TripleSec message or ciphertext; if not specified it
                       will be read from stdin; by default ciphertexts will be
                       considered hex encoded (see -b and --hex)

  optional arguments:
    -h, --help         show this help message and exit
    -b, --binary       consider all input (key, plaintext, ciphertext) to be
                       plain binary data and output everything as binary data -
                       this turns off smart decoding/encoding - if you pipe
                       data, you should use this
    --hex              consider all input (key, plaintext, ciphertext) to be hex
                       encoded; hex encode all output
    -k KEY, --key KEY  the TripleSec key; if not specified will check the
                       TRIPLESEC_KEY env variable, then prompt the user for it
    --compatibility    Use Keccak instead of SHA3 for the second MAC and reverse
                       endianness of Salsa20 in version 1. Only effective in
                       versions before 4.

Changes in 0.5
-----------------------
For message authentication, the Triplesec spec uses the Keccak SHA3 proposal function for versions 1 through 3, but for some time, this library used the standardized SHA3-512 function instead. Thus, by default, the Python implementation for versions 1 through 3 is incompatible with the JavaScript and Golang implementations.
From version 4 and going forward, the spec will use only the standardized SHA3-512 function (provided, for example, by `hashlib` in Python), and the Python, JavaScript, and Golang implementations will be compatible.

If you would like to use Keccak with versions 1 through 3 (and thus achieve compatibility with the Node and Go packages), you can pass in `compatibility=True` to `encrypt` and `decrypt`, or on the commandline as detailed in the above section.

Additionally, encryptions that do not specify a version will now use version 4 by default, which is not compatible with previous versions.

Example
-------

>>> import triplesec
>>> x = triplesec.encrypt(b"IT'S A YELLOW SUBMARINE", b'* password *')
>>> print(triplesec.decrypt(x, b'* password *').decode())
IT'S A YELLOW SUBMARINE

>>> from triplesec import TripleSec
>>> T = TripleSec(b'* password *')
>>> x = T.encrypt(b"IT'S A YELLOW SUBMARINE")
>>> print(T.decrypt(x).decode())
IT'S A YELLOW SUBMARINE
