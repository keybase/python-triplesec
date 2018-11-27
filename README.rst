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

Compatible with Python 2.6, 2.7 and 3.3.

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

If you would like to use Keccak with versions 1 through 3 (and thus achieve compatibility with the Node and Go packages), you can pass in `compatibility=True` to `encrypt` and `decrypt`, or on the commandline as detailed in the Example section.

Additionally, invocations that do not specify a version will now use version 4 by default, which is incompatible with previous versions.

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

# Use --compatibility in the command line to decrypt version 1 through 3 messages made with the Node or Go packages.
$ TRIPLESEC_KEY=abc triplesec dec 1c94d7de000000031355e46727ab2f1a1575a605e4aa5012dcf0e13e55891a4167b10a0f5c173a2e6c6cbb5718f3f7021005f2501b8b5b674bed2553687404aae7aed32d4e9a7bb456dbef209786ee14d974e7899a3d8bacfb7f6705f4abeb307047b1360fa2e5721e5e485361d3a59f426af89d6170fd67feba4ccf6c61157e4a563d1de4ed64d7afff92032bc9c5c9e2c125f9f245acf6683c40f3380b0a762c862859b3651a6a51aa1fdd3887e69eecf46cb60e2f6cf2fcf3d29341b2066dd56bb3f164448b6fa4cf4b1ae9312cb147a667350bdaffdd6c4d31
ERROR: Failed authentication of the data
$ TRIPLESEC_KEY=abc triplesec --compatibility dec 1c94d7de000000031355e46727ab2f1a1575a605e4aa5012dcf0e13e55891a4167b10a0f5c173a2e6c6cbb5718f3f7021005f2501b8b5b674bed2553687404aae7aed32d4e9a7bb456dbef209786ee14d974e7899a3d8bacfb7f6705f4abeb307047b1360fa2e5721e5e485361d3a59f426af89d6170fd67feba4ccf6c61157e4a563d1de4ed64d7afff92032bc9c5c9e2c125f9f245acf6683c40f3380b0a762c862859b3651a6a51aa1fdd3887e69eecf46cb60e2f6cf2fcf3d29341b2066dd56bb3f164448b6fa4cf4b1ae9312cb147a667350bdaffdd6c4d31
Hello world
