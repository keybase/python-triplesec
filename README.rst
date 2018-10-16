python-triplesec
================

.. image:: https://travis-ci.org/mfrager/python-triplesec.png
   :alt: Build Status
   :target: https://travis-ci.org/mfrager/python-triplesec

.. image:: https://coveralls.io/repos/keybase/python-triplesec/badge.png
   :alt: Coverage Status
   :target: https://coveralls.io/r/keybase/python-triplesec

.. image:: https://pypip.in/v/TripleSec/badge.png
   :alt: PyPi version
   :target: https://crate.io/packages/TripleSec

.. image:: https://pypip.in/d/TripleSec/badge.png
   :alt: PyPi downloads
   :target: https://crate.io/packages/TripleSec


A Python port of the TripleSec_ library. The Python version is NOT binary compatible with other TripleSec versions.

Compatible with Python 3.

.. _TripleSec: https://keybase.io/triplesec/
.. _implementation: https://github.com/keybase/triplesec/


Installation
------------

::

  pip install TripleSec

Usage
-----

Instantiate a ``triplesec.TripleSec(key=None)`` object, with or without a key (if omitted it will have to be specified at each use), then use the ``encrypt(message, key=None)`` and ``decrypt(ciphertext, key=None)`` methods.

All values must be binary strings (``bytes`` on Python 3)

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

API
---

Sphinx documentation coming soon.

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
