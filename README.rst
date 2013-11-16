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

  Usage: triplesec {enc|dec} [key] {message|ciphertext}

  Both the key and the message can be specified as text or as hex if prepended with 0x
  The key, if omitted, will be requested

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
