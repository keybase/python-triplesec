"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
"""

try:
    from setuptools import setup
    setuptools_available = True
except ImportError:
    from distutils.core import setup
    setuptools_available = False

params = {}

if setuptools_available:
    params['entry_points'] = {'console_scripts': ['triplesec = triplesec:main']}
else:
    params['scripts'] = ['bin/triplesec']

setup(
    name = 'TripleSec',
    version = '0.2',
    description = 'a Python implementation of TripleSec',
    author = 'Filippo Valsorda',
    author_email = 'filippo.valsorda@gmail.com',
    url = 'http://github.com/keybase/python-triplesec',
    packages = ['triplesec'],
    license = 'BSD-new',
    classifiers = ['Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Programming Language :: Python :: 2.6',
                   'Programming Language :: Python :: 2.7',
                   'Programming Language :: Python :: 3.3',
                   'Topic :: Security :: Cryptography',
                   'Topic :: Software Development :: Libraries'],
    long_description = open('README.rst').read(),
    install_requires = ["pycrypto",
                        "scrypt",
                        "six",
                        "pysha3",
                        "twofish",
                        "salsa20"],
    **params
)
