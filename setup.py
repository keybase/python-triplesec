"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
"""

import sys

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

tests_require = ['nose']
if sys.version_info < (2, 7): tests_require.append('unittest2')

setup(
    name = 'TripleSec',
    version = '0.5',
    description = 'a Python implementation of TripleSec',
    author = 'Keybase',
    author_email = 'max@keybase.io',
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
    install_requires = ["pycryptodome==3.7.1",
                        "scrypt==0.8.6",
                        "six==1.11.0",
                        "pysha3==1.0.2",
                        "twofish==0.3.0",
                        "salsa20==0.3.0"],
    test_suite = 'nose.collector',
    tests_require = tests_require,
    **params
)
