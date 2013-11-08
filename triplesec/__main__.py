#!/usr/bin/env python

"""
This file is part of Python TripleSec - a Python implementation of TripleSec

Released under The BSD 3-Clause License
Copyright (c) 2013 Keybase
"""

# Execute with
# $ python triplesec/__main__.py (2.6+)
# $ python -m triplesec          (2.7+)

import sys

if __package__ is None and not hasattr(sys, "frozen"):
    # direct call of __main__.py
    import os.path
    path = os.path.realpath(os.path.abspath(__file__))
    sys.path.append(os.path.dirname(os.path.dirname(path)))

import triplesec

if __name__ == '__main__':
    triplesec.main()
