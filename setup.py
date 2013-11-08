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
    version = '0.1dev',
    packages = ['triplesec'],
    license = 'BSD-new',

    **params
)
