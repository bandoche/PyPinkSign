#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from setuptools import setup


PROJECT = 'pypinksign'
VERSION = '0.3'
URL = 'http://github.com/bandoche/PyPinkSign'
AUTHOR = 'Sangjun Jung'
AUTHOR_EMAIL = 'spamcoffee+pypinksign@gmail.com'
DESC = "Basic NPKI module."
LONG_DESC = "See https://github.com/bandoche/PyPinkSign"  # read_file('README.rst')

EXTRAS = {}

if sys.version_info > (3,):
    EXTRAS['use_2to3'] = True

setup(
    name=PROJECT,
    version=VERSION,
    description=DESC,
    long_description=LONG_DESC,
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    url=URL,
    license='MIT',
    packages=['pypinksign'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'pyasn1==0.4.5',
        'cryptography==2.6.1',
        'bitarray==0.8.3',
        'pyOpenSSL==19.0.0',
        'future',
    ],
    keywords='npki 공인인증서 korean pki certificate',
    platforms='OS Independent',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7'
        'Programming Language :: Python :: 3.6'
        'Programming Language :: Python :: 3.7'
    ],
    **EXTRAS
)
