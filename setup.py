#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


PROJECT = 'pypinksign'
VERSION = '0.5.1'
URL = 'http://github.com/bandoche/PyPinkSign'
AUTHOR = 'Sangjun Jung'
AUTHOR_EMAIL = 'spamcoffee+pypinksign@gmail.com'
DESC = "Basic NPKI module."
LONG_DESC = "See https://github.com/bandoche/PyPinkSign"  # read_file('README.rst')

EXTRAS = {}

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
        'pyasn1==0.4.8',
        'cryptography==38.0.3',
    ],
    keywords='npki 공인인증서 공동인증서 korean pki certificate',
    platforms='OS Independent',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    **EXTRAS
)
