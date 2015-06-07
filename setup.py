#!/usr/bin/env python

# Bootstrap installation of Distribute
import distribute_setup
distribute_setup.use_setuptools()

import sys

from setuptools import setup


def read_file(name):
    """
    Read file content
    """
    f = open(name)
    try:
        return f.read()
    except IOError:
        print("could not read %r" % name)
        f.close()


PROJECT = 'skeleton'
VERSION = '0.6'
URL = 'http://github.com/dinoboff/skeleton'
AUTHOR = 'Damien Lebrun'
AUTHOR_EMAIL = 'dinoboff@gmail.com'
DESC = "Basic Template system for project skeleton."
LONG_DESC = read_file('README.rst') + '\n\n' + read_file('HISTORY.rst')

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
    license='BSD',
    packages=['skeleton', 'skeleton.tests', 'skeleton.examples'],
    test_suite='skeleton.tests',
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    extras_require={
        'virtualenv-templates':  [
            'virtualenvwrapper>=2.1.1',
            'virtualenvwrapper.project>=1.0'
            ],
    },
    entry_points={
        'virtualenvwrapper.project.template': [
            'package = skeleton.examples.basicpackage:virtualenv_warpper_hook',
            ],
        },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.1',
        ],
    **EXTRAS
)
