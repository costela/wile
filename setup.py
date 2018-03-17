#!/usr/bin/python
import os
import sys
from setuptools import setup


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


config = dict(
    name="wile",
    author="Leo Antunes",
    author_email="leo@costela.net",
    description=("A stripped down Let's Encrypt (ACME) client"),
    license="GPLv3",
    keywords="letsencrypt acme ssl",
    url="https://github.com/costela/wile",
    packages=['wile'],
    setup_requires=[
        'pytest-runner',
    ],
    install_requires=[
        'six',
        'acme >= 0.21.0, != 0.22.0',
        'click >= 6.0',
        'pyOpenSSL',
        'cryptography',
        'setuptools_scm',  # for run-time version-detect
        'paramiko',
        'josepy',
    ],
    tests_require=[
        'backports.tempfile;python_version<"3.0"',
        'mock',
        'pytest',
        'pytest-datafiles',
        'testfixtures',
    ],
    entry_points={
        'console_scripts': [
            'wile = wile:main',
        ],
    },
    long_description=read('README.md'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Security :: Cryptography',
        'Topic :: Utilities',
    ],
)

if 'sdist' in sys.argv:
    config.update(dict(
        use_scm_version=True,
    ))
    config['setup_requires'] += [
        'setuptools_scm',
    ]

setup(**config)
