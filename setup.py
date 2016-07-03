#!/usr/bin/python
import os
from setuptools import setup


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()

setup(
    name="wile",
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    author="Leo Antunes",
    author_email="leo@costela.net",
    description=("A stripped down Let's Encrypt (ACME) client"),
    license="GPLv3",
    keywords="letsencrypt acme ssl",
    url="https://github.com/costela/wile",
    py_modules=['wile', 'reg', 'cert'],
    install_requires=[
        'acme >= 0.6',
        'click >= 6.0',
        'pyOpenSSL',
        'cryptography',
        'setuptools_scm',  # for run-time version-detect
    ],
    entry_points={
        'console_scripts': [
            'wile = wile:main',
        ],
    },
    long_description=read('README.md'),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Topic :: Utilities',
    ],
)
