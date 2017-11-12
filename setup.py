#!/usr/bin/env python3

from setuptools import setup, find_packages
import fusecry

setup(
    name = 'fusecry',
    description = fusecry.__doc__.strip(),
    url = 'https://github.com/nul-one/fusecry',
    download_url = 'https://github.com/nul-one/fusecry/archive/'+fusecry.__version__+'.tar.gz',
    version = fusecry.__version__,
    author = fusecry.__author__,
    author_email = fusecry.__author_email__,
    license = fusecry.__licence__,
    packages = [ 'fusecry' ],
    entry_points={
        'console_scripts': [
            'fusecry=fusecry.__main__:main',
        ],
    },
    install_requires = [
        'fusepy>=2.0.4',
        'pycrypto>=2.6.1',
        'argcomplete>=1.8.2',
    ],
    python_requires=">=3.4",
)

