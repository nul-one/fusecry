#!/usr/bin/env python3

from setuptools import setup, find_packages
import fusecry

setup(
    name = 'fusecry',
    description = fusecry.__doc__.strip(),
    url = 'https://github.com/phlogisto/fusecry',
    download_url = '#TODO',
    version = fusecry.__version__,
    author = fusecry.__author__,
    author_email = fusecry.__author_email__,
    license = fusecry.__licence__,
    packages = [ 'fusecry' ],
    install_requires = [
            'fusepy>=2.0.4',
            'pycrypto>=2.6.1',
        ],
    )

