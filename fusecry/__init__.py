"""
Encrypted filesystem based on FUSE and AES.
"""

__version__ = "0.5.1"
__licence__ = "GPL v3"
__author__ = "Predrag Mandic"
__author_email__ = "github@phlogisto.com"


class Objectview(object):
    def __init__(self, d):
        self.__dict__ = d

config = Objectview(
    {
        "kdf_iter_range": (60000,80000),
        "kdf_salt_size": 32,
        "extension": '.fcry',
        "conf": '.fusecry',
        "sample_size": 1024,
        "default_chunk_size": 4096,
    }
)


