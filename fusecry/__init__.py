"""
Encrypted filesystem and encryption tool based on FUSE and AES.
"""

__version__ = "0.7.2"
__licence__ = "GPL v3"
__author__ = "Predrag Mandic"
__author_email__ = "github@phlogisto.com"


class FuseCryException(Exception):
    """Generic FuseCry exception."""
    pass


class IntegrityCheckFail(FuseCryException):
    """Raised when data integity check fails during decryption."""
    pass


class FileSizeException(FuseCryException):
    """Raised when encrypted files are of undefined decrypted size."""
    pass


class BadConfException(FuseCryException):
    """Raised when FuseCry conf is not valid or not matching."""
    pass


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
"""Configuration options used throughout the package."""

