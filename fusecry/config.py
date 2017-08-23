"""
FuseCry config.
"""

from Crypto.Cipher import AES
from Crypto.Hash import MD5

class Objectview(object):
    def __init__(self, d):
        self.__dict__ = d

enc = Objectview(
    {
        "hash_size": MD5.digest_size,
        "key_size": AES.key_size[2],
        "iv_size": 16,
        "kdf_iter_range": (60000,80000),
        "kdf_salt_size": 32,
        "aes_block": AES.block_size,
        "extension": '.fcry',
        "conf": '.fusecry',
        "default_chunk_size": 4096,
    }
)

