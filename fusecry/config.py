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
        "aes_block": AES.block_size,
        "chunk_size": 256 * AES.block_size, # 256*16 = 4096 FS_B
        "extension": '.fcry',
    }
)

