"""
FuseCry config.
"""
from Crypto.Cipher.AES import block_size

class Objectview(object):
    def __init__(self, d):
        self.__dict__ = d

enc = Objectview(
    {
        "key_size": 32,
        "iv_size": 16,
        "aes_block": block_size,
        "chunk_size": 256 * block_size, # 256*16 = 4096 FS_B
        "extension": '.fcry',
    }
)

