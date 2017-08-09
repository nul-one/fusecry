"""
FuseCry config.
"""

class Objectview(object):
    def __init__(self, d):
        self.__dict__ = d

encryption = Objectview(
    {
        "checksum_size": 16, # unused
        "key_size": 32,
        "iv_size": 16,
        "chunk_blocks": 256, # 256*16(AES) = 4096 FS_B
    }
)

