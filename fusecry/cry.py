"""
Fusecry encryption functions.
"""

from Crypto import Random
from Crypto.Cipher import AES 
from Crypto.Hash import SHA256, MD5 
import fusecry.config as config


class Cry(object):
    def __init__(self, password):
        self.password = password

    def enc(self, chunk):
        ks = config.encryption.key_size
        vs = config.encryption.iv_size
        if len(chunk) % AES.block_size != 0:
            chunk += bytes(AES.block_size - len(chunk) % AES.block_size)
        random_key = Random.get_random_bytes(ks)
        random_iv = Random.get_random_bytes(vs)
        random_encryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        secret_key = SHA256.new(bytes(str(self.password), 'utf-8')).digest()
        secret_iv = Random.get_random_bytes(vs)
        secret_encryptor = AES.new(secret_key, AES.MODE_CBC, secret_iv)
        encrypted_random_key = secret_encryptor.encrypt(random_key)
        encrypted_random_iv = secret_encryptor.encrypt(random_iv)
        return secret_iv \
            + encrypted_random_key \
            + encrypted_random_iv \
            + random_encryptor.encrypt(chunk)

    def dec(self, enc_chunk):
        poz = 0
        ks = config.encryption.key_size
        vs = config.encryption.iv_size
        secret_iv = enc_chunk[poz:poz+vs]; poz+=vs
        encrypted_random_key = enc_chunk[poz:poz+ks]; poz+=ks
        encrypted_random_iv = enc_chunk[poz:poz+vs]; poz+=vs
        secret_key = SHA256.new(bytes(str(self.password), 'utf-8')).digest()
        secret_decryptor = AES.new(secret_key, AES.MODE_CBC, secret_iv)
        random_key = secret_decryptor.decrypt(encrypted_random_key)
        random_iv = secret_decryptor.decrypt(encrypted_random_iv)
        random_decryptor = AES.new(random_key, AES.MODE_CBC, random_iv)
        return random_decryptor.decrypt(
                enc_chunk[poz:]
            )
