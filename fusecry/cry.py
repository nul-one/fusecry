"""
FuseCry encryption functions.

Use Cry objects `enc` and `dec` methods to encrypt and decrypt data.
Use `get_password_cry` and `get_rsa_cry` to generate proper Cry object.

Examples:
    Generate new Cry object with user password:

        get_password_cry(password)

    Generate existing Cry object with user password:

        get_password_cry(password, kdf_salt, kdf_iterations)

    Generate new Cry object with RSA key:

        get_rsa_cry(rsa_key):

    Generate existing Cry object with RSA key and RSA encrypted AES key:

        get_rsa_cry(rsa_key, encrypted_aes_key)

Todo:
    * Add additional encryption methods like Blowfish
    * Add additional HMAC digest modes like MD5
    * Make HMAC validation optional
"""
from Crypto.Cipher import AES 
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from fusecry import IntegrityCheckFail
from fusecry import config
from random import randint
import os


def get_password_cry(password, kdf_salt=None, kdf_iters=None):
    """Generate Cry object from password using KDF.

    Optional arguments are not required if you generate your first Cry object.
    If you already used it to encrypt data before, you will have to provide the
    generated arguments (returned by this function) in order to create the
    exact same Cry object.

    Args:
        password (str): User password.
        kdf_salt (:obj:`bytes`, optional): KDF salt. Defaults to None.
        kdf_iters (:obj:`int`, optional): Number of KDF iterations. Defaults to
            None.

    Returns:
        (
            Cry: Cry object ready for encryption use,
            bytes: KDF salt,
            int: KDF iterations
        )

        KDF salt and number of KDF iterations are returned for future reference
        if they were generated and not provided. They will be returned in any
        case.
    """
    key_size = AES.key_size[2] # 256 bit key
    kdf_salt = kdf_salt or os.urandom(config.kdf_salt_size)
    kdf_iters = kdf_iters or randint(*config.kdf_iter_range)
    aes_key = PBKDF2(str(password), kdf_salt, key_size, kdf_iters)
    crypto = Cry(aes_key)
    return crypto, kdf_salt, kdf_iters

def get_rsa_cry(rsa_key, enc_aes=None):
    """Generate Cry object using RSA key.

    Optional arguemnt is not required if you generate your first Cry object. If
    you already used it to encrypt data before, you will have to provide the
    generated argument (returned by this function) in order to create the exact
    same Cry object.

    Args:
        rsa_key (bytes): Public or private RSA key. If public key is used, only
            encryption methods will be available in returned Cry object. The
            RSA key is used to encrypt random generated 256 bit AES key.
        enc_aes (:obj:`bytes`, optional): RSA encrypted AES key. It has to be
            encrypted with the same key provided in rsa_key argument. Defaults
            to None.

    Returns:
        (
            Cry: Cry object ready for encryption use,
            int: RSA key size,
            bytes: encrypted AES key
        )

        RSA key size and encrypted AES key are returned to be stored for future
        reference. If encrypted AES key was not provided, it will be generated,
        but it is returned in any case.
    """
    key_size = AES.key_size[2]
    rsa = RSA.importKey(rsa_key)
    rsa_size = int((rsa.size()+1)/8)
    aes_key = None
    if enc_aes:
        aes_key = rsa.decrypt(enc_aes)
        aes_key = b'\x00' * (AES.block_size - len(aes_key)) + aes_key
    else:
        aes_key = os.urandom(key_size)
        enc_aes = rsa.encrypt(aes_key, 'K')[0]
        enc_aes = b'\x00' * (rsa_size - len(enc_aes)) + enc_aes
    crypto = Cry(aes_key)
    return crypto, rsa_size, enc_aes


class Cry(object):
    """Contains methods and keys for encryption and decryption of byte chunks.

    Cry uses AES in CBC mode to encrypt and decrypt bytes. Once created, it may
    be reused multiple times.

    Attributes:
        hash_func (function): Function used for HMAC hashing.
        ks (int): AES key size.
        vs (int): AES initialization vector size.
        hs (int): Digest size of hash function defined in attribute hash_func.
        aes_key (bytes): AES key in plain text.
        ms (int): Meta size - size of non-data part of encrypted chunk. This
            meta data consists of IV and HMAC.
    """

    def __init__(self, aes_key):
        """Constructor.

        Args:
            aes_key (bytes): Plain text AES key.
        """
        self.hash_func = SHA256
        self.ks = len(aes_key)
        self.vs = AES.block_size
        self.hs = self.hash_func.digest_size
        self.aes_key = aes_key
        self.ms = self.vs + self.hs

    def enc(self, chunk):
        """Encrypt a chunk of bytes and returned encrypted chunk.

        Initialization vector is randomly generated for each chunk.

        Args:
            chunk (bytes): Plain text data to be encrypted.

        Returns:
            bytes: Encrypted chunk.

            Encrypted chunk is bytes object consisting of IV, HMAC and
            encrypted bytes in that order.
        """
        checksum = HMAC.new(self.aes_key, digestmod=self.hash_func)
        if not chunk:
            return bytes(0)
        chunk += bytes((AES.block_size - len(chunk)) % AES.block_size)
        checksum.update(chunk)
        iv = os.urandom(self.vs)
        aes = AES.new(self.aes_key, AES.MODE_CBC, iv)
        return iv + aes.encrypt(checksum.digest() + chunk)

    def dec(self, enc_chunk):
        """Decrypt encrypted chunk, perform validation and return plain text.

        Args:
            enc_chunk (bytes): Encrypted chunk returned by enc(chunk) method.

        Returns:
            bytes: Plain text data.

        Raises:
            IntegrityCheckFail: When integrity check fails.
        """
        if not enc_chunk:
            return b'', False
        checksum = HMAC.new(self.aes_key, digestmod=self.hash_func)
        iv = enc_chunk[:self.vs]
        aes = AES.new(self.aes_key, AES.MODE_CBC, iv)
        chunk = aes.decrypt(enc_chunk[self.vs:])
        checksum.update(chunk[self.hs:])
        if chunk[:self.hs] != checksum.digest():
            raise IntegrityCheckFail("Integrity check failed.")
        return chunk[self.hs:]

