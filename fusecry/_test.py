from Crypto import Random
from fusecry import config, cry
import os
import random
import string

## helpers

def random_string(length):
    return ''.join(random.choice(
        string.ascii_letters + 
        string.digits + 
        string.punctuation + 
        string.whitespace ) for i in range(length))


## tests

def test_cry_enc():
    c = cry.Cry(
        random_string(15),
        Random.get_random_bytes(config.enc.kdf_salt_size),
        1000,
        )
    data = os.urandom(5000)
    assert len(c.enc(data)) % config.enc.aes_block == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_dec():
    c = cry.Cry(
        random_string(15),
        Random.get_random_bytes(config.enc.kdf_salt_size),
        1000,
        )
    data = os.urandom(5000)
    dec_data, ic_check = c.dec(c.enc(data))
    assert ic_check
    assert data == dec_data[:len(data)]

def test_cry_bad_ic():
    c = cry.Cry(
        random_string(15),
        Random.get_random_bytes(config.enc.kdf_salt_size),
        1000,
        )
    data = os.urandom(5000)
    enc_data = c.enc(data)
    bad_enc_data = enc_data[:1000] + b'x' + enc_data[1001:]
    dec_data, ic_check = c.dec(enc_data)
    bad_dec_data, bad_ic_check = c.dec(bad_enc_data)
    assert ic_check == True
    assert bad_ic_check == False


