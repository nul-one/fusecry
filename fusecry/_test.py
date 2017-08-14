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
    c = cry.Cry(random_string(15))
    data = os.urandom(5000)
    assert len(c.enc(data)) % config.enc.aes_block == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_dec():
    c = cry.Cry(random_string(15))
    data = os.urandom(5000)
    assert data == c.dec(c.enc(data))[:len(data)]

def test_cry_enc_ic():
    c = cry.Cry(random_string(15), True)
    data = os.urandom(5000)
    assert len(c.enc(data)) % config.enc.aes_block == 0
    assert data != c.enc(data)[:len(data)]
    assert c.enc(data) != c.enc(data)

def test_cry_dec_ic():
    c = cry.Cry(random_string(15), True)
    data = os.urandom(5000)
    assert data == c.dec(c.enc(data))[:len(data)]

