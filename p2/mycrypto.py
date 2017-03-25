import base64
from collections import Counter
import itertools
from Crypto.Cipher import AES

import pbkdf2

def xorstring(s1, s2):
    return "".join([chr(ord(a) ^ ord(b)) for a, b in itertools.izip(s1, s2)])


def xorstring_key(s, key):
    key = (key*(len(s)/len(key) + 1))[:len(s)]
    return xorstring(s, key)


def str_to_nlength_blocks(s, length):
    """
    Return a list of slices of string 's' of length 'length', with any leftover
    in the last element.
    """
    if len(s) % length:
        return [s[length*i:length*(i+1)] for i in range(len(s)/length + 1)]
    else:
        return [s[length*i:length*(i+1)] for i in range(len(s)/length)]


def aes_decrypt_block(ct, key):
    ct = ct[:AES.block_size]
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)


def aes_encrypt_block(pt, key):
    pt = pt[:AES.block_size]
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)


def aes_decrypt_cbc(ct, key, iv):
    blocks = str_to_nlength_blocks(ct, AES.block_size)
    feed = iv
    pt = ""
    for block in blocks:
        ptb = aes_decrypt_block(block, key)
        ptb = xorstring_key(ptb, feed)
        feed = block
        pt += ptb

    return pt

def aes_encrypt_cbc(pt, key, iv):
    blocks = str_to_nlength_blocks(pt, AES.block_size)
    feed = iv
    ct = ""
    for block in blocks:
        input = xorstring_key(block, feed)
        ctb = aes_encrypt_block(input, key)
        feed = ctb
        ct += ctb

    return ct
