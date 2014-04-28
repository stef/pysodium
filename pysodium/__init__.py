#!/usr/bin/env python2
"""
Wrapper for libsodium library

Copyright (c) 2013-2014, Marsiske Stefan.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import ctypes

sodium = ctypes.cdll.LoadLibrary("libsodium.so")
crypto_box_NONCEBYTES = 24L
crypto_box_PUBLICKEYBYTES = 32L
crypto_box_SECRETKEYBYTES = 32L
crypto_box_ZEROBYTES = 32L
crypto_box_BOXZEROBYTES = 16L
crypto_box_MACBYTES = crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES
crypto_secretbox_KEYBYTES = 32L
crypto_secretbox_NONCEBYTES = 24L
crypto_secretbox_KEYBYTES = 32L
crypto_secretbox_ZEROBYTES = 32L
crypto_secretbox_BOXZEROBYTES = 16L
crypto_secretbox_MACBYTES = crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES
crypto_sign_PUBLICKEYBYTES = 32L
crypto_sign_SECRETKEYBYTES = 64L
crypto_sign_SEEDBYTES = 32L
crypto_stream_KEYBYTES = 32L
crypto_stream_NONCEBYTES = 24L
crypto_generichash_BYTES = 32L
crypto_scalarmult_curve25519_BYTES = 32L
crypto_scalarmult_BYTES = 32L
crypto_sign_BYTES = 64L

"""
typedef struct crypto_generichash_blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[256];
    size_t   buflen;
    uint8_t  last_node;
    ...;
} crypto_generichash_state;
"""
crypto_generichash_state = 8*12 + 256 + ctypes.sizeof(ctypes.c_size_t) + 1

def crypto_scalarmult_curve25519(n,p):
    buf = ctypes.create_string_buffer(crypto_scalarmult_BYTES)
    sodium.crypto_scalarmult_curve25519(buf, n, p)
    return buf.raw

def crypto_scalarmult_curve25519_base(n):
    buf = ctypes.create_string_buffer( crypto_scalarmult_BYTES)
    sodium.crypto_scalarmult_curve25519_base(buf, n)
    return buf.raw


# crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen)
def crypto_generichash(m, k=b'', outlen=crypto_generichash_BYTES):
    buf = ctypes.create_string_buffer(outlen)
    if not sodium.crypto_generichash(buf, ctypes.c_uint(outlen), m, ctypes.c_ulonglong(len(m)), k, ctypes.c_uint(len(k))) == 0:
        raise ValueError
    return buf.raw

#crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen);
def crypto_generichash_init(outlen=crypto_generichash_BYTES, k=b''):
    buf = ctypes.create_string_buffer(crypto_generichash_state)
    sodium.crypto_generichash_init(buf, k, ctypes.c_ulonglong(len(k)), outlen)
    return buf.raw

#crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen);
def crypto_generichash_update(state, m):
    sodium.crypto_generichash_update(state, m, ctypes.c_ulonglong(len(m)))
    return state

#crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen);
def crypto_generichash_final(state, outlen=crypto_generichash_BYTES):
    buf = ctypes.create_string_buffer(outlen)
    sodium.crypto_generichash_final(state, buf, outlen)
    return buf.raw

def randombytes(size):
    buf = ctypes.create_string_buffer(size)
    sodium.randombytes(buf, ctypes.c_ulonglong(size))
    return buf.raw

def crypto_box_keypair():
    pk = ctypes.create_string_buffer( crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer( crypto_box_SECRETKEYBYTES)
    if not sodium.crypto_box_keypair(pk, sk) == 0:
        raise ValueError
    return (pk.raw, sk.raw)

def crypto_box(msg, nonce, pk, sk):
    if None in (msg, nonce, pk, sk): raise ValueError
    padded = b"\x00" * crypto_box_ZEROBYTES + msg
    c = ctypes.create_string_buffer( len(padded))
    if not sodium.crypto_box(c, padded, ctypes.c_ulonglong(len(padded)), nonce, pk, sk) == 0:
        raise ValueError
    return c.raw[crypto_box_BOXZEROBYTES:]

def crypto_box_open(c, nonce, pk, sk):
    if None in (c, nonce, pk, sk): raise ValueError
    padded = b"\x00" * crypto_box_BOXZEROBYTES + c
    msg = ctypes.create_string_buffer( len(padded))
    if not sodium.crypto_box_open(msg, padded, ctypes.c_ulonglong(len(padded)), nonce, pk, sk) == 0:
        raise ValueError
    return msg.raw[crypto_box_ZEROBYTES:]

def crypto_secretbox(msg, nonce, k):
    if None in (msg, nonce, k): raise ValueError
    padded = b"\x00" * crypto_secretbox_ZEROBYTES + msg
    c = ctypes.create_string_buffer( len(padded))
    if not sodium.crypto_secretbox(c, padded, ctypes.c_ulonglong(len(padded)), nonce, k) == 0:
        raise ValueError
    return c.raw[crypto_secretbox_BOXZEROBYTES:]

def crypto_secretbox_open(c, nonce, k):
    if None in (c, nonce, k): raise ValueError
    padded = b"\x00" * crypto_secretbox_BOXZEROBYTES + c
    msg = ctypes.create_string_buffer( len(padded))
    if not sodium.crypto_secretbox_open(msg, padded, ctypes.c_ulonglong(len(padded)), nonce, k) == 0:
        raise ValueError
    return msg.raw[crypto_secretbox_ZEROBYTES:]

def crypto_sign_keypair():
    pk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    if not sodium.crypto_sign_keypair(pk, sk) == 0:
        raise ValueError
    return (pk.raw, sk.raw)

def crypto_sign_seed_keypair(seed):
    pk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    if not sodium.crypto_sign_seed_keypair(pk, sk, seed) == 0:
        raise ValueError
    return (pk.raw, sk.raw)

def crypto_sign(m, sk):
    if None in (m, sk): raise ValueError
    smsg = ctypes.create_string_buffer(len(m)+crypto_sign_BYTES)
    smsglen = ctypes.pointer(ctypes.c_ulonglong())
    if not sodium.crypto_sign(smsg, smsglen, m, ctypes.c_ulonglong(len(m)), sk) == 0:
        raise ValueError
    return smsg.raw

def crypto_sign_open(sm, pk):
    if None in (sm, pk): raise ValueError
    msg = ctypes.create_string_buffer(len(sm))
    msglen = ctypes.c_ulonglong()
    msglenp = ctypes.pointer(msglen)
    if not sodium.crypto_sign_open(msg, msglenp, sm, ctypes.c_ulonglong(len(sm)), pk) == 0:
        raise ValueError
    return msg.raw[:msglen.value]

def crypto_stream(cnt, nonce = None, key = None):
    res = ctypes.create_string_buffer(cnt)
    if not nonce:
        nonce = randombytes(crypto_stream_NONCEBYTES)
    if not key:
        key = randombytes(crypto_stream_KEYBYTES)
    if not sodium.crypto_stream(res, ctypes.c_ulonglong(cnt), nonce, key) == 0:
        raise ValueError
    return res.raw

def crypto_stream_xor(msg, cnt, nonce = None, key = None):
    res = ctypes.create_string_buffer(cnt)
    if not nonce:
        nonce = randombytes(crypto_stream_NONCEBYTES)
    if not key:
        key = randombytes(crypto_stream_KEYBYTES)
    if not sodium.crypto_stream_xor(res, msg, ctypes.c_ulonglong(cnt), nonce, key) == 0:
        raise ValueError
    return res.raw

def test():
    import binascii

    crypto_stream(8L)
    crypto_stream(1337L)
    print(binascii.hexlify(crypto_stream(8L)))
    print(binascii.hexlify(crypto_stream(16L)))
    print(binascii.hexlify(crypto_stream(32L)))
    print(binascii.hexlify(crypto_stream_xor('howdy', len('howdy'))))
    print(binascii.hexlify(crypto_stream_xor('howdy' * 16, len('howdy')*16)))

    print(binascii.hexlify(crypto_generichash('howdy')))
    state = crypto_generichash_init()
    state = crypto_generichash_update(state, 'howdy')
    print(binascii.hexlify(crypto_generichash_final(state)))
    print(binascii.hexlify(crypto_generichash('howdy', outlen=4)))
    print(binascii.hexlify(crypto_generichash('howdy', outlen=8)))
    state = crypto_generichash_init(outlen=6)
    state = crypto_generichash_update(state, 'howdy')
    print(binascii.hexlify(crypto_generichash_final(state, outlen=6)))

    pk, sk = crypto_box_keypair()
    n = randombytes(crypto_box_NONCEBYTES)
    c = crypto_box("howdy", n, pk, sk)
    print(crypto_box_open(c, n, pk, sk))

    k = randombytes(crypto_secretbox_KEYBYTES)
    n = randombytes(crypto_secretbox_NONCEBYTES)
    c = crypto_secretbox("howdy", n, k)
    print(crypto_secretbox_open(c, n, k))

    s = crypto_scalarmult_curve25519_base(randombytes(crypto_scalarmult_BYTES))
    r = crypto_scalarmult_curve25519_base(randombytes(crypto_scalarmult_BYTES))
    print('scalarmult')
    print(repr(crypto_scalarmult_curve25519(s,r)))

    pk, sk = crypto_sign_keypair()
    signed = crypto_sign('howdy',sk)
    changed = signed[:crypto_sign_BYTES]+'0'+signed[crypto_sign_BYTES+1:]
    print crypto_sign_open(signed, pk)
    try:
        crypto_sign_open(changed, pk)
    except ValueError:
        print "signature failed to verify for changed payload"

    seed = crypto_generichash('howdy', outlen=crypto_sign_SEEDBYTES)
    pk, sk = crypto_sign_seed_keypair(seed)
    pk2, sk2 = crypto_sign_seed_keypair(seed)
    print binascii.hexlify(pk)
    print binascii.hexlify(pk2)
    assert pk == pk2
    assert sk == sk2

if __name__ == '__main__':
    test()
