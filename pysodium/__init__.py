#!/usr/bin/env python
"""
Wrapper for libsodium library

Copyright (c) 2013, Marsiske Stefan and individual contributors.
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

from pysodium import sodium

crypto_box_NONCEBYTES = sodium.lib.crypto_box_NONCEBYTES
crypto_box_PUBLICKEYBYTES = sodium.lib.crypto_box_PUBLICKEYBYTES
crypto_box_SECRETKEYBYTES = sodium.lib.crypto_box_SECRETKEYBYTES
crypto_box_ZEROBYTES = sodium.lib.crypto_box_ZEROBYTES
crypto_box_BOXZEROBYTES = sodium.lib.crypto_box_BOXZEROBYTES
crypto_secretbox_KEYBYTES = sodium.lib.crypto_secretbox_KEYBYTES
crypto_secretbox_NONCEBYTES = sodium.lib.crypto_secretbox_NONCEBYTES
crypto_secretbox_KEYBYTES = sodium.lib.crypto_secretbox_KEYBYTES
crypto_secretbox_ZEROBYTES = sodium.lib.crypto_box_ZEROBYTES
crypto_secretbox_BOXZEROBYTES = sodium.lib.crypto_box_BOXZEROBYTES
crypto_sign_PUBLICKEYBYTES = sodium.lib.crypto_sign_PUBLICKEYBYTES
crypto_sign_SECRETKEYBYTES = sodium.lib.crypto_sign_SECRETKEYBYTES
crypto_stream_KEYBYTES = sodium.lib.crypto_stream_KEYBYTES
crypto_stream_NONCEBYTES = sodium.lib.crypto_stream_NONCEBYTES
crypto_generichash_BYTES = sodium.lib.crypto_generichash_BYTES
crypto_scalarmult_curve25519_BYTES = sodium.lib.crypto_scalarmult_curve25519_BYTES
crypto_scalarmult_BYTES = sodium.lib.crypto_scalarmult_curve25519_BYTES
crypto_sign_BYTES = sodium.lib.crypto_sign_BYTES

def crypto_scalarmult_curve25519(n,p):
    buf = sodium.ffi.new("unsigned char[]", crypto_scalarmult_BYTES)
    sodium.lib.crypto_scalarmult_curve25519(buf, n, p)
    return sodium.ffi.buffer(buf, crypto_scalarmult_BYTES)[:]

def crypto_scalarmult_curve25519_base(n):
    buf = sodium.ffi.new("unsigned char[]", crypto_scalarmult_BYTES)
    sodium.lib.crypto_scalarmult_curve25519_base(buf, n)
    return sodium.ffi.buffer(buf, crypto_scalarmult_BYTES)[:]

def crypto_generichash(m, k='', outlen=crypto_generichash_BYTES):
    # FIXME returns different result than the 3-step procedure used as a workaround
    #buf = sodium.ffi.new("unsigned char[]", outlen)
    #sodium.lib.crypto_generichash(buf, len(buf), m, len(m), k, len(k))
    #return sodium.ffi.buffer(buf, crypto_generichash_BYTES)[:]
    state = crypto_generichash_init(k=k, outlen=outlen)
    state = crypto_generichash_update(state, m)
    return crypto_generichash_final(state)

#crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen);
def crypto_generichash_init(outlen=crypto_generichash_BYTES, k=''):
    buf = sodium.ffi.new("crypto_generichash_state*")
    sodium.lib.crypto_generichash_init(buf, k, len(k), outlen)
    return buf

#crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen);
def crypto_generichash_update(state, m):
    buf = sodium.ffi.new("unsigned char[]", len(m))
    sodium.lib.crypto_generichash_update(state, buf, len(m))
    return state

#crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen);
def crypto_generichash_final(state, outlen=crypto_generichash_BYTES):
    buf = sodium.ffi.new("unsigned char[]", outlen)
    sodium.lib.crypto_generichash_final(state, buf, outlen )
    return sodium.ffi.buffer(buf, outlen)[:]

def randombytes(l):
    buf = sodium.ffi.new("unsigned char[]", l)
    sodium.lib.randombytes(buf, l)
    return sodium.ffi.buffer(buf, l)[:]

def crypto_box_keypair():
    pk = sodium.ffi.new("unsigned char[]", crypto_box_PUBLICKEYBYTES)
    sk = sodium.ffi.new("unsigned char[]", crypto_box_SECRETKEYBYTES)
    if not sodium.lib.crypto_box_keypair(pk, sk):
        raise ValueError
    pk = sodium.ffi.buffer(pk, crypto_box_PUBLICKEYBYTES)[:]
    sk = sodium.ffi.buffer(sk, crypto_box_SECRETKEYBYTES)[:]
    return (pk, sk)

def crypto_box(msg, nonce, pk, sk):
    if None in (msg, nonce, pk, sk): raise ValueError
    padded = b"\x00" * crypto_box_ZEROBYTES + msg
    c = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_box(c, padded, len(padded), nonce, pk, sk):
        raise ValueError
    return sodium.ffi.buffer(c, len(padded))[crypto_box_BOXZEROBYTES:]

def crypto_box_open(c, nonce, pk, sk):
    if None in (c, nonce, pk, sk): raise ValueError
    padded = b"\x00" * crypto_box_BOXZEROBYTES + c
    msg = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_box_open(msg, padded, len(padded), nonce, pk, sk):
        raise ValueError
    return sodium.ffi.buffer(msg, len(padded))[crypto_box_ZEROBYTES:]

def crypto_secretbox(msg, nonce, k):
    if None in (msg, nonce, k): raise ValueError
    padded = b"\x00" * crypto_secretbox_ZEROBYTES + msg
    c = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_secretbox(c, padded, len(padded), nonce, k):
        raise ValueError
    return sodium.ffi.buffer(c, len(padded))[crypto_secretbox_BOXZEROBYTES:]

def crypto_secretbox_open(c, nonce, k):
    if None in (c, nonce, k): raise ValueError
    padded = b"\x00" * crypto_secretbox_BOXZEROBYTES + c
    msg = sodium.ffi.new("unsigned char[]", len(padded))
    if not sodium.lib.crypto_secretbox_open(msg, padded, len(padded), nonce, k):
        raise ValueError
    return sodium.ffi.buffer(msg, len(padded))[crypto_secretbox_ZEROBYTES:]

def crypto_sign_keypair():
    pk = sodium.ffi.new("unsigned char[]", crypto_sign_PUBLICKEYBYTES)
    sk = sodium.ffi.new("unsigned char[]", crypto_sign_SECRETKEYBYTES)
    if not sodium.lib.crypto_sign_keypair(pk, sk):
        raise ValueError
    pk = sodium.ffi.buffer(pk, crypto_sign_PUBLICKEYBYTES)[:]
    sk = sodium.ffi.buffer(sk, crypto_sign_SECRETKEYBYTES)[:]
    return (pk, sk)

def crypto_sign(m, sk):
    if None in (m, sk): raise ValueError
    smsg = sodium.ffi.new("unsigned char[]", len(m)+crypto_sign_BYTES)
    smsglen = sodium.ffi.new("unsigned long long *")
    if not sodium.lib.crypto_sign(smsg, smsglen, m, len(m), sk):
        raise ValueError
    return sodium.ffi.buffer(smsg, smsglen[0])[:]

def crypto_sign_open(sm, pk):
    if None in (sm, pk): raise ValueError
    msg = sodium.ffi.new("unsigned char[]", len(sm))
    msglen = sodium.ffi.new("unsigned long long *")
    if not sodium.lib.crypto_sign_open(msg, msglen, sm, len(sm), pk):
        raise ValueError
    return sodium.ffi.buffer(msg, msglen[0])[:]

def crypto_stream(cnt, nonce = None, key = None):
    res = sodium.ffi.new("unsigned char[]", cnt)
    if not nonce:
        nonce = randombytes(crypto_stream_NONCEBYTES)
    if not key:
        key = randombytes(crypto_stream_KEYBYTES)
    if not sodium.lib.crypto_stream(res, len(res), nonce, key):
        raise ValueError
    return sodium.ffi.buffer(res, cnt)[:]

def crypto_stream_xor(msg, cnt, nonce = None, key = None):
    res = sodium.ffi.new("unsigned char[]", cnt)
    mres = sodium.ffi.new("unsigned char[]", len(msg))
    if not nonce:
        nonce = randombytes(crypto_stream_NONCEBYTES)
    if not key:
        key = randombytes(crypto_stream_KEYBYTES)
    if not sodium.lib.crypto_stream_xor(res, msg, len(res), nonce, key):
        raise ValueError
    return sodium.ffi.buffer(res, cnt)[:]

def test():
    import binascii
    print binascii.hexlify(crypto_stream(8))
    print binascii.hexlify(crypto_stream(16))
    print binascii.hexlify(crypto_stream(32))
    print binascii.hexlify(crypto_stream_xor('howdy', len('howdy')))
    print binascii.hexlify(crypto_stream_xor('howdy' * 16, len('howdy')*16))

    return
    print binascii.hexlify(crypto_generichash('howdy'))
    state = crypto_generichash_init()
    state = crypto_generichash_update(state, 'howdy')
    print binascii.hexlify(crypto_generichash_final(state))

    pk, sk = crypto_box_keypair()
    n = randombytes(crypto_box_NONCEBYTES)
    c = crypto_box("howdy", n, pk, sk)
    print crypto_box_open(c, n, pk, sk)

    k = randombytes(crypto_secretbox_KEYBYTES)
    n = randombytes(crypto_secretbox_NONCEBYTES)
    c = crypto_secretbox("howdy", n, k)
    print crypto_secretbox_open(c, n, k)

    s = crypto_scalarmult_curve25519_base(randombytes(crypto_scalarmult_BYTES))
    r = crypto_scalarmult_curve25519_base(randombytes(crypto_scalarmult_BYTES))
    print 'scalarmult'
    print repr(crypto_scalarmult_curve25519(s,r))

    pk, sk = crypto_sign_keypair()
    signed = crypto_sign('howdy',sk)
    print crypto_sign_open(signed, pk)

if __name__ == '__main__':
    test()
