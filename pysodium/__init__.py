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

import ctypes, platform

if platform.system() == 'Windows':
    sodium = ctypes.cdll.LoadLibrary("libsodium")
elif platform.system() == 'Darwin':
    sodium = ctypes.cdll.LoadLibrary('libsodium.dylib')
else:
    sodium = ctypes.cdll.LoadLibrary("libsodium.so")

crypto_box_NONCEBYTES = sodium.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = sodium.crypto_box_publickeybytes()
crypto_box_SECRETKEYBYTES = sodium.crypto_box_secretkeybytes()
crypto_box_ZEROBYTES = sodium.crypto_box_zerobytes()
crypto_box_BOXZEROBYTES = sodium.crypto_box_boxzerobytes()
crypto_box_MACBYTES = sodium.crypto_box_macbytes()
crypto_secretbox_KEYBYTES = sodium.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = sodium.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES = sodium.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES = sodium.crypto_secretbox_boxzerobytes()
crypto_secretbox_MACBYTES = sodium.crypto_secretbox_macbytes()
crypto_sign_PUBLICKEYBYTES = sodium.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = sodium.crypto_sign_secretkeybytes()
crypto_sign_SEEDBYTES = sodium.crypto_sign_seedbytes()
crypto_sign_BYTES = sodium.crypto_sign_bytes()
crypto_stream_KEYBYTES = sodium.crypto_stream_keybytes()
crypto_stream_NONCEBYTES = sodium.crypto_stream_noncebytes()
crypto_generichash_BYTES = sodium.crypto_generichash_bytes()
crypto_scalarmult_curve25519_BYTES = sodium.crypto_scalarmult_curve25519_bytes()
crypto_scalarmult_BYTES = sodium.crypto_scalarmult_bytes()

"""
#pragma pack(push, 1)
CRYPTO_ALIGN(64) typedef struct crypto_generichash_blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[2 * 128];
    size_t   buflen;
    uint8_t  last_node;
} crypto_generichash_blake2b_state;
#pragma pack(pop)
"""
crypto_generichash_state = 8*12 + 256 + ctypes.sizeof(ctypes.c_size_t) + 1 + 63

def crypto_scalarmult_curve25519(n,p):
    buf = ctypes.create_string_buffer(crypto_scalarmult_BYTES)
    sodium.crypto_scalarmult_curve25519(buf, n, p)
    return buf.raw

def crypto_scalarmult_curve25519_base(n):
    buf = ctypes.create_string_buffer( crypto_scalarmult_BYTES)
    sodium.crypto_scalarmult_curve25519_base(buf, n)
    return buf.raw

# crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)
def crypto_stream_chacha20_xor(message,
                               nonce,
                               key):

    mlen = ctypes.c_longlong(len(message))

    c    = ctypes.create_string_buffer(len(message))

    sodium.crypto_stream_chacha20_xor(c,
                                      message,
                                      mlen,
                                      nonce,
                                      key)

    return c.raw

# crypto_aead_chacha20poly1305_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
def crypto_aead_chacha20poly1305_encrypt(message,
                                         ad,
                                         nonce,
                                         key):

    mlen  = ctypes.c_ulonglong(len(message))

    if ad:
        adlen = ctypes.c_ulonglong(len(ad))
    else:
        adlen = ctypes.c_ulonglong(0)

    c    = ctypes.create_string_buffer(mlen.value+16L)
    clen = ctypes.c_ulonglong(0)

    sodium.crypto_aead_chacha20poly1305_encrypt(c,
                                                ctypes.byref(clen),
                                                message,
                                                mlen,
                                                ad,
                                                adlen,
                                                None,
                                                nonce,
                                                key)
    return c.raw

#crypto_aead_chacha20poly1305_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k)
def crypto_aead_chacha20poly1305_decrypt(ciphertext,
                                         ad,
                                         nonce,
                                         key):

    m    = ctypes.create_string_buffer(len(ciphertext)-16L)
    mlen = ctypes.c_ulonglong(0)
    clen = ctypes.c_ulonglong(len(ciphertext))

    if ad:
        adlen = ctypes.c_ulonglong(len(ad))
    else:
        adlen = ctypes.c_ulonglong(0)

    if not sodium.crypto_aead_chacha20poly1305_decrypt(m,
                                                       ctypes.byref(mlen),
                                                       None,
                                                       ciphertext,
                                                       clen,
                                                       ad,
                                                       adlen,
                                                       nonce,
                                                       key) == 0:
        raise ValueError
    else:
        return m.raw

# crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen)
def crypto_generichash(m, k=b'', outlen=crypto_generichash_BYTES):
    buf = ctypes.create_string_buffer(outlen)
    if not sodium.crypto_generichash(buf, ctypes.c_size_t(outlen), m, ctypes.c_ulonglong(len(m)), k, ctypes.c_size_t(len(k))) == 0:
        raise ValueError
    return buf.raw

#crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen);
def crypto_generichash_init(outlen=crypto_generichash_BYTES, k=b''):
    state = ctypes.create_string_buffer(crypto_generichash_state)
    statealign = ctypes.addressof(state) + 63
    statealign ^= statealign & 63
    sodium.crypto_generichash_init(statealign, k, ctypes.c_size_t(len(k)), ctypes.c_size_t(outlen))
    return state

#crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen);
def crypto_generichash_update(state, m):
    statealign = ctypes.addressof(state) + 63
    statealign ^= statealign & 63
    sodium.crypto_generichash_update(statealign, m, ctypes.c_ulonglong(len(m)))
    return state

#crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen);
def crypto_generichash_final(state, outlen=crypto_generichash_BYTES):
    statealign = ctypes.addressof(state) + 63
    statealign ^= statealign & 63
    buf = ctypes.create_string_buffer(outlen)
    sodium.crypto_generichash_final(statealign, buf, ctypes.c_size_t(outlen))
    return buf.raw

def randombytes(size):
    buf = ctypes.create_string_buffer(size)
    sodium.randombytes(buf, ctypes.c_size_t(size))
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

def crypto_sign_detached(m, sk):
    if None in (m, sk): raise ValueError
    sig = ctypes.create_string_buffer(crypto_sign_BYTES)
    # second parm is for output of signature len (optional, ignored if NULL)
    if not sodium.crypto_sign_detached(sig, ctypes.c_void_p(0), m, ctypes.c_ulonglong(len(m)), sk) == 0:
        raise ValueError
    return sig.raw

def crypto_sign_open(sm, pk):
    if None in (sm, pk): raise ValueError
    msg = ctypes.create_string_buffer(len(sm))
    msglen = ctypes.c_ulonglong()
    msglenp = ctypes.pointer(msglen)
    if not sodium.crypto_sign_open(msg, msglenp, sm, ctypes.c_ulonglong(len(sm)), pk) == 0:
        raise ValueError
    return msg.raw[:msglen.value]

def crypto_sign_verify_detached(sig, msg, pk):
    if None in (sig, msg, pk): raise ValueError
    if len(sig) != crypto_sign_BYTES: raise ValueError
    return sodium.crypto_sign_verify_detached(sig, msg, ctypes.c_ulonglong(len(msg)), pk) == 0

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

    # crypto_aead_chacha20poly1305_encrypt
    # http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
    # test vectors
    key = binascii.unhexlify("4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
    input_ = binascii.unhexlify("86d09974840bded2a5ca")
    nonce  = binascii.unhexlify("cd7cf67be39c794a")
    ad     = binascii.unhexlify("87e229d4500845a079c0")
    output = crypto_aead_chacha20poly1305_encrypt(input_,
                                                  ad,
                                                  nonce,
                                                  key)
    print('crypto_aead_chacha20poly1305_encrypt')
    print(binascii.hexlify(output))
    assert output == binascii.unhexlify("e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6")

    # crypto_aead_chacha20poly1305_decrypt
    output = crypto_aead_chacha20poly1305_decrypt(output,
                                                  ad,
                                                  nonce,
                                                  key)
    print('crypto_aead_chacha20poly1305_decrypt')
    print(binascii.hexlify(output))
    assert output == input_



    key = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    nonce = binascii.unhexlify("0001020304050607")
    input_ = '\x00'*256
    output = crypto_stream_chacha20_xor(input_,
                                        nonce,
                                        key)
    print('crypto_stream_chacha20_xor')
    print(binascii.hexlify(output))
    assert output == binascii.unhexlify("f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9")

if __name__ == '__main__':
    test()
