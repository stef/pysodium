#!/usr/bin/env python2
"""
CFFI interface to libsodium library

Copyright (c) 2013, Donald Stufft and individual contributors.
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
from __future__ import absolute_import
from __future__ import division

import functools

from cffi import FFI


__all__ = ["ffi", "lib"]


ffi = FFI()
ffi.cdef(
    # Secret Key Encryption
    """
        static const int crypto_secretbox_KEYBYTES;
        static const int crypto_secretbox_NONCEBYTES;
        static const int crypto_secretbox_ZEROBYTES;
        static const int crypto_secretbox_BOXZEROBYTES;
        static const int crypto_secretbox_KEYBYTES;

        int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
    """

    # Public Key Encryption - Signatures
    """
        static const int crypto_sign_PUBLICKEYBYTES;
        static const int crypto_sign_SECRETKEYBYTES;
        static const int crypto_sign_BYTES;

        int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, unsigned char *seed);
        int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
        int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
        int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
    """

    # Public Key Encryption
    """
        static const int crypto_box_PUBLICKEYBYTES;
        static const int crypto_box_SECRETKEYBYTES;
        static const int crypto_box_BEFORENMBYTES;
        static const int crypto_box_NONCEBYTES;
        static const int crypto_box_ZEROBYTES;
        static const int crypto_box_BOXZEROBYTES;

        int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
        int crypto_box(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk);
        int crypto_box_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk);
        int crypto_box_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_box_open_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
        int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk);
    """

    # Hashing
    """
        static const int crypto_generichash_BYTES;
        static const int crypto_generichash_BYTES_MIN;
        static const int crypto_generichash_KEYBYTES;
        static const int crypto_generichash_KEYBYTES_MIN;
        static const int crypto_generichash_KEYBYTES_MAX;
        static const int crypto_generichash_BLOCKBYTES;

        typedef struct crypto_generichash_blake2b_state {
            uint64_t h[8];
            uint64_t t[2];
            uint64_t f[2];
            uint8_t  buf[256];
            size_t   buflen;
            uint8_t  last_node;
            ...;
        } crypto_generichash_state;
        int crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen);
        int crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen);
        int crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen);
        int crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen);
    """

    # Secure Random
    """
        void randombytes(unsigned char * const buf, const unsigned long long buf_len);
    """

    # Low Level - Scalar Multiplication
    """
        static const int crypto_scalarmult_curve25519_BYTES;
        int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
        int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n, unsigned char *q);
    """

    # Stream  Encryption
    """
        static const int crypto_stream_KEYBYTES;
        static const int crypto_stream_NONCEBYTES;

        int crypto_stream(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
        int crypto_stream_xor(unsigned char *m, unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
    """
)


lib = ffi.verify("#include <sodium.h>", libraries=["sodium"])


# This works around a bug in PyPy where CFFI exposed functions do not have a
#   __name__ attribute. See https://bugs.pypy.org/issue1452
def wraps(wrapped):
    def inner(func):
        if hasattr(wrapped, "__name__"):
            return functools.wraps(wrapped)(func)
        else:
            return func
    return inner


# A lot of the functions in nacl return 0 for success and a negative integer
#   for failure. This is inconvenient in Python as 0 is a falsey value while
#   negative integers are truthy. This wrapper has them return True/False as
#   you'd expect in Python
def wrap_nacl_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return ret == 0
    return wrapper

lib.crypto_secretbox = wrap_nacl_function(lib.crypto_secretbox)
lib.crypto_secretbox_open = wrap_nacl_function(lib.crypto_secretbox_open)

lib.crypto_sign_seed_keypair = wrap_nacl_function(lib.crypto_sign_seed_keypair)
lib.crypto_sign_keypair = wrap_nacl_function(lib.crypto_sign_keypair)
lib.crypto_sign = wrap_nacl_function(lib.crypto_sign)
lib.crypto_sign_open = wrap_nacl_function(lib.crypto_sign_open)

lib.crypto_box_keypair = wrap_nacl_function(lib.crypto_box_keypair)
lib.crypto_box = wrap_nacl_function(lib.crypto_box)
lib.crypto_box_open = wrap_nacl_function(lib.crypto_box_open)
lib.crypto_box_afternm = wrap_nacl_function(lib.crypto_box_afternm)
lib.crypto_box_open_afternm = wrap_nacl_function(lib.crypto_box_open_afternm)
lib.crypto_box_beforenm = wrap_nacl_function(lib.crypto_box_beforenm)

lib.crypto_hash = wrap_nacl_function(lib.crypto_generichash)

lib.crypto_scalarmult_curve25519_base = wrap_nacl_function(lib.crypto_scalarmult_curve25519_base)
lib.crypto_scalarmult_curve25519 = wrap_nacl_function(lib.crypto_scalarmult_curve25519)

lib.randombytes = wrap_nacl_function(lib.randombytes)

lib.crypto_stream_xor = wrap_nacl_function(lib.crypto_stream_xor)
lib.crypto_stream = wrap_nacl_function(lib.crypto_stream)

lib.crypto_generichash = wrap_nacl_function(lib.crypto_generichash)
lib.crypto_generichash_update =  wrap_nacl_function(lib.crypto_generichash_update)
lib.crypto_generichash_final = wrap_nacl_function(lib.crypto_generichash_final)
lib.crypto_generichash_init = wrap_nacl_function(lib.crypto_generichash_init)
