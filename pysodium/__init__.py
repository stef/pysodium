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
import ctypes.util

sodium = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium') or ctypes.util.find_library('libsodium'))
sodium.crypto_pwhash_scryptsalsa208sha256_strprefix.restype = ctypes.c_char_p
sodium.sodium_version_string.restype = ctypes.c_char_p
crypto_aead_chacha20poly1305_KEYBYTES = sodium.crypto_aead_chacha20poly1305_keybytes()
crypto_aead_chacha20poly1305_NONCEBYTES = sodium.crypto_aead_chacha20poly1305_npubbytes()
crypto_aead_chacha20poly1305_ietf_KEYBYTES = sodium.crypto_aead_chacha20poly1305_ietf_keybytes()
crypto_aead_chacha20poly1305_ietf_NONCEBYTES = sodium.crypto_aead_chacha20poly1305_ietf_npubbytes()
crypto_box_NONCEBYTES = sodium.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = sodium.crypto_box_publickeybytes()
crypto_box_SECRETKEYBYTES = sodium.crypto_box_secretkeybytes()
crypto_box_ZEROBYTES = sodium.crypto_box_zerobytes()
crypto_box_BOXZEROBYTES = sodium.crypto_box_boxzerobytes()
crypto_box_MACBYTES = sodium.crypto_box_macbytes()
crypto_box_SEALBYTES = sodium.crypto_box_sealbytes()
crypto_box_SEEDBYTES = sodium.crypto_box_seedbytes()
crypto_secretbox_KEYBYTES = sodium.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = sodium.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES = sodium.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES = sodium.crypto_secretbox_boxzerobytes()
crypto_secretbox_MACBYTES = sodium.crypto_secretbox_macbytes()
crypto_sign_PUBLICKEYBYTES = sodium.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = sodium.crypto_sign_secretkeybytes()
crypto_sign_SEEDBYTES = sodium.crypto_sign_seedbytes()
crypto_sign_BYTES = sodium.crypto_sign_bytes()
crypto_sign_ed25519_SECRETKEYBYTES = sodium.crypto_sign_ed25519_secretkeybytes()
crypto_sign_ed25519_PUBLICKEYBYTES = sodium.crypto_sign_ed25519_publickeybytes()
crypto_stream_KEYBYTES = sodium.crypto_stream_keybytes()
crypto_stream_NONCEBYTES = sodium.crypto_stream_noncebytes()
crypto_generichash_BYTES = sodium.crypto_generichash_bytes()
crypto_scalarmult_curve25519_BYTES = sodium.crypto_scalarmult_curve25519_bytes()
crypto_scalarmult_BYTES = sodium.crypto_scalarmult_bytes()
crypto_generichash_blake2b_KEYBYTES_MAX = sodium.crypto_generichash_blake2b_keybytes_max()
crypto_generichash_blake2b_BYTES = sodium.crypto_generichash_blake2b_bytes()
crypto_generichash_blake2b_BYTES_MIN = sodium.crypto_generichash_blake2b_bytes_min()
crypto_generichash_blake2b_BYTES_MAX = sodium.crypto_generichash_blake2b_bytes_max()
crypto_generichash_blake2b_SALTBYTES = sodium.crypto_generichash_blake2b_saltbytes()
crypto_generichash_blake2b_PERSONALBYTES = sodium.crypto_generichash_blake2b_personalbytes()
crypto_pwhash_scryptsalsa208sha256_SALTBYTES = sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes()
crypto_pwhash_scryptsalsa208sha256_STRBYTES = sodium.crypto_pwhash_scryptsalsa208sha256_strbytes()
crypto_pwhash_scryptsalsa208sha256_STRPREFIX = sodium.crypto_pwhash_scryptsalsa208sha256_strprefix()
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE = sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive()
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE = sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive()
crypto_hash_sha256_BYTES = sodium.crypto_hash_sha256_bytes()

class CryptoGenericHashState(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('h', ctypes.c_uint64 * 8),
        ('t', ctypes.c_uint64 * 2),
        ('f', ctypes.c_uint64 * 2),
        ('buf', ctypes.c_uint8 * 2 * 128),
        ('buflen', ctypes.c_size_t),
        ('last_node', ctypes.c_uint8)
    ]


def __check(code):
    if code != 0:
        raise ValueError


def pad_buf(buf, length, name = 'buf'):
    buflen = len(buf)
    if buflen > length:
        raise ValueError("Cannot pad %s (len: %d - expected %d or less)" % (name, buflen, length))

    padding = length - buflen
    if padding > 0:
        return buf + b"\x00"*padding
    else:
        return buf

def crypto_scalarmult_curve25519(n, p):
    buf = ctypes.create_string_buffer(crypto_scalarmult_BYTES)
    __check(sodium.crypto_scalarmult_curve25519(buf, n, p))
    return buf.raw


def crypto_scalarmult_curve25519_base(n):
    buf = ctypes.create_string_buffer(crypto_scalarmult_BYTES)
    __check(sodium.crypto_scalarmult_curve25519_base(buf, n))
    return buf.raw


# crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)
def crypto_stream_chacha20_xor(message, nonce, key):

    mlen = ctypes.c_longlong(len(message))

    c = ctypes.create_string_buffer(len(message))

    __check(sodium.crypto_stream_chacha20_xor(c, message, mlen, nonce, key))

    return c.raw


# crypto_aead_chacha20poly1305_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
def crypto_aead_chacha20poly1305_encrypt(message, ad, nonce, key):

    if ad == None: raise ValueError("ad cannot be None")
    mlen = ctypes.c_ulonglong(len(message))

    if ad:
        adlen = ctypes.c_ulonglong(len(ad))
    else:
        adlen = ctypes.c_ulonglong(0)

    c = ctypes.create_string_buffer(mlen.value + 16)
    clen = ctypes.c_ulonglong(0)

    __check(sodium.crypto_aead_chacha20poly1305_encrypt(c, ctypes.byref(clen), message, mlen, ad, adlen, None, nonce, key))
    return c.raw


# crypto_aead_chacha20poly1305_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k)
def crypto_aead_chacha20poly1305_decrypt(ciphertext, ad, nonce, key):

    if ad == None: raise ValueError("ad cannot be None")
    m = ctypes.create_string_buffer(len(ciphertext) - 16)
    mlen = ctypes.c_ulonglong(0)
    clen = ctypes.c_ulonglong(len(ciphertext))
    adlen = ctypes.c_ulonglong(len(ad))
    __check(sodium.crypto_aead_chacha20poly1305_decrypt(m, ctypes.byref(mlen), None, ciphertext, clen, ad, adlen, nonce, key))
    return m.raw

# crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k)
def crypto_aead_chacha20poly1305_ietf_encrypt(message, ad, nonce, key):

    if ad == None: raise ValueError("ad cannot be None")
    mlen = ctypes.c_ulonglong(len(message))

    if ad:
        adlen = ctypes.c_ulonglong(len(ad))
    else:
        adlen = ctypes.c_ulonglong(0)

    c = ctypes.create_string_buffer(mlen.value + 16)
    clen = ctypes.c_ulonglong(0)

    __check(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, ctypes.byref(clen), message, mlen, ad, adlen, None, nonce, key))
    return c.raw

# crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k)
def crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext, ad, nonce, key):

    if ad == None: raise ValueError("ad cannot be None")
    m = ctypes.create_string_buffer(len(ciphertext) - 16)
    mlen = ctypes.c_ulonglong(0)
    clen = ctypes.c_ulonglong(len(ciphertext))
    adlen = ctypes.c_ulonglong(len(ad))
    __check(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m, ctypes.byref(mlen), None, ciphertext, clen, ad, adlen, nonce, key))
    return m.raw

# crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in, unsigned long long inlen, const unsigned char *key, size_t keylen)
def crypto_generichash(m, k=b'', outlen=crypto_generichash_BYTES):
    buf = ctypes.create_string_buffer(outlen)
    __check(sodium.crypto_generichash(buf, ctypes.c_size_t(outlen), m, ctypes.c_ulonglong(len(m)), k, ctypes.c_size_t(len(k))))
    return buf.raw


# crypto_generichash_init(crypto_generichash_state *state, const unsigned char *key, const size_t keylen, const size_t outlen);
def crypto_generichash_init(outlen=crypto_generichash_BYTES, k=b''):
    state = CryptoGenericHashState()
    __check(sodium.crypto_generichash_init(ctypes.byref(state), k, ctypes.c_size_t(len(k)), ctypes.c_size_t(outlen)))
    return state


# crypto_generichash_update(crypto_generichash_state *state, const unsigned char *in, unsigned long long inlen);
def crypto_generichash_update(state, m):
    assert isinstance(state, CryptoGenericHashState)
    __check(sodium.crypto_generichash_update(ctypes.byref(state), m, ctypes.c_ulonglong(len(m))))
    return state


# crypto_generichash_final(crypto_generichash_state *state, unsigned char *out, const size_t outlen);
def crypto_generichash_final(state, outlen=crypto_generichash_BYTES):
    assert isinstance(state, CryptoGenericHashState)
    buf = ctypes.create_string_buffer(outlen)
    __check(sodium.crypto_generichash_final(ctypes.byref(state), buf, ctypes.c_size_t(outlen)))
    return buf.raw

def crypto_generichash_blake2b_salt_personal(message, outlen = crypto_generichash_blake2b_BYTES, key = b'', salt = b'', personal = b''):
    keylen   = len(key)

    if keylen != 0 and not crypto_generichash_blake2b_BYTES_MIN <= keylen <= crypto_generichash_blake2b_KEYBYTES_MAX:
        raise ValueError("%d <= len(key) <= %d - %d recieved" % (crypto_generichash_blake2b_BYTES_MIN, crypto_generichash_blake2b_KEYBYTES_MAX, keylen))

    salt     = pad_buf(salt, crypto_generichash_blake2b_SALTBYTES, 'salt')
    personal = pad_buf(personal, crypto_generichash_blake2b_PERSONALBYTES, 'personal')

    buf      = ctypes.create_string_buffer(outlen)
    outlen   = ctypes.c_size_t(outlen)
    inlen    = ctypes.c_ulonglong(len(message))
    keylen   = ctypes.c_size_t(keylen)

    __check(sodium.crypto_generichash_blake2b_salt_personal(buf, outlen, message, inlen, key, keylen, salt, personal))
    return buf.raw


def randombytes(size):
    buf = ctypes.create_string_buffer(size)
    sodium.randombytes(buf, ctypes.c_ulonglong(size))
    return buf.raw


def crypto_box_keypair():
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)
    __check(sodium.crypto_box_keypair(pk, sk))
    return pk.raw, sk.raw

# int crypto_box_seed_keypair(unsigned char *pk, unsigned char *sk,
#                                const unsigned char *seed);
def crypto_box_seed_keypair(seed):
    if seed is None:
        raise ValueError("invalid parameters")
    pk = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)
    __check(sodium.crypto_box_seed_keypair(pk, sk, seed))
    return pk.raw, sk.raw

# int crypto_box_easy(unsigned char *c, const unsigned char *m,
#                        unsigned long long mlen, const unsigned char *n,
#                        const unsigned char *pk, const unsigned char *sk);
def crypto_box_easy(msg, nonce, pk, sk):
    if None in (msg, nonce, pk, sk):
        raise ValueError("invalid parameters")
    c = ctypes.create_string_buffer(crypto_box_MACBYTES + len(msg))
    __check(sodium.crypto_box_easy(c, msg, ctypes.c_ulonglong(len(msg)), nonce, pk, sk))
    return c.raw

# int crypto_box_open_easy(unsigned char *m, const unsigned char *c,
#                         unsigned long long clen, const unsigned char *n,
#                         const unsigned char *pk, const unsigned char *sk);
def crypto_box_open_easy(c, nonce, pk, sk):
    if None in (c, nonce, pk, sk):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(c) - crypto_box_MACBYTES)
    __check(sodium.crypto_box_open_easy(msg, c, ctypes.c_ulonglong(len(c)), nonce, pk, sk))
    return msg.raw

def crypto_box(msg, nonce, pk, sk):
    if None in (msg, nonce, pk, sk):
        raise ValueError("invalid parameters")
    padded = b"\x00" * crypto_box_ZEROBYTES + msg
    c = ctypes.create_string_buffer(len(padded))
    __check(sodium.crypto_box(c, padded, ctypes.c_ulonglong(len(padded)), nonce, pk, sk))
    return c.raw[crypto_box_BOXZEROBYTES:]


def crypto_box_open(c, nonce, pk, sk):
    if None in (c, nonce, pk, sk):
        raise ValueError("invalid parameters")
    padded = b"\x00" * crypto_box_BOXZEROBYTES + c
    msg = ctypes.create_string_buffer(len(padded))
    __check(sodium.crypto_box_open(msg, padded, ctypes.c_ulonglong(len(padded)), nonce, pk, sk))
    return msg.raw[crypto_box_ZEROBYTES:]


def crypto_secretbox(msg, nonce, k):
    if None in (msg, nonce, k):
        raise ValueError("invalid parameters")
    padded = b"\x00" * crypto_secretbox_ZEROBYTES + msg
    c = ctypes.create_string_buffer(len(padded))
    __check(sodium.crypto_secretbox(c, padded, ctypes.c_ulonglong(len(padded)), nonce, k))
    return c.raw[crypto_secretbox_BOXZEROBYTES:]


def crypto_secretbox_open(c, nonce, k):
    if None in (c, nonce, k):
        raise ValueError("invalid parameters")
    padded = b"\x00" * crypto_secretbox_BOXZEROBYTES + c
    msg = ctypes.create_string_buffer(len(padded))
    __check(sodium.crypto_secretbox_open(msg, padded, ctypes.c_ulonglong(len(padded)), nonce, k))
    return msg.raw[crypto_secretbox_ZEROBYTES:]

# int crypto_box_seal(unsigned char *c, const unsigned char *m,
#                    unsigned long long mlen, const unsigned char *pk);

def crypto_box_seal(msg, k):
    if None in (msg, k):
        raise ValueError("invalid parameters")
    c = ctypes.create_string_buffer(len(msg)+crypto_box_SEALBYTES)
    __check(sodium.crypto_box_seal(c, msg, ctypes.c_ulonglong(len(msg)), k))
    return c.raw

# int crypto_box_seal_open(unsigned char *m, const unsigned char *c,
#                         unsigned long long clen,
#                         const unsigned char *pk, const unsigned char *sk);

def crypto_box_seal_open(c, pk, sk):
    if None in (c, pk, sk):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(c)-crypto_box_SEALBYTES)
    __check(sodium.crypto_box_seal_open(msg, c, ctypes.c_ulonglong(len(c)), pk, sk))
    return msg.raw

def crypto_sign_keypair():
    pk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    __check(sodium.crypto_sign_keypair(pk, sk))
    return pk.raw, sk.raw


def crypto_sign_seed_keypair(seed):
    pk = ctypes.create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = ctypes.create_string_buffer(crypto_sign_SECRETKEYBYTES)
    __check(sodium.crypto_sign_seed_keypair(pk, sk, seed))
    return pk.raw, sk.raw


def crypto_sign(m, sk):
    if None in (m, sk):
        raise ValueError("invalid parameters")
    smsg = ctypes.create_string_buffer(len(m) + crypto_sign_BYTES)
    smsglen = ctypes.c_ulonglong()
    __check(sodium.crypto_sign(smsg, ctypes.byref(smsglen), m, ctypes.c_ulonglong(len(m)), sk))
    return smsg.raw


def crypto_sign_detached(m, sk):
    if None in (m, sk):
        raise ValueError("invalid parameters")
    sig = ctypes.create_string_buffer(crypto_sign_BYTES)
    # second parm is for output of signature len (optional, ignored if NULL)
    __check(sodium.crypto_sign_detached(sig, ctypes.c_void_p(0), m, ctypes.c_ulonglong(len(m)), sk))
    return sig.raw


def crypto_sign_open(sm, pk):
    if None in (sm, pk):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(sm))
    msglen = ctypes.c_ulonglong()
    __check(sodium.crypto_sign_open(msg, ctypes.byref(msglen), sm, ctypes.c_ulonglong(len(sm)), pk))
    return msg.raw[:msglen.value]


def crypto_sign_verify_detached(sig, msg, pk):
    if None in (sig, msg, pk):
        raise ValueError
    if len(sig) != crypto_sign_BYTES:
        raise ValueError("invalid sign")
    __check(sodium.crypto_sign_verify_detached(sig, msg, ctypes.c_ulonglong(len(msg)), pk))


# int crypto_stream_salsa20(unsigned char *c, unsigned long long clen,
#                           const unsigned char *n, const unsigned char *k);
def crypto_stream(cnt, nonce=None, key=None):
    res = ctypes.create_string_buffer(cnt)
    if not nonce:
        nonce = randombytes(crypto_stream_NONCEBYTES)
    if not key:
        key = randombytes(crypto_stream_KEYBYTES)
    __check(sodium.crypto_stream(res, ctypes.c_ulonglong(cnt), nonce, key))
    return res.raw


# crypto_stream_salsa20_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen,
#                           const unsigned char *n, const unsigned char *k)
def crypto_stream_xor(msg, cnt, nonce=None, key=None):
    res = ctypes.create_string_buffer(cnt)
    if not nonce:
        nonce = randombytes(crypto_stream_NONCEBYTES)
    if not key:
        key = randombytes(crypto_stream_KEYBYTES)
    __check(sodium.crypto_stream_xor(res, msg, ctypes.c_ulonglong(cnt), nonce, key))
    return res.raw


def crypt_sign_pk_to_box_pk(pk):
    if pk is None:
        raise ValueError
    res = ctypes.create_string_buffer(crypto_box_PUBLICKEYBYTES)
    __check(sodium.crypto_sign_ed25519_pk_to_curve25519(ctypes.byref(res), pk))
    return res.raw


def crypto_sign_sk_to_box_sk(sk):
    if sk is None:
        raise ValueError
    res = ctypes.create_string_buffer(crypto_box_SECRETKEYBYTES)
    __check(sodium.crypto_sign_ed25519_sk_to_curve25519(ctypes.byref(res), sk))
    return res.raw

# int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
#                                        unsigned long long outlen,
#                                        const char * const passwd,
#                                        unsigned long long passwdlen,
#                                        const unsigned char * const salt,
#                                        unsigned long long opslimit,
#                                        size_t memlimit);
def crypto_pwhash_scryptsalsa208sha256(outlen, passwd, salt, opslimit, memlimit):
    if None in (outlen, passwd, salt, opslimit, memlimit):
        raise ValueError
    out = ctypes.create_string_buffer(outlen)
    __check(sodium.crypto_pwhash_scryptsalsa208sha256(out, ctypes.c_ulonglong(outlen), passwd, ctypes.c_ulonglong(len(passwd)), salt, ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit)))
    return out.raw

# int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
#                                            const char * const passwd,
#                                            unsigned long long passwdlen,
#                                            unsigned long long opslimit,
#                                            size_t memlimit);
def crypto_pwhash_scryptsalsa208sha256_str(passwd, opslimit, memlimit):
    if None in (passwd, opslimit, memlimit):
        raise ValueError
    out = ctypes.create_string_buffer(crypto_pwhash_scryptsalsa208sha256_STRBYTES)
    __check(sodium.crypto_pwhash_scryptsalsa208sha256_str(out, passwd, ctypes.c_ulonglong(len(passwd)), ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit)))
    return out.value

#int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
#                                                  const char * const passwd,
#                                                  unsigned long long passwdlen);
def crypto_pwhash_scryptsalsa208sha256_str_verify(stored, passwd):
    if None in (stored, passwd):
       raise ValueError
    __check(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(stored, passwd, ctypes.c_ulonglong(len(passwd))))

# int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
def crypto_sign_sk_to_pk(sk):
    if sk is None or len(sk) != crypto_sign_ed25519_SECRETKEYBYTES:
        raise ValueError
    res = ctypes.create_string_buffer(crypto_sign_ed25519_PUBLICKEYBYTES)
    __check(sodium.crypto_sign_ed25519_sk_to_pk(ctypes.byref(res), sk))
    return res.raw

# int crypto_hash_sha256(unsigned char *out, const unsigned char *in,
#                       unsigned long long inlen);
def crypto_hash_sha256(message):
    if message is None:
        raise ValueError("invalid parameters")
    out = ctypes.create_string_buffer(crypto_hash_sha256_BYTES).raw
    __check(sodium.crypto_hash_sha256(out, message.encode(), ctypes.c_ulonglong(len(message))))
    return out
