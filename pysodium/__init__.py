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
if not sodium._name:
    raise ValueError('Unable to find libsodium')

sodium.sodium_version_string.restype = ctypes.c_char_p

try:
    sodium_major = int(sodium.sodium_version_string().decode('utf8').split('.')[0])
    sodium_minor = int(sodium.sodium_version_string().decode('utf8').split('.')[1])
    sodium_patch = int(sodium.sodium_version_string().decode('utf8').split('.')[2])
except (IndexError, ValueError):
    raise ValueError('Unable to parse version string from libsodium')

def sodium_version_check(major, minor, patch):
    """Check if the current libsodium version is greater or equal to the supplied one
    """
    if major > sodium_major:
        return False
    if major == sodium_major and minor > sodium_minor:
        return False
    if major == sodium_major and minor == sodium_minor and patch > sodium_patch:
        return False
    return True

def sodium_version(major, minor, patch):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if sodium_version_check(major, minor, patch) == False:
                raise ValueError('Unavailable in this libsodium version')
            return func(*args, **kwargs)
        return wrapper
    return decorator

def encode_strings(func):
    """
    This decorator forces the encoding of str function parameters to UTF-8
    to elliminate the differences between Python 3.x and Python 2.x. The only
    caveat is that bytes and str are both str types in Python 2.x so it is
    possible for the encode() function to fail. It is OK for us to accept that
    failure, hence the pass in the except block.

    Use this decorator on any functions that can take strings as parameters
    such as crypto_pwhash().
    """
    def wrapper(*args, **kwargs):
        largs = []
        for arg in args:
            if isinstance(arg, str):
                try:
                    arg = arg.encode(encoding='utf-8')
                except:
                    pass
            largs.append(arg)
        for k in kwargs.keys():
            if isinstance(kwargs[k], str):
                try:
                    kwargs[k] = kwargs[k].encode(encoding='utf-8')
                except:
                    pass
        return func(*largs, **kwargs)
    return wrapper

sodium.crypto_pwhash_scryptsalsa208sha256_strprefix.restype = ctypes.c_char_p

crypto_auth_KEYBYTES = sodium.crypto_auth_keybytes()
crypto_auth_BYTES = sodium.crypto_auth_bytes()
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
crypto_hash_sha512_BYTES = sodium.crypto_hash_sha512_bytes()
crypto_aead_chacha20poly1305_KEYBYTES = sodium.crypto_aead_chacha20poly1305_keybytes()
crypto_aead_chacha20poly1305_NONCEBYTES = sodium.crypto_aead_chacha20poly1305_npubbytes()
crypto_aead_chacha20poly1305_ABYTES = sodium.crypto_aead_chacha20poly1305_abytes()
if sodium_version_check(1, 0, 9):
    crypto_aead_chacha20poly1305_ietf_KEYBYTES = sodium.crypto_aead_chacha20poly1305_ietf_keybytes()
    crypto_aead_chacha20poly1305_ietf_NONCEBYTES = sodium.crypto_aead_chacha20poly1305_ietf_npubbytes()
    crypto_pwhash_SALTBYTES = sodium.crypto_pwhash_saltbytes()
    crypto_pwhash_STRBYTES = sodium.crypto_pwhash_strbytes()
    crypto_pwhash_OPSLIMIT_INTERACTIVE = sodium.crypto_pwhash_opslimit_interactive()
    crypto_pwhash_MEMLIMIT_INTERACTIVE = sodium.crypto_pwhash_memlimit_interactive()
    crypto_pwhash_OPSLIMIT_MODERATE = sodium.crypto_pwhash_opslimit_moderate()
    crypto_pwhash_MEMLIMIT_MODERATE = sodium.crypto_pwhash_memlimit_moderate()
    crypto_pwhash_OPSLIMIT_SENSITIVE = sodium.crypto_pwhash_opslimit_sensitive()
    crypto_pwhash_MEMLIMIT_SENSITIVE = sodium.crypto_pwhash_memlimit_sensitive()
    crypto_pwhash_ALG_DEFAULT = sodium.crypto_pwhash_alg_default()
else:
    crypto_pwhash_ALG_DEFAULT = None

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
    if n is None:
        raise ValueError("invalid parameters")
    buf = ctypes.create_string_buffer(crypto_scalarmult_BYTES)
    __check(sodium.crypto_scalarmult_curve25519_base(ctypes.byref(buf), n))
    return buf.raw

# crypto_stream_chacha20_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k)
def crypto_stream_chacha20_xor(message, nonce, key):

    mlen = ctypes.c_longlong(len(message))

    c = ctypes.create_string_buffer(len(message))

    __check(sodium.crypto_stream_chacha20_xor(c, message, mlen, nonce, key))

    return c.raw


# crypto_aead_chacha20poly1305_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k);
def crypto_aead_chacha20poly1305_encrypt(message, ad, nonce, key):

    mlen = ctypes.c_ulonglong(len(message))
    adlen = ctypes.c_ulonglong(len(ad))

    c = ctypes.create_string_buffer(mlen.value + 16)
    clen = ctypes.c_ulonglong(0)

    __check(sodium.crypto_aead_chacha20poly1305_encrypt(c, ctypes.byref(clen), message, mlen, ad, adlen, None, nonce, key))
    return c.raw


# crypto_aead_chacha20poly1305_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k)
def crypto_aead_chacha20poly1305_decrypt(ciphertext, ad, nonce, key):

    m = ctypes.create_string_buffer(len(ciphertext) - 16)
    mlen = ctypes.c_ulonglong(0)
    clen = ctypes.c_ulonglong(len(ciphertext))
    adlen = ctypes.c_ulonglong(len(ad))
    __check(sodium.crypto_aead_chacha20poly1305_decrypt(m, ctypes.byref(mlen), None, ciphertext, clen, ad, adlen, nonce, key))
    return m.raw

# crypto_aead_chacha20poly1305_encrypt_detached(unsigned char *c, unsigned char *mac, unsigned long long *maclen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k)
@sodium_version(1, 0, 9)
def crypto_aead_chacha20poly1305_encrypt_detached(message, ad, nonce, key):
    """ Return ciphertext, mac tag """
    
    mlen = ctypes.c_ulonglong(len(message))
    if ad is None:
        adlen = ctypes.c_ulonglong(0)
    else:
        adlen = ctypes.c_ulonglong(len(ad))

    c = ctypes.create_string_buffer(mlen.value)
    maclen_p = ctypes.c_ulonglong(crypto_aead_chacha20poly1305_ABYTES)
    mac = ctypes.create_string_buffer(maclen_p.value)    

    __check(sodium.crypto_aead_chacha20poly1305_encrypt_detached(c, mac, ctypes.byref(maclen_p), message, mlen, ad, adlen, None, nonce, key))
    return c.raw, mac.raw

# crypto_aead_chacha20poly1305_decrypt_detached(unsigned char *m, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *mac, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k)
@sodium_version(1, 0, 9)
def crypto_aead_chacha20poly1305_decrypt_detached(ciphertext, mac, ad, nonce, key):
    """ Return message if successful or -1 (ValueError) if not successful"""
    
    if len(mac) != crypto_aead_chacha20poly1305_ABYTES:
        raise ValueError("mac length != %i" % crypto_aead_chacha20poly1305_ABYTES)
    
    clen = ctypes.c_ulonglong(len(ciphertext))
    m = ctypes.create_string_buffer(clen.value)

    if ad is None:
        adlen = ctypes.c_ulonglong(0)
    else:
        adlen = ctypes.c_ulonglong(len(ad))

    __check(sodium.crypto_aead_chacha20poly1305_decrypt_detached(m, None, ciphertext, clen, mac, ad, adlen, nonce, key))
    return m.raw
    
# crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c, unsigned long long *clen_p, const unsigned char *m, unsigned long long mlen, const unsigned char *ad, unsigned long long adlen, const unsigned char *nsec, const unsigned char *npub, const unsigned char *k)
@sodium_version(1, 0, 4)
def crypto_aead_chacha20poly1305_ietf_encrypt(message, ad, nonce, key):

    mlen = ctypes.c_ulonglong(len(message))
    adlen = ctypes.c_ulonglong(len(ad))
    c = ctypes.create_string_buffer(mlen.value + 16)
    clen = ctypes.c_ulonglong(0)

    __check(sodium.crypto_aead_chacha20poly1305_ietf_encrypt(c, ctypes.byref(clen), message, mlen, ad, adlen, None, nonce, key))
    return c.raw

# crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m, unsigned long long *mlen, unsigned char *nsec, const unsigned char *c, unsigned long long clen, const unsigned char *ad, unsigned long long adlen, const unsigned char *npub, const unsigned char *k)
@sodium_version(1, 0, 4)
def crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext, ad, nonce, key):

    m = ctypes.create_string_buffer(len(ciphertext) - 16)
    mlen = ctypes.c_ulonglong(0)
    clen = ctypes.c_ulonglong(len(ciphertext))
    adlen = ctypes.c_ulonglong(len(ad))
    __check(sodium.crypto_aead_chacha20poly1305_ietf_decrypt(m, ctypes.byref(mlen), None, ciphertext, clen, ad, adlen, nonce, key))
    return m.raw

# crypto_auth(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
def crypto_auth(m, k=b''):
    if m is None:
        raise ValueError("invalid parameters")
    buf = ctypes.create_string_buffer(crypto_auth_BYTES)
    __check(sodium.crypto_auth(buf, m, ctypes.c_ulonglong(len(m)), k))
    return buf.raw

# crypto_auth_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k)
def crypto_auth_verify(h, m, k=b''):
    if h is None or m is None:
        raise ValueError("invalid parameters")
    if len(h) != crypto_auth_BYTES:
        raise ValueError("invalid tag")
    __check(sodium.crypto_auth_verify(h, m, ctypes.c_ulonglong(len(m)), k))

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

def crypto_box_beforenm(pk, sk):
    if pk is None or sk is None:
        raise ValueError("invalid parameters")
    c = ctypes.create_string_buffer(crypto_secretbox_KEYBYTES)
    __check(sodium.crypto_box_beforenm(c, pk, sk))
    return c.raw

def crypto_box(msg, nonce, pk, sk):
    if None in (msg, nonce, pk, sk):
        raise ValueError("invalid parameters")
    c = ctypes.create_string_buffer(crypto_box_MACBYTES + len(msg))
    __check(sodium.crypto_box_easy(c, msg, ctypes.c_ulonglong(len(msg)), nonce, pk, sk))
    return c.raw

def crypto_box_afternm(msg, nonce, k):
    if None in (msg, nonce, k):
        raise ValueError("invalid parameters")
    c = ctypes.create_string_buffer(crypto_box_MACBYTES + len(msg))
    __check(sodium.crypto_box_easy_afternm(c, msg, ctypes.c_ulonglong(len(msg)), nonce, k))
    return c.raw

def crypto_box_open(c, nonce, pk, sk):
    if None in (c, nonce, pk, sk):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(c) - crypto_box_MACBYTES)
    __check(sodium.crypto_box_open_easy(msg, c, ctypes.c_ulonglong(len(c)), nonce, pk, sk))
    return msg.raw

def crypto_box_open_afternm(c, nonce, k):
    if None in (c, nonce, k):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(c) - crypto_box_MACBYTES)
    __check(sodium.crypto_box_open_easy_afternm(msg, c, ctypes.c_ulonglong(len(c)), nonce, k))
    return msg.raw

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

@sodium_version(1, 0, 3)
def crypto_box_seal(msg, k):
    if msg is None or k is None:
        raise ValueError("invalid parameters")
    c = ctypes.create_string_buffer(len(msg)+crypto_box_SEALBYTES)
    __check(sodium.crypto_box_seal(c, msg, ctypes.c_ulonglong(len(msg)), k))
    return c.raw

# int crypto_box_seal_open(unsigned char *m, const unsigned char *c,
#                         unsigned long long clen,
#                         const unsigned char *pk, const unsigned char *sk);

@sodium_version(1, 0, 3)
def crypto_box_seal_open(c, pk, sk):
    if None in (c, pk, sk):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(c)-crypto_box_SEALBYTES)
    __check(sodium.crypto_box_seal_open(msg, c, ctypes.c_ulonglong(len(c)), pk, sk))
    return msg.raw


# int crypto_box_detached(unsigned char *c, unsigned char *mac,
#                        const unsigned char *m, unsigned long long mlen,
#                        const unsigned char *n, const unsigned char *pk,
#                        const unsigned char *sk);

def crypto_box_detached(msg, nonce, pk, sk):
        if None in (msg, nonce, pk, sk):
            raise ValueError("invalid parameters")
        c = ctypes.create_string_buffer(len(msg))
        mac = ctypes.create_string_buffer(crypto_box_MACBYTES)
        __check(sodium.crypto_box_detached(c, mac, msg.encode(), ctypes.c_ulonglong(len(msg)), nonce, pk, sk))
        return c.raw, mac.raw

# int crypto_box_open_detached(unsigned char *m, const unsigned char *c,
#                             const unsigned char *mac,
#                             unsigned long long clen,
#                             const unsigned char *n,
#                             const unsigned char *pk,
#                             const unsigned char *sk);

def crypto_box_open_detached(c, mac, nonce, pk, sk):
    if None in (c, mac, nonce, pk, sk):
        raise ValueError("invalid parameters")
    msg = ctypes.create_string_buffer(len(c))
    __check(sodium.crypto_box_open_detached(msg, c, mac, ctypes.c_ulonglong(len(c)), nonce, pk, sk))
    return msg.raw.decode()

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
    if m is None or sk is None:
        raise ValueError("invalid parameters")
    smsg = ctypes.create_string_buffer(len(m) + crypto_sign_BYTES)
    smsglen = ctypes.c_ulonglong()
    __check(sodium.crypto_sign(smsg, ctypes.byref(smsglen), m, ctypes.c_ulonglong(len(m)), sk))
    return smsg.raw


def crypto_sign_detached(m, sk):
    if m is None or sk is None:
        raise ValueError("invalid parameters")
    sig = ctypes.create_string_buffer(crypto_sign_BYTES)
    # second parm is for output of signature len (optional, ignored if NULL)
    __check(sodium.crypto_sign_detached(sig, ctypes.c_void_p(0), m, ctypes.c_ulonglong(len(m)), sk))
    return sig.raw


def crypto_sign_open(sm, pk):
    if sm is None or pk is None:
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


def crypto_sign_pk_to_box_pk(pk):
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

def crypto_sign_sk_to_seed(sk):
    if sk is None:
        raise ValueError
    seed = ctypes.create_string_buffer(crypto_sign_SEEDBYTES)
    __check(sodium.crypto_sign_ed25519_sk_to_seed(ctypes.byref(seed), sk))
    return seed.raw

# int crypto_pwhash(unsigned char * const out,
#                   unsigned long long outlen,
#                   const char * const passwd,
#                   unsigned long long passwdlen,
#                   const unsigned char * const salt,
#                   unsigned long long opslimit,
#                   size_t memlimit, int alg);
@sodium_version(1, 0, 9)
@encode_strings
def crypto_pwhash(outlen, passwd, salt, opslimit, memlimit, alg=crypto_pwhash_ALG_DEFAULT):
    if None in (outlen, passwd, salt, opslimit, memlimit):
        raise ValueError("invalid parameters")
    out = ctypes.create_string_buffer(outlen)
    __check(sodium.crypto_pwhash(ctypes.byref(out), ctypes.c_ulonglong(outlen), passwd, ctypes.c_ulonglong(len(passwd)), salt, ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit), ctypes.c_int(alg)))
    return out.raw

# int crypto_pwhash_str(char out[crypto_pwhash_STRBYTES],
#                       const char * const passwd,
#                       unsigned long long passwdlen,
#                       unsigned long long opslimit,
#                       size_t memlimit);
@sodium_version(1, 0, 9)
@encode_strings
def crypto_pwhash_str(passwd, opslimit, memlimit):
    if None in (passwd, opslimit, memlimit):
        raise ValueError("invalid parameters")
    out = ctypes.create_string_buffer(crypto_pwhash_STRBYTES)
    __check(sodium.crypto_pwhash_str(ctypes.byref(out), passwd, ctypes.c_ulonglong(len(passwd)), ctypes.c_ulonglong(opslimit), ctypes.c_size_t(memlimit)))
    return out.raw

# int crypto_pwhash_str_verify(const char str[crypto_pwhash_STRBYTES],
#                              const char * const passwd,
#                              unsigned long long passwdlen);
@sodium_version(1, 0, 9)
@encode_strings
def crypto_pwhash_str_verify(pstr, passwd):
    if None in (pstr, passwd) or len(pstr) != crypto_pwhash_STRBYTES:
        raise ValueError("invalid parameters")
    return sodium.crypto_pwhash_str_verify(pstr, passwd, ctypes.c_ulonglong(len(passwd))) == 0

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
    if stored is None or passwd is None:
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

# int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
#                       unsigned long long inlen);
def crypto_hash_sha512(message):
    if message is None:
        raise ValueError("invalid parameters")
    out = ctypes.create_string_buffer(crypto_hash_sha512_BYTES).raw
    __check(sodium.crypto_hash_sha512(out, message.encode(), ctypes.c_ulonglong(len(message))))
    return out
