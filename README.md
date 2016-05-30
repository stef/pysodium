This is a very simple wrapper around libsodium masquerading as nacl.

[![Build Status](https://travis-ci.org/stef/pysodium.svg?branch=master)](https://travis-ci.org/stef/pysodium)

This wrapper requires a pre-installed libsodium from:

   https://github.com/jedisct1/libsodium

then it provides access to the following functions:

Constants:

crypto_aead_chacha20poly1305_KEYBYTES, crypto_aead_chacha20poly1305_NONCEBYTES
crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_NONCEBYTES
crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES,
crypto_box_SECRETKEYBYTES, crypto_box_ZEROBYTES,
crypto_box_BOXZEROBYTES, crypto_secretbox_KEYBYTES,
crypto_secretbox_NONCEBYTES, crypto_secretbox_KEYBYTES,
crypto_secretbox_ZEROBYTES, crypto_secretbox_BOXZEROBYTES,
crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES,
crypto_sign_SEEDBYTES,
crypto_stream_KEYBYTES, crypto_stream_NONCEBYTES,
crypto_generichash_BYTES, crypto_scalarmult_curve25519_BYTES,
crypto_scalarmult_BYTES, crypto_sign_BYTES,
crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
crypto_pwhash_scryptsalsa208sha256_STRBYTES,
crypto_pwhash_scryptsalsa208sha256_STRPREFIX,
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE,
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE,
crypto_hash_sha256_BYTES

crypto_scalarmult_curve25519(n, p)

crypto_scalarmult_curve25519_base(n)

crypto_stream_chacha20_xor(message, nonce, key)

crypto_aead_chacha20poly1305_encrypt(message, ad, nonce, key)

crypto_aead_chacha20poly1305_decrypt(ciphertext, ad, nonce, key)

crypto_aead_chacha20poly1305_ietf_encrypt(message, ad, nonce, key)

crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext, ad, nonce, key)

crypto_generichash(m, k=b'', outlen=crypto_generichash_BYTES)

crypto_generichash_init(outlen=crypto_generichash_BYTES, k=b'')

crypto_generichash_update(state, m)

crypto_generichash_final(state, outlen=crypto_generichash_BYTES)

randombytes(size)

crypto_box_keypair()

crypto_box_seed_keypair(seed)

crypto_box(msg, nonce, pk, sk)

crypto_box_open(c, nonce, pk, sk)

crypto_box_easy(msg, nonce, pk, sk)

crypto_box_open_easy(c, nonce, pk, sk)

crypto_box_detached(msg, nonce, pk, sk)

crypto_box_open_detached(c, mac, nonce, pk, sk)

crypto_secretbox(msg, nonce, k)

crypto_secretbox_open(c, nonce, k)

crypto_box_seal(msg, pk)

crypto_box_seal_open(c, pk, sk)

crypto_sign_keypair()

crypto_sign_seed_keypair(seed)

crypto_sign(m, sk)

crypto_sign_detached(m, sk)

crypto_sign_open(sm, pk)

crypto_sign_verify_detached(sig, msg, pk)

crypto_stream(cnt, nonce=None, key=None)

crypto_stream_xor(msg, cnt, nonce=None, key=None)

crypt_sign_pk_to_box_pk(pk)

crypto_sign_sk_to_box_sk(sk)

crypto_sign_sk_to_pk(sk)

crypto_pwhash_scryptsalsa208sha256(outlen, passwd, salt, opslimit, memlimit)

crypto_pwhash_scryptsalsa208sha256_str(passwd, opslimit, memlimit)

crypto_pwhash_scryptsalsa208sha256_str_verify(stored, passwd)

crypto_hash_sha256(message)
