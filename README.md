This is a very simple wrapper around libsodium masquerading as nacl.

This wrapper requires a pre-installed libsodium from:

   https://github.com/jedisct1/libsodium

then it provides access to the following functions:

Constants:

crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES,
crypto_box_SECRETKEYBYTES, crypto_box_ZEROBYTES,
crypto_box_BOXZEROBYTES, crypto_secretbox_KEYBYTES,
crypto_secretbox_NONCEBYTES, crypto_secretbox_KEYBYTES,
crypto_secretbox_ZEROBYTES, crypto_secretbox_BOXZEROBYTES,
crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES,
crypto_stream_KEYBYTES, crypto_stream_NONCEBYTES,
crypto_generichash_BYTES, crypto_scalarmult_curve25519_BYTES,
crypto_scalarmult_BYTES, crypto_sign_BYTES

randombytes(l)

crypto_scalarmult_curve25519(n,p)

crypto_scalarmult_curve25519_base(n)

crypto_generichash(m, k='', outlen=crypto_generichash_BYTES)

crypto_generichash_init(outlen=crypto_generichash_BYTES, k='')

crypto_generichash_update(state, m)

crypto_generichash_final(state, outlen=crypto_generichash_BYTES)

crypto_box_keypair()

crypto_box(msg, nonce, pk, sk)

crypto_box_open(c, nonce, pk, sk)

crypto_secretbox(msg, nonce, k)

crypto_secretbox_open(c, nonce, k)

crypto_sign_keypair()

crypto_sign(m, sk)

crypto_sign_open(sm, pk)

crypto_stream(cnt, nonce = None, key = None)

crypto_stream_xor(msg, cnt, nonce = None, key = None)
