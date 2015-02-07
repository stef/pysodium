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

import pysodium
import unittest
import binascii


class TestPySodium(unittest.TestCase):
    def test_crypto_stream(self):
        pysodium.crypto_stream(8)
        pysodium.crypto_stream(16)
        pysodium.crypto_stream(32)

    def test_crypto_stream_xor(self):
        pysodium.crypto_stream_xor(b'howdy', len(b'howdy'))
        pysodium.crypto_stream_xor(b'howdy' * 16, len(b'howdy') * 16)

    def test_crypto_generichash(self):
        pysodium.crypto_generichash(b'howdy')
        pysodium.crypto_generichash(b'howdy', outlen=4)
        pysodium.crypto_generichash(b'howdy', outlen=6)
        pysodium.crypto_generichash(b'howdy', outlen=8)
        state = pysodium.crypto_generichash_init()
        pysodium.crypto_generichash_update(state, b'howdy')
        pysodium.crypto_generichash_final(state)

        state = pysodium.crypto_generichash_init(outlen=6)
        pysodium.crypto_generichash_update(state, b'howdy')
        pysodium.crypto_generichash_final(state, outlen=6)

    def test_crypto_box_open(self):
        pk, sk = pysodium.crypto_box_keypair()
        n = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        c = pysodium.crypto_box(b"howdy", n, pk, sk)
        pysodium.crypto_box_open(c, n, pk, sk)

    def test_crypto_secretbox_open(self):
        k = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
        n = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
        c = pysodium.crypto_secretbox(b"howdy", n, k)
        pysodium.crypto_secretbox_open(c, n, k)

    def test_crypto_scalarmut_curve25519_base(self):
        s = pysodium.crypto_scalarmult_curve25519_base(pysodium.randombytes(pysodium.crypto_scalarmult_BYTES))
        r = pysodium.crypto_scalarmult_curve25519_base(pysodium.randombytes(pysodium.crypto_scalarmult_BYTES))
        pysodium.crypto_scalarmult_curve25519(s, r)

    def test_crypto_sign_open(self):
        pk, sk = pysodium.crypto_sign_keypair()
        signed = pysodium.crypto_sign(b'howdy', sk)
        changed = signed[:pysodium.crypto_sign_BYTES] + b'0' + signed[pysodium.crypto_sign_BYTES + 1:]
        pysodium.crypto_sign_open(signed, pk)
        self.assertRaises(ValueError, pysodium.crypto_sign_open, changed, pk)

    def test_crypto_sign_seed_keypair(self):
        seed = pysodium.crypto_generichash(b'howdy', outlen=pysodium.crypto_sign_SEEDBYTES)
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)
        pk2, sk2 = pysodium.crypto_sign_seed_keypair(seed)
        self.assertEqual(pk, pk2)
        self.assertEqual(sk, sk2)

    def test_aead_chacha20poly1305(self):
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"cd7cf67be39c794a")
        ad = binascii.unhexlify(b"87e229d4500845a079c0")
        output = pysodium.crypto_aead_chacha20poly1305_encrypt(input_, ad, nonce, key)
        self.assertEqual(binascii.unhexlify(b"e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6"), output)
        output = pysodium.crypto_aead_chacha20poly1305_decrypt(output, ad, nonce, key)
        self.assertEqual(output, input_)

    def test_crypto_stream_chacha20_xor(self):
        key = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = binascii.unhexlify(b"0001020304050607")
        input_ = b'\x00' * 256
        output = pysodium.crypto_stream_chacha20_xor(input_, nonce, key)
        self.assertEqual(binascii.unhexlify(b"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9"),
                         output)

    def test_crypto_pwhash_scryptsalsa208sha256(self):
        passwd = "howdy"
        outlen = 128
        salt = pysodium.randombytes(pysodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
        output = pysodium.crypto_pwhash_scryptsalsa208sha256(outlen, passwd, salt)
        self.assertEqual(128, len(output))
        salt = b'12345678901234567890123456789012'
        output = pysodium.crypto_pwhash_scryptsalsa208sha256(outlen, passwd, salt)
        self.assertEqual(binascii.unhexlify(b'6af52bde42cb37deae6661ba684c78d006ed450542e812a7133f14d052fb59bd400476d2787834df1ab47576cb18da4881e5cea2cba4b676e2abc5411af80d5ddcf36217b43b3eab50a0067e820b5bcc215be0fc6ff016a717ff876304d51a87af7e8d0113f737a268e94a76abd4e690b0012a688e895e7edb93a030cd341b4f'), output)

if __name__ == '__main__':
    unittest.main()
