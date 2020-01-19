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

import unittest
import binascii
import pysodium


class TestPySodium(unittest.TestCase):
    def test_crypto_stream(self):
        pysodium.crypto_stream(8)
        pysodium.crypto_stream(16)
        pysodium.crypto_stream(32)

    def test_crypto_stream_xor(self):
        nonce = b'\x00' * pysodium.crypto_stream_NONCEBYTES
        key = b'\x00' * pysodium.crypto_stream_KEYBYTES
        pysodium.crypto_stream_xor(b'howdy', len(b'howdy'), nonce, key)
        pysodium.crypto_stream_xor(b'howdy' * 16, len(b'howdy') * 16, nonce, key)

    def test_crypto_generichash(self):
        r=pysodium.crypto_generichash(b'howdy')
        pysodium.crypto_generichash(b'howdy', outlen=4)
        r6=pysodium.crypto_generichash(b'howdy', outlen=6)
        pysodium.crypto_generichash(b'howdy', outlen=8)
        state = pysodium.crypto_generichash_init()
        pysodium.crypto_generichash_update(state, b'howdy')
        r1=pysodium.crypto_generichash_final(state)

        state = pysodium.crypto_generichash_init(outlen=6)
        pysodium.crypto_generichash_update(state, b'howdy')
        r61=pysodium.crypto_generichash_final(state, outlen=6)
        self.assertEqual(r, r1)
        self.assertEqual(r6, r61)

    def test_crypto_box_pk_from_sk(self):
        pk1, sk = pysodium.crypto_box_keypair()
        pk2 = pysodium.crypto_scalarmult_curve25519_base(sk)
        self.assertEqual(pk1, pk2)

    def test_crypto_box_seal(self):
        if not pysodium.sodium_version_check(1, 0, 3): return
        pk, sk = pysodium.crypto_box_keypair()
        c = pysodium.crypto_box_seal(b"howdy", pk)
        self.assertEqual(pysodium.crypto_box_seal_open(c, pk, sk), b'howdy')

    def test_crypto_box_open(self):
        m = b"howdy"
        pk, sk = pysodium.crypto_box_keypair()
        n = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        c = pysodium.crypto_box(m, n, pk, sk)
        plaintext = pysodium.crypto_box_open(c, n, pk, sk)
        self.assertEqual(m, plaintext)

    def test_crypto_box_open_afternm(self):
        m = b"howdy"
        pk, sk = pysodium.crypto_box_keypair()
        k = pysodium.crypto_box_beforenm(pk, sk)
        n = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        c = pysodium.crypto_box_afternm(m, n, k)
        self.assertEqual(c, c)
        plaintext = pysodium.crypto_box_open_afternm(c, n, k)
        self.assertEqual(m, plaintext)

    def test_crypto_box_open_detached(self):
        pk, sk = pysodium.crypto_box_keypair()
        n = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        c, mac = pysodium.crypto_box_detached(b"howdy", n, pk, sk)
        r = pysodium.crypto_box_open_detached(c, mac, n, pk, sk)
        self.assertEqual(r, b"howdy")
        changed = b"\0"*len(c)
        self.assertRaises(ValueError, pysodium.crypto_box_open_detached,changed, mac, n, pk, sk)

    def test_crypto_secretbox_open(self):
        k = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
        n = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
        c = pysodium.crypto_secretbox(b"howdy", n, k)
        pysodium.crypto_secretbox_open(c, n, k)

    def test_crypto_secretstream_xchacha20poly1305_keygen(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        self.assertEqual(len(key), 32)

    # The following 3 tests verify that no exceptions are raised. Cannot check these
    # in any more detail as doing so would require internal knowledge of the state and
    # header structures, which may change. This can be assumed to be correct as long
    # as 'pull' test passes, it's decrypted values matches the original plain text.
    def test_crypto_secretstream_xchacha20poly1305_init_push(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)

    def test_crypto_secretstream_xchacha20poly1305_init_pull(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)

    def test_crypto_secretstream_xchacha20poly1305_push(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, 0)
    #----

    def test_crypto_secretstream_xchacha20poly1305_pull(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        msg, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state2, ciphertext, None)

        self.assertEqual(msg, b"howdy")
        self.assertEqual(tag, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

    def test_crypto_secretstream_xchacha20poly1305_pull_changed_ad(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", b"some data", pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        self.assertRaises(ValueError, pysodium.crypto_secretstream_xchacha20poly1305_pull, state2, ciphertext, b"different data")


    def test_crypto_secretstream_xchacha20poly1305_pull_incorrect_key(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        bad_key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, bad_key)
        self.assertRaises(ValueError, pysodium.crypto_secretstream_xchacha20poly1305_pull, state2, ciphertext, None)

    def test_crypto_secretstream_xchacha20poly1305_pull_multiple(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)

        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"Correct Horse Battery Staple", None, 0)
        ciphertext2 = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        # Verify decryption
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        msg, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state2, ciphertext, None)
        msg2, tag2 = pysodium.crypto_secretstream_xchacha20poly1305_pull(state2, ciphertext2, None)

        self.assertEqual(msg, b"Correct Horse Battery Staple")
        self.assertEqual(tag, 0)

        self.assertEqual(msg2, b"howdy")
        self.assertEqual(tag2, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

    def test_crypto_secretstream_xchacha20poly1305_pull_corrupted(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)

        ad = 'additional data'
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"Correct Horse Battery Staple", ad, 0)

        # Verify error is raised if cypher text is changed
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        self.assertRaises(ValueError, pysodium.crypto_secretstream_xchacha20poly1305_pull, state2, ciphertext + 'this is a corruption'.encode(), ad)

        # Verify error is raised if additional data is changed
        ad2 = 'this is not the same'
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        self.assertRaises(ValueError, pysodium.crypto_secretstream_xchacha20poly1305_pull, state2, ciphertext, ad2)


    def test_crypto_secretstream_xchacha20poly1305_rekey(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)

        # Encrypt two messages with intermediate re-key
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"Correct Horse Battery Staple", None, 0)
        pysodium.crypto_secretstream_xchacha20poly1305_rekey(state)
        ciphertext2 = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        # Verify by decrypting them
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        msg, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state2, ciphertext, None)
        pysodium.crypto_secretstream_xchacha20poly1305_rekey(state2)
        msg2, tag2 = pysodium.crypto_secretstream_xchacha20poly1305_pull(state2, ciphertext2, None)

        self.assertEqual(msg, b"Correct Horse Battery Staple")
        self.assertEqual(tag, 0)

        self.assertEqual(msg2, b"howdy")
        self.assertEqual(tag2, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

    def test_crypto_secretstream_xchacha20poly1305_missing_rekey(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)

        # Encrypt two messages with intermediate re-key
        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"Correct Horse Battery Staple", None, 0)
        pysodium.crypto_secretstream_xchacha20poly1305_rekey(state)
        ciphertext2 = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        msg, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state2, ciphertext, None)
        # re-key should be here, so following call should fail
        self.assertRaises(ValueError, pysodium.crypto_secretstream_xchacha20poly1305_pull, state2, ciphertext2, None)

    def test_crypto_secretstream_xchacha20poly1305_out_of_order_messeges(self):
        if not pysodium.sodium_version_check(1, 0, 15): return

        key = pysodium.crypto_secretstream_xchacha20poly1305_keygen()
        state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(key)

        ciphertext = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"Correct Horse Battery Staple", None, 0)
        ciphertext2 = pysodium.crypto_secretstream_xchacha20poly1305_push(state, b"howdy", None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)

        # Decrypting the second message first should fail
        state2 = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
        self.assertRaises(ValueError, pysodium.crypto_secretstream_xchacha20poly1305_pull, state2, ciphertext2, None)

    def test_test_crypto_scalarmult_curve25519_base(self):
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
        ct_common = b"e3e446f7ede9a19b62a4"
        for ad, ct in [
                (binascii.unhexlify(b"87e229d4500845a079c0"), b"677dabf4e3d24b876bb284753896e1d6"),
                (None,                                        b"69e7789bcd954e658ed38423e23161dc"),
        ]:
            output = pysodium.crypto_aead_chacha20poly1305_encrypt(input_, ad, nonce, key)
            self.assertEqual(binascii.unhexlify(ct_common + ct), output)
            output = pysodium.crypto_aead_chacha20poly1305_decrypt(output, ad, nonce, key)
            self.assertEqual(output, input_)

    def test_aead_chacha20poly1305_detached(self):
        if not pysodium.sodium_version_check(1, 0, 9): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"cd7cf67be39c794a")
        for ad, ct in [
                (binascii.unhexlify(b"87e229d4500845a079c0"), b"677dabf4e3d24b876bb284753896e1d6"),
                (None,                                        b"69e7789bcd954e658ed38423e23161dc"),
        ]:
            output, mac = pysodium.crypto_aead_chacha20poly1305_encrypt_detached(input_, ad, nonce, key)
            self.assertEqual(binascii.unhexlify(b"e3e446f7ede9a19b62a4"), output)
            self.assertEqual(binascii.unhexlify(ct), mac)
            output = pysodium.crypto_aead_chacha20poly1305_decrypt_detached(output, mac, ad, nonce, key)
            self.assertEqual(output, input_)

    def test_aead_chacha20poly1305_ietf(self):
        if not pysodium.sodium_version_check(1, 0, 4): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"cd7cf67be39c794acd7cf67b")
        for ad in [binascii.unhexlify(b"87e229d4500845a079c0"), None]:
            output = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(input_, ad, nonce, key)
            output = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt(output, ad, nonce, key)
            self.assertEqual(output, input_)

    def test_aead_chacha20poly1305_ietf_detached(self):
        if not pysodium.sodium_version_check(1, 0, 9): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"cd7cf67be39c794acd7cf67b")
        for ad, ct in [
            (binascii.unhexlify(b"87e229d4500845a079c0"), b"09394ed41cf16d3c0820c5e0caf8a7bf"),
            (None, b"07bf99e3c0d8aaac48c04e1f93b12a63"),
        ]:
            output, mac = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(input_, ad, nonce, key)
            self.assertEqual(binascii.unhexlify(b"eef4c561bdda5ef7e044"), output)
            self.assertEqual(binascii.unhexlify(ct), mac)
            output = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(output, mac, ad, nonce, key)
            self.assertEqual(output, input_)

    def test_aead_xchacha20poly1305_ietf(self):
        if not pysodium.sodium_version_check(1, 0, 12): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"cd7cf67be39c794acd7cf67bcd7cf67be39c794acd7cf67b")
        for ad in [binascii.unhexlify(b"87e229d4500845a079c0"), None]:
            output = pysodium.crypto_aead_xchacha20poly1305_ietf_encrypt(input_, ad, nonce, key)
            output = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(output, ad, nonce, key)
            self.assertEqual(output, input_)

    def test_crypto_stream_chacha20_xor(self):
        key = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = binascii.unhexlify(b"0001020304050607")
        input_ = b'\x00' * 256
        output = pysodium.crypto_stream_chacha20_xor(input_, nonce, key)
        self.assertEqual(binascii.unhexlify(b"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9"),
                         output)

    def test_crypto_stream_chacha20_xor_ic(self):
        key = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = binascii.unhexlify(b"0001020304050607")
        input_ = b'\x00' * 128
        ic = 2
        output = pysodium.crypto_stream_chacha20_xor_ic(input_, nonce, ic, key)
        self.assertEqual(binascii.unhexlify(b"9db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9"), output)

    def test_crypto_blake2b(self):
        message   = binascii.unhexlify(b'54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67')
        key       = binascii.unhexlify(b'000102030405060708090a0b0c0d0e0f')

        # Test vectors generated from the blake2b reference implementation
        self.assertEqual(pysodium.crypto_generichash_blake2b_salt_personal(message, key      = key),      binascii.unhexlify(b'0f44eda51dba98442425d486b89962647c1a6e0e8b98a93e7090bf849a5156da'))
        self.assertEqual(pysodium.crypto_generichash_blake2b_salt_personal(message, personal = key),      binascii.unhexlify(b'8c68aecca4b50e91aebaf8c53bde15b68c01b13d571a772fcb8b432affa52a7c'))
        self.assertEqual(pysodium.crypto_generichash_blake2b_salt_personal(message, salt     = key),      binascii.unhexlify(b'43b7feaa91019d0d5b492357fb923211af827d6126af28ccc1874e70bc2177f8'))
        self.assertEqual(pysodium.crypto_generichash_blake2b_salt_personal(message, personal = key[0:8]), binascii.unhexlify(b'31353589b3f179cda74387fbe1deca94f004661f05cde2295a16c0a8d8ead79b'))
        self.assertEqual(pysodium.crypto_generichash_blake2b_salt_personal(message, salt     = key[0:8]), binascii.unhexlify(b'11c29bf7b91b8500a463f27e215dc83afdb71ed5e959f0847e339769c4835fc7'))
        self.assertEqual(pysodium.crypto_generichash_blake2b_salt_personal(message, personal = key, key = key), binascii.unhexlify(b'5a0b3db4bf2dab71485211447fc2014391228cc6c1acd2f3031050a9a32ca407'))


    def test_crypto_pwhash(self):
        if not pysodium.sodium_version_check(1, 0, 9): return
        pw = "Correct Horse Battery Staple"
        salt = binascii.unhexlify(b'0f58b94c7a369fd8a9a7083e4cd75266')
        out = pysodium.crypto_pwhash(pysodium.crypto_auth_KEYBYTES, pw, salt, pysodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE, pysodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE, pysodium.crypto_pwhash_ALG_ARGON2I13)
        self.assertEqual(binascii.hexlify(out), b'79db3095517c7358449d84ee3b2f81f0e9907fbd4e0bae4e0bcc6c79821427dc')

    def test_crypto_pwhash_storage(self):
        if not pysodium.sodium_version_check(1, 0, 9): return
        pw = "Correct Horse Battery Staple"
        pstr = pysodium.crypto_pwhash_str(pw, pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE, pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
        self.assertTrue(pysodium.crypto_pwhash_str_verify(pstr, pw))

    def test_crypto_pwhash_scryptsalsa208sha256(self):
        passwd = b'Correct Horse Battery Staple'
        other_passwd = b'correct horse battery staple'
        salt = binascii.unhexlify(b'4206baae5578933d7cfb315b1c257cc7af162965a91a74ccbb1cfa1d747eb691')
        other_salt = binascii.unhexlify(b'4206baae5578933d7cfb315b1c257cc7af162965a91a74ccbb1cfa1d747eb692')

        # Use very small limits to avoid burning resources in CI
        mem_limit = 16777216
        ops_limit = 32768

        key16 = pysodium.crypto_pwhash_scryptsalsa208sha256(16, passwd, salt, ops_limit, mem_limit)
        self.assertEqual(len(key16), 16)
        self.assertEqual(key16, b'U\x18aL\xcf\xc9\xa3\xf6(\x8f\xed)\xeej8\xdf')

        key = pysodium.crypto_pwhash_scryptsalsa208sha256(32, passwd, salt, ops_limit, mem_limit)
        self.assertEqual(len(key), 32)
        self.assertEqual(key, b'U\x18aL\xcf\xc9\xa3\xf6(\x8f\xed)\xeej8\xdfG\x82hf+vu\xcd\x9c\xdb\xbcmt\xf7\xf1\x10')

        self.assertNotEqual(key, pysodium.crypto_pwhash_scryptsalsa208sha256(32, passwd, other_salt, ops_limit, mem_limit))
        self.assertNotEqual(key, pysodium.crypto_pwhash_scryptsalsa208sha256(32, other_passwd, salt, ops_limit, mem_limit))

    def test_crypto_pwhash_scryptsalsa208sha256_str(self):
        passwd = b'Correct Horse Battery Staple'

        # Use very small limits to avoid burning resources in CI
        mem_limit = 16777216
        ops_limit = 32768

        storage_string = pysodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, ops_limit, mem_limit)
        self.assertTrue(storage_string.startswith(pysodium.crypto_pwhash_scryptsalsa208sha256_STRPREFIX))

        self.assertNotEqual(storage_string, pysodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, ops_limit, mem_limit), "Each call should compute a new random salt.")

    def test_crypto_pwhash_scryptsalsa208sha256_str_verify(self):
        passwd = b'Correct Horse Battery Staple'
        other_passwd = b'correct horse battery staple'

        # Use very small limits to avoid burning resources in CI
        mem_limit = 16777216
        ops_limit = 32768

        storage_string = pysodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, ops_limit, mem_limit)

        pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify(storage_string, passwd)

        self.assertRaises(ValueError, pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify, storage_string, other_passwd)
        self.assertRaises(ValueError, pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify, storage_string[:-1], passwd)
        self.assertRaises(ValueError, pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify, storage_string + b'a', passwd)

    def test_crypto_sign_sk_to_pk(self):
        pk, sk = pysodium.crypto_sign_keypair()
        pk2 = pysodium.crypto_sign_sk_to_pk(sk)
        self.assertEqual(pk, pk2)

    def test_crypto_sign_sk_to_seed(self):
        seed1 = pysodium.crypto_generichash(b'howdy', outlen=pysodium.crypto_sign_SEEDBYTES)
        _, sk = pysodium.crypto_sign_seed_keypair(seed1)
        seed2 = pysodium.crypto_sign_sk_to_seed(sk)
        self.assertEqual(seed1, seed2)

    def test_AsymCrypto_With_Seeded_Keypair(self):
        msg     = b"correct horse battery staple"
        nonce   = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        pk, sk = pysodium.crypto_box_seed_keypair(b"\x00" * pysodium.crypto_box_SEEDBYTES)

        c = pysodium.crypto_box(msg, nonce, pk, sk)
        m = pysodium.crypto_box_open(c, nonce, pk, sk)

        self.assertEqual(msg, m)

    def test_crypto_hash_sha256(self):
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256(b"test")),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256(b"howdy")),
            "0f1128046248f83dc9b9ab187e16fad0ff596128f1524d05a9a77c4ad932f10a")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256(b"Correct Horse Battery Staple")),
            "af139fa284364215adfa49c889ab7feddc5e5d1c52512ffb2cfc9baeb67f220e")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256(b"pysodium")),
            "0a53ef9bc1bea173118a42bbbe8300abb6bbef83139046940e9593d9559a5df7")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256(b"\x80")),
            "76be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71")

    def test_crypto_hash_sha512(self):
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha512(b"test")),
            "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha512(b"howdy")),
            "905caca5c4685f296c5491d38660d7720ee87bef08f829332e905593522907674de8490de46c969d2c585b40af40439b387562d6f776023507753d1a9554ebbb")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha512(b"Correct Horse Battery Staple")),
            "0675070bda47bef936f0b65ae721d90f82ca137841df4d7cae27776501ae4b446ab926d64dc1d282c8758ac0eb02cc4aa11b2452d4f8ffeb795023b797fe2b80")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha512(b"pysodium")),
            "ecbc6f4ffdb6e6dcbe6e6beecf0b8e05c11b0cc8a56f2b4098cd613585749fcca5ed1cfda3518e33a5d2c63746ee2857ff6857b9a2eeda4cc208c1e7fd89cc17")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha512(b"\x80")),
            "dfe8ef54110b3324d3b889035c95cfb80c92704614bf76f17546ad4f4b08218a630e16da7df34766a975b3bb85b01df9e99a4ec0a1d0ec3de6bed7b7a40b2f10")

    def byteHashToString(self, input):
        import sys
        result = ""
        for i in range(0, len(input)):
            if sys.version_info.major == 3:
                tmp = str(hex(ord(chr(input[i]))))[2:]
            else:
                tmp = str(hex(ord(input[i])))[2:]
            if len(tmp) == 1:
                tmp = "0" + tmp
            result += tmp
        return result

    def test_crypto_auth(self):
        sk = pysodium.randombytes(pysodium.crypto_auth_KEYBYTES)
        tag = pysodium.crypto_auth("howdy", sk)
        pysodium.crypto_auth_verify(tag, "howdy", sk)

    def test_crypto_kx(self):
        if not pysodium.sodium_version_check(1, 0, 12): return
        client_pk, client_sk = pysodium.crypto_kx_keypair()
        server_pk, server_sk = pysodium.crypto_kx_keypair()

        crx, ctx = pysodium.crypto_kx_client_session_keys(client_pk, client_sk, server_pk)
        srx, stx = pysodium.crypto_kx_server_session_keys(server_pk, server_sk, client_pk)

        self.assertEqual(crx, stx)
        self.assertEqual(ctx, srx)

    def test_sodium_inc(self):
        r = b'A' * 32
        pysodium.sodium_increment(r)
        self.assertEqual(r, b'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

    def test_crypto_core_ristretto255_scalar_random(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        a = pysodium.crypto_core_ristretto255_scalar_random()
        b = pysodium.crypto_core_ristretto255_scalar_random()
        # stupid check that random returns different values...
        self.assertNotEqual(a,b)

    def test_crypto_core_ristretto255_is_valid_point(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        invalid = binascii.unhexlify(b"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        self.assertEqual(False, pysodium.crypto_core_ristretto255_is_valid_point(invalid))
        invalid = binascii.unhexlify(b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        self.assertEqual(False, pysodium.crypto_core_ristretto255_is_valid_point(invalid))

    def test_crypto_core_ristretto255_from_hash(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        h = pysodium.crypto_generichash(b'howdy', outlen=pysodium.crypto_core_ristretto255_HASHBYTES)
        p = pysodium.crypto_core_ristretto255_from_hash(h)
        pysodium.crypto_core_ristretto255_is_valid_point(p)

    def test_crypto_scalarmult_ristretto255_base(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        p = pysodium.crypto_scalarmult_ristretto255_base(pysodium.crypto_core_ristretto255_scalar_random())
        pysodium.crypto_core_ristretto255_is_valid_point(p)

    def test_crypto_scalarmult_ristretto255(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        n = pysodium.crypto_scalarmult_ristretto255_base(pysodium.crypto_core_ristretto255_scalar_random())
        p = pysodium.crypto_scalarmult_ristretto255_base(pysodium.crypto_core_ristretto255_scalar_random())
        r = pysodium.crypto_scalarmult_ristretto255(n, p)
        pysodium.crypto_core_ristretto255_is_valid_point(r)

    def test_crypto_core_ristretto255_scalar_invert(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        s = pysodium.crypto_core_ristretto255_scalar_random()
        r = pysodium.crypto_core_ristretto255_scalar_invert(s)
        p = pysodium.crypto_scalarmult_ristretto255_base(pysodium.crypto_core_ristretto255_scalar_random())
        q = pysodium.crypto_scalarmult_ristretto255(s, p)
        p_ = pysodium.crypto_scalarmult_ristretto255(r, q)
        self.assertEqual(p,p_)

if __name__ == '__main__':
    unittest.main()
