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

        self.assertNotEqual(pysodium.crypto_generichash( 'salt0'), pysodium.crypto_generichash( 'salt1'))
        self.assertNotEqual(pysodium.crypto_generichash(b'salt0'), pysodium.crypto_generichash(b'salt1'))
    def test_crypto_auth_hmac_256_512_512256(self):
        """Taken from https://www.rfc-editor.org/rfc/rfc4231#section-4"""
        vectors = [
            {
                "k": b"\x0b" * 20 + b"\x00" * 12,
                "m": b"Hi There",
                "256": bytes.fromhex(
                    "b0344c61d8db38535ca8afceaf0bf12b"
                    "881dc200c9833da726e9376c2e32cff7"
                ),
                "512": bytes.fromhex(
                    "87aa7cdea5ef619d4ff0b4241a1d6cb0"
                    "2379f4e2ce4ec2787ad0b30545e17cde"
                    "daa833b7d6b8a702038b274eaea3f4e4"
                    "be9d914eeb61f1702e696c203a126854"
                ),
                "512256": bytes.fromhex(
                    "87aa7cdea5ef619d4ff0b4241a1d6cb0"
                    "2379f4e2ce4ec2787ad0b30545e17cde"
                ),
            },
            {
                "k": b"Jefe" + b"\x00" * 28,
                "m": b"what do ya want for nothing?",
                "256": bytes.fromhex(
                    "5bdcc146bf60754e6a042426089575c7"
                    "5a003f089d2739839dec58b964ec3843"
                ),
                "512": bytes.fromhex(
                    "164b7a7bfcf819e2e395fbe73b56e0a3"
                    "87bd64222e831fd610270cd7ea250554"
                    "9758bf75c05a994a6d034f65f8f0e6fd"
                    "caeab1a34d4a6b4b636e070a38bce737"
                ),
                "512256": bytes.fromhex(
                    "164b7a7bfcf819e2e395fbe73b56e0a3"
                    "87bd64222e831fd610270cd7ea250554"
                ),
            },
        ]

        for v in vectors:
            self.assertEqual(pysodium.crypto_auth_hmacsha256(v["m"], v["k"]), v["256"])
            self.assertEqual(pysodium.crypto_auth_hmacsha512(v["m"], v["k"]), v["512"])
            self.assertEqual(
                pysodium.crypto_auth_hmacsha512256(v["m"], v["k"]), v["512256"]
            )
            try:
                pysodium.crypto_auth_hmacsha256_verify(v["256"], v["m"], v["k"])
                pysodium.crypto_auth_hmacsha512_verify(v["512"], v["m"], v["k"])
                pysodium.crypto_auth_hmacsha512256_verify(v["512256"], v["m"], v["k"])
            except Exception as e:
                self.assertTrue(False, f"verification fail: {e}")

        msg = b"pull request plz"
        try:
            key = pysodium.crypto_auth_hmacsha256_keygen()
            hmac = pysodium.crypto_auth_hmacsha256(msg, key)
            pysodium.crypto_auth_hmacsha256_verify(hmac, msg, key)

        except Exception:
            self.assertTrue(False)

        try:
            key = pysodium.crypto_auth_hmacsha256_keygen()
            hmac = pysodium.crypto_auth_hmacsha256(msg, key)
            pysodium.crypto_auth_hmacsha256_verify(hmac, msg, key)

        except Exception:
            self.assertTrue(False)

        try:
            key = pysodium.crypto_auth_hmacsha256_keygen()
            hmac = pysodium.crypto_auth_hmacsha256(msg, key)
            pysodium.crypto_auth_hmacsha256_verify(hmac, msg, key)

        except Exception:
            self.assertTrue(False)

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

    def test_crypto_secretbox_open_detached(self):
        m = b"howdy"
        n = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
        k = pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
        c, mac = pysodium.crypto_secretbox_detached(m, n, k)
        mplain = pysodium.crypto_secretbox_open_detached(c, mac, n, k)
        self.assertEqual(m, mplain)
        changed = b"\0"*len(c)
        self.assertRaises(ValueError, pysodium.crypto_secretbox_open_detached, changed, mac, n, k)

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

    def test_crypto_scalarmult_base(self):
        # In the C code, crypto_scalarmult_base just delegates to
        # crypto_scalarmult_curve25519_base. If libsodium changes the preferred
        # algorithm, this answer will change.
        k = binascii.unhexlify(b"e38e290880cee71a0cbb7b09328fd034c1fe4bd8838b19ab303a64a8c6b01456")
        expected = binascii.unhexlify(b"4aa82c2514ed88eb46085369a45ddd0db997e53bfee877c4556ab49a1581e545")
        actual = pysodium.crypto_scalarmult_base(k)
        self.assertEqual(expected, actual)

    def test_crypto_scalarmult_curve25519_base(self):
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

    def test_aead_aegis128l(self):
        if not pysodium.sodium_version_check(1, 0, 19): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b50")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"087b5f9fadfb515388394f8035482608")
        ad = binascii.unhexlify(b"87e229d4500845a079c0")
        ct = binascii.unhexlify(b"a4fa71e3508259ff98e9e2874d98f97b7b3e14a033b835f25e335735385f604afe227394ad9032c1bcea")
        output = pysodium.crypto_aead_aegis128l_encrypt(input_, ad, nonce, key)
        self.assertEqual(bytes.hex(ct), bytes.hex(output))
        output = pysodium.crypto_aead_aegis128l_decrypt(output, ad, nonce, key)
        self.assertEqual(output, input_)

    def test_aead_aegis256(self):
        if not pysodium.sodium_version_check(1, 0, 19): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"087b5f9fadfb515388394f8035482608e17b07153e560e301406cfad9f12c164")
        ad = binascii.unhexlify(b"87e229d4500845a079c0")
        ct = binascii.unhexlify(b"5b0b85a1a45a52e0950b2336fa9df3aacd14862fc4e7f670eafd04d6697be30973fa0f6c82cdfbfb1b7a")
        output = pysodium.crypto_aead_aegis256_encrypt(input_, ad, nonce, key)
        self.assertEqual(bytes.hex(ct), bytes.hex(output))
        output = pysodium.crypto_aead_aegis256_decrypt(output, ad, nonce, key)
        self.assertEqual(output, input_)

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

    def test_crypto_stream_chacha20_ietf_xor(self):
        key = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = binascii.unhexlify(b"000000090000004a00000000")
        input_ = b'\x00' * 256
        output = pysodium.crypto_stream_chacha20_ietf_xor(input_, nonce, key)
        self.assertEqual(binascii.unhexlify(b"8adc91fd9ff4f0f51b0fad50ff15d637e40efda206cc52c783a74200503c1582cd9833367d0a54d57d3c9e998f490ee69ca34c1ff9e939a75584c52d690a35d410f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e0a88837739d7bf4ef8ccacb0ea2bb9d69d56c394aa351dfda5bf459f0a2e9fe8e721f89255f9c486bf21679c683d4f9c5cf2fa27865526005b06ca374c86af3bdcbfbdcb83be65862ed5c20eae5a43241d6a92da6dca9a156be25297f51c27188a861e93cc3aeb129a76598baccd27453ac6941b4b4e1e5153a9fee95d1ba00e"),
                         output)

    def test_crypto_stream_chacha20_ietf_xor_ic(self):
        key = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = binascii.unhexlify(b"000000090000004a00000000")
        input_ = b'\x00' * 128
        ic = 2
        output = pysodium.crypto_stream_chacha20_ietf_xor_ic(input_, nonce, ic, key)
        self.assertEqual(binascii.unhexlify(b"0a88837739d7bf4ef8ccacb0ea2bb9d69d56c394aa351dfda5bf459f0a2e9fe8e721f89255f9c486bf21679c683d4f9c5cf2fa27865526005b06ca374c86af3bdcbfbdcb83be65862ed5c20eae5a43241d6a92da6dca9a156be25297f51c27188a861e93cc3aeb129a76598baccd27453ac6941b4b4e1e5153a9fee95d1ba00e"), output)

    def test_crypto_stream_xchacha20_xor(self):
        # test vectors taken from:
        # https://github.com/jedisct1/libsodium/blob/609e42be75589f91179d218e24f5e35a7124abfd/test/default/xchacha20.c#L102
        key = binascii.unhexlify("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232")
        nonce = binascii.unhexlify("c047548266b7c370d33566a2425cbf30d82d1eaf5294109e")
        out = binascii.unhexlify("a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc")
        output = pysodium.crypto_stream_xchacha20_xor(out, nonce, key)
        self.assertEqual(b'\x00'*len(output), output)

    def test_crypto_stream_xchacha20_xor_ic(self):
        key = binascii.unhexlify("9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232")
        nonce = binascii.unhexlify("c047548266b7c370d33566a2425cbf30d82d1eaf5294109e")
        out = binascii.unhexlify("a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc")
        output = pysodium.crypto_stream_xchacha20_xor_ic(out, nonce, 0, key)
        self.assertEqual(b'\x00'*len(output), output)

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

    def test_crypto_hash_sha512_steps(self):
        s = pysodium.crypto_hash_sha512_init()
        pysodium.crypto_hash_sha512_update(s, b"Correct Horse ")
        pysodium.crypto_hash_sha512_update(s, b"Battery Staple")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha512_final(s)),
            "0675070bda47bef936f0b65ae721d90f82ca137841df4d7cae27776501ae4b446ab926d64dc1d282c8758ac0eb02cc4aa11b2452d4f8ffeb795023b797fe2b80")

    def byteHashToString(self, input):
        return binascii.hexlify(input).decode('utf8')

    def test_crypto_auth(self):
        sk = pysodium.randombytes(pysodium.crypto_auth_KEYBYTES)
        tag = pysodium.crypto_auth("howdy", sk)
        pysodium.crypto_auth_verify(tag, "howdy", sk)

    def test_crypto_kdf_hkdf_sha256(self):
        # test vectors: https://datatracker.ietf.org/doc/html/rfc5869
        if not pysodium.sodium_version_check(1, 0, 19): return
        expected_prk = bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        expected_out = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        ctx = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        outlen = 42
        self.assertEqual(expected_prk, pysodium.crypto_kdf_hkdf_sha256_extract(salt, ikm))
        self.assertEqual(expected_out, pysodium.crypto_kdf_hkdf_sha256_expand(outlen, expected_prk, ctx))

        expected_prk = bytes.fromhex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
        expected_out = bytes.fromhex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
        ikm = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
        salt = bytes.fromhex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
        ctx = bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        outlen = 82
        self.assertEqual(expected_prk, pysodium.crypto_kdf_hkdf_sha256_extract(salt, ikm))
        self.assertEqual(expected_out, pysodium.crypto_kdf_hkdf_sha256_expand(outlen, expected_prk, ctx))

        expected_prk = bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        expected_out = bytes.fromhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("")
        ctx = bytes.fromhex("")
        outlen = 42
        state = pysodium.crypto_kdf_hkdf_sha256_extract_init(salt)
        state = pysodium.crypto_kdf_hkdf_sha256_extract_update(state, ikm)
        self.assertEqual(expected_prk, pysodium.crypto_kdf_hkdf_sha256_extract_final(state))
        self.assertEqual(expected_out, pysodium.crypto_kdf_hkdf_sha256_expand(outlen, expected_prk, ctx))

    def test_crypto_kdf_hkdf_sha512(self):
        if not pysodium.sodium_version_check(1, 0, 19): return
        expected_prk = bytes.fromhex("665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237")
        expected_out = bytes.fromhex("832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb")
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        ctx = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        outlen = 42
        self.assertEqual(expected_prk, pysodium.crypto_kdf_hkdf_sha512_extract(salt, ikm))
        self.assertEqual(expected_out, pysodium.crypto_kdf_hkdf_sha512_expand(outlen, expected_prk, ctx))

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

    def test_crypto_core_ristretto255_random(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        a = pysodium.crypto_core_ristretto255_random()
        b = pysodium.crypto_core_ristretto255_random()
        # same stupid check that random returns different values...
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

    def test_crypto_core_ristretto255_add_sub(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        p = pysodium.crypto_core_ristretto255_random()
        q = pysodium.crypto_core_ristretto255_random()

        p_q = pysodium.crypto_core_ristretto255_add(p, q)
        r = pysodium.crypto_core_ristretto255_sub(p_q,q)
        self.assertEqual(p,r)

    def test_crypto_core_ristretto255_scalar_add_sub(self):
        if not pysodium.sodium_version_check(1, 0, 18): return

        x = pysodium.crypto_core_ristretto255_scalar_random()
        y = pysodium.crypto_core_ristretto255_scalar_random()
        x_y = pysodium.crypto_core_ristretto255_scalar_add(x,y)
        r = pysodium.crypto_core_ristretto255_scalar_sub(x_y,y)

        p1 = pysodium.crypto_scalarmult_ristretto255_base(x)
        p2 = pysodium.crypto_scalarmult_ristretto255_base(r)
        self.assertEqual(p1,p2)

    def test_crypto_core_ristretto255_scalar_negate(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        s = pysodium.crypto_core_ristretto255_scalar_random()
        r = pysodium.crypto_core_ristretto255_scalar_negate(s)
        # s + neg(s) = 0 mod L
        s_r = pysodium.crypto_core_ristretto255_scalar_add(s,r)
        self.assertEqual(s_r,b"\x00"*32)

    def test_crypto_core_ristretto255_scalar_complement(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        x = pysodium.crypto_core_ristretto255_scalar_random()
        x_ = pysodium.crypto_core_ristretto255_scalar_complement(x)
        # x + complement(x) = 1 mod L
        one = pysodium.crypto_core_ristretto255_scalar_add(x,x_)
        self.assertEqual(one,b'\x01'+b"\x00"*31)

    def test_crypto_core_ristretto255_scalar_mul(self):
        if not pysodium.sodium_version_check(1, 0, 18): return
        two = b'\x02' + b'\x00' * 31
        four_mul = pysodium.crypto_core_ristretto255_scalar_mul(two,two)
        four_add = pysodium.crypto_core_ristretto255_scalar_add(two,two)
        self.assertEqual(four_mul,four_add)

        x = pysodium.crypto_core_ristretto255_scalar_random()
        one = b'\x01' + b'\x00' * 31
        r = pysodium.crypto_core_ristretto255_scalar_mul(x,one)
        self.assertEqual(x,r)

if __name__ == '__main__':
    unittest.main()
