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
        c, mac = pysodium.crypto_box_detached("howdy", n, pk, sk) 
        pysodium.crypto_box_open_detached(c, mac, n, pk, sk)

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

    def test_aead_chacha20poly1305_ietf(self):
        if not pysodium.sodium_version_check(1, 0, 4): return
        key = binascii.unhexlify(b"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
        input_ = binascii.unhexlify(b"86d09974840bded2a5ca")
        nonce = binascii.unhexlify(b"cd7cf67be39c794a")
        ad = binascii.unhexlify(b"87e229d4500845a079c0")
        output = pysodium.crypto_aead_chacha20poly1305_ietf_encrypt(input_, ad, nonce, key)
        output = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt(output, ad, nonce, key)
        self.assertEqual(output, input_)

    def test_crypto_stream_chacha20_xor(self):
        key = binascii.unhexlify(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        nonce = binascii.unhexlify(b"0001020304050607")
        input_ = b'\x00' * 256
        output = pysodium.crypto_stream_chacha20_xor(input_, nonce, key)
        self.assertEqual(binascii.unhexlify(b"f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9"),
                         output)

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

    def test_crypto_pwhash_scryptsalsa208sha256(self):
        passwd = b'Correct Horse Battery Staple'
        other_passwd = b'correct horse battery staple'
        salt = binascii.unhexlify(b'4206baae5578933d7cfb315b1c257cc7af162965a91a74ccbb1cfa1d747eb691')
        other_salt = binascii.unhexlify(b'4206baae5578933d7cfb315b1c257cc7af162965a91a74ccbb1cfa1d747eb692')

        # Use very small limits to avoid burning resources in CI
        mem_limit = 32 * 1024
        ops_limit = 1024

        key16 = pysodium.crypto_pwhash_scryptsalsa208sha256(16, passwd, salt, ops_limit, mem_limit)
        self.assertEqual(len(key16), 16)
        self.assertEqual(key16, binascii.unhexlify(b'34f05e9bef8beccd658acf5f123680b7'))

        key = pysodium.crypto_pwhash_scryptsalsa208sha256(32, passwd, salt, ops_limit, mem_limit)
        self.assertEqual(len(key), 32)
        self.assertEqual(key, binascii.unhexlify(b'34f05e9bef8beccd658acf5f123680b7d30c88d7e9328f9e47ab90185b6ee9ff'))

        self.assertNotEqual(key, pysodium.crypto_pwhash_scryptsalsa208sha256(32, passwd, other_salt, ops_limit, mem_limit))
        self.assertNotEqual(key, pysodium.crypto_pwhash_scryptsalsa208sha256(32, other_passwd, salt, ops_limit, mem_limit))

    def test_crypto_pwhash_scryptsalsa208sha256_str(self):
        passwd = b'Correct Horse Battery Staple'

        # Use very small limits to avoid burning resources in CI
        mem_limit = 32 * 1024
        ops_limit = 1024

        storage_string = pysodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, ops_limit, mem_limit)
        self.assertTrue(storage_string.startswith(pysodium.crypto_pwhash_scryptsalsa208sha256_STRPREFIX))
        self.assertNotIn(b'\x00', storage_string)

        self.assertNotEqual(storage_string, pysodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, ops_limit, mem_limit), "Each call should compute a new random salt.")

    def test_crypto_pwhash_scryptsalsa208sha256_str_verify(self):
        passwd = b'Correct Horse Battery Staple'
        other_passwd = b'correct horse battery staple'

        # Use very small limits to avoid burning resources in CI
        mem_limit = 32 * 1024
        ops_limit = 1024

        storage_string = pysodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, ops_limit, mem_limit)

        pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify(storage_string, passwd)

        self.assertRaises(ValueError, pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify, storage_string, other_passwd)
        self.assertRaises(ValueError, pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify, storage_string[:-1], passwd)
        self.assertRaises(ValueError, pysodium.crypto_pwhash_scryptsalsa208sha256_str_verify, storage_string + b'a', passwd)

    def test_crypto_sign_sk_to_pk(self):
        pk, sk = pysodium.crypto_sign_keypair()
        pk2 = pysodium.crypto_sign_sk_to_pk(sk)
        self.assertEqual(pk, pk2)

    def test_AsymCrypto_With_Seeded_Keypair(self):
        msg     = b"correct horse battery staple"
        nonce   = pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)
        pk, sk = pysodium.crypto_box_seed_keypair("howdy")

        c = pysodium.crypto_box(msg, nonce, pk, sk)
        m = pysodium.crypto_box_open(c, nonce, pk, sk)
        
        self.assertEqual(msg, m)

    def test_crypto_hash_sha256(self):
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256("test")),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256("howdy")),
            "0f1128046248f83dc9b9ab187e16fad0ff596128f1524d05a9a77c4ad932f10a")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256("Correct Horse Battery Staple")),
            "af139fa284364215adfa49c889ab7feddc5e5d1c52512ffb2cfc9baeb67f220e")
        self.assertEqual(self.byteHashToString(pysodium.crypto_hash_sha256("pysodium")),
            "0a53ef9bc1bea173118a42bbbe8300abb6bbef83139046940e9593d9559a5df7")

    def byteHashToString(self, input):
        import sys
        result = ""
        for i in range(0, len(input)):
            if sys.version_info.major == 3:
                tmp = str(hex(ord(chr(input[i]))))[2:]
            else:
                tmp = str(hex(ord(input[i])))[2:]
            if len(tmp) is 1:
                tmp = "0" + tmp
            result += tmp
        return result

if __name__ == '__main__':
    unittest.main()
