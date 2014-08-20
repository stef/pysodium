from pysodium import  crypto_aead_chacha20poly1305_encrypt
from bitstring import BitStream

key = BitStream(hex="4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007")
nonce = BitStream(hex="cd7cf67be39c794a")
ad = BitStream(hex="87e229d4500845a079c0")
msg = BitStream(hex="86d09974840bded2a5ca")

print(key)
print(nonce)
print(ad)
print(msg)

m = crypto_aead_chacha20poly1305_encrypt(message=msg.bytes,
                                         ad=ad.bytes,
                                         nonce=nonce.bytes,
                                         key=key.bytes)

edata = BitStream(bytes=m)
print(edata)


