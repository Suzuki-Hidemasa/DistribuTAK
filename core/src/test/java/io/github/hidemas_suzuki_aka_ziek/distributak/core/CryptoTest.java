// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {
    static byte[] hex(String value) { return HexFormat.of().parseHex(value); }
    @Test void blake2sEmpty() {
        assertArrayEquals(hex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"), Crypto.blake2s(new byte[0]));
        // Python hashlib.blake2s(b'', digest_size=16) とも照合する。
        assertArrayEquals(hex("64550d6ffe2c0a01a14aba1eade0200c"), Crypto.blake2s128(new byte[0]));
    }
    @Test void x25519Rfc7748() {
        byte[] secret = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assertArrayEquals(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), Crypto.x25519Public(secret));
        assertThrows(SecurityException.class, () -> Crypto.x25519(secret, new byte[32]));
    }
    @Test void ed25519Rfc8032() {
        byte[] secret = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] pub = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] sig = hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assertArrayEquals(pub, Crypto.ed25519Public(secret));
        assertArrayEquals(sig, Crypto.sign(secret, new byte[0]));
        assertTrue(Crypto.verify(pub, new byte[0], sig));
        sig[0] ^= 1;
        assertFalse(Crypto.verify(pub, new byte[0], sig));
    }
    @Test void hkdfRfc5869() {
        byte[] ikm = new byte[22]; java.util.Arrays.fill(ikm, (byte) 0x0b);
        byte[] prk = Crypto.extract(hex("000102030405060708090a0b0c"), ikm);
        assertArrayEquals(hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), prk);
        assertArrayEquals(hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), Crypto.expand(prk, hex("f0f1f2f3f4f5f6f7f8f9"), 42));
    }
    @Test void aeadRejectsTamperingAndWipe() {
        for (boolean aes : new boolean[]{false,true}) {
            byte[] key = new byte[aes ? 16 : 32], nonce = new byte[12], aad = {1};
            byte[] sealed = Crypto.aead(aes, true, key, nonce, aad, new byte[]{2,3});
            assertArrayEquals(new byte[]{2,3}, Crypto.aead(aes, false, key, nonce, aad, sealed));
            sealed[0] ^= 1;
            assertThrows(SecurityException.class, () -> Crypto.aead(aes, false, key, nonce, aad, sealed));
        }
        byte[] secret = {1,2}; Crypto.wipe(secret); assertArrayEquals(new byte[2], secret);
    }
}
