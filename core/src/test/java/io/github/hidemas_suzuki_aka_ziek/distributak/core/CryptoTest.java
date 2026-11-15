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
    // 以下の x25519・ed25519・hkdf の値は、このプロジェクトで乱数から作り、
    // Python の cryptography・hmac・hashlib（独立した実装）で計算した。RFC の例の値は使わない。
    // The x25519, ed25519 and hkdf values below were generated randomly for this project and
    // computed with Python cryptography / hmac / hashlib (independent implementations). No RFC example values are used.
    @Test void x25519PublicKey() {
        byte[] secret = hex("5b3b25c4303cc06a9f4fad00adc0c3e8537f461ef751579d1416d1e205ef8d95");
        assertArrayEquals(hex("42800ea35307e11b2a92430e5601b4e113bbfb53b1dfefd86cc2ac0ade0cc010"), Crypto.x25519Public(secret));
        assertThrows(SecurityException.class, () -> Crypto.x25519(secret, new byte[32]));
    }
    @Test void ed25519SignAndVerify() {
        byte[] secret = hex("8f49ef94c601c44af5759f808a56a381bb299059e4fb0c41af588a536bc72d07");
        byte[] pub = hex("2ce8cd084440d7a7ca45d179736e8e236fa055fd50d94d0cba46ac9b4cb454d5");
        byte[] sig = hex("6113e31f7b09ee7e821a85e86d306c3581c57d2dec54d7507da11c26442733c8afff5f9dc5ca7cd7e37c8df340b75f7a59b1d81cccfb554593e536d96b1c860e");
        byte[] message = hex("646973747269627574616b2d746573742d6d6573736167652d31");
        byte[] messageSig = hex("9b7547771cc2e97b4c4aec57bbb9801540315c134f473a3864502bd7da1f3d5e93ab93cdffb4a0705586ff347856e5e06e333d61af5b3d41fb3369889e71e000");
        assertArrayEquals(pub, Crypto.ed25519Public(secret));
        assertArrayEquals(sig, Crypto.sign(secret, new byte[0]));
        assertArrayEquals(messageSig, Crypto.sign(secret, message));
        assertTrue(Crypto.verify(pub, new byte[0], sig));
        assertTrue(Crypto.verify(pub, message, messageSig));
        assertFalse(Crypto.verify(pub, message, sig));
        sig[0] ^= 1;
        assertFalse(Crypto.verify(pub, new byte[0], sig));
    }
    @Test void hkdfSha256() {
        byte[] ikm = hex("9e4cad06010207be7b87fc12033fe833aa0782d7350ef6a524660d08d35924af");
        byte[] prk = Crypto.extract(hex("e08d4e238cc07ee507142cd9959adc25"), ikm);
        assertArrayEquals(hex("a0062654cad9f87e6f6f3184f18ec1cf6d2aedeb4a4bfdc87d505251f405cd8e"), prk);
        assertArrayEquals(hex("a25b11419fa9e9a8b2bad2bf8717931c840847a27aef5a8c600ff0902f3b6dbb8bf53da589281bde361b"), Crypto.expand(prk, hex("ef7a28ac75cac7e12af115f6"), 42));
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
