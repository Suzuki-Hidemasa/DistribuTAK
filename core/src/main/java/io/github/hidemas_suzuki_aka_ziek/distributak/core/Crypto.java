// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.Arrays;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/** 公開標準の部品を Bouncy Castle に委ねる。引数の秘密配列は呼び出し元が所有する。 */
public final class Crypto {
    private Crypto() {}
    public static void wipe(byte[] value) { if (value != null) Arrays.fill(value, (byte) 0); }
    static void length(byte[] value, int size) {
        if (value == null || value.length != size) throw new IllegalArgumentException("長さが違います: " + size);
    }
    public static byte[] concat(byte[]... parts) {
        int size = 0; for (byte[] part : parts) size = Math.addExact(size, part.length);
        byte[] out = new byte[size]; int offset = 0;
        for (byte[] part : parts) { System.arraycopy(part, 0, out, offset, part.length); offset += part.length; }
        return out;
    }
    public static boolean equal(byte[] a, byte[] b) { return org.bouncycastle.util.Arrays.constantTimeAreEqual(a,b); }
    private static byte[] digest(Digest d, byte[] input) {
        d.update(input,0,input.length); byte[] out = new byte[d.getDigestSize()]; d.doFinal(out,0); return out;
    }
    public static byte[] blake2s(byte[] input) { return digest(new Blake2sDigest(256), input); }
    public static byte[] blake2s128(byte[] input) { return digest(new Blake2sDigest(128), input); }
    public static byte[] sha256(byte[] input) { return digest(new SHA256Digest(), input); }
    static byte[] hmac(boolean blake, byte[] key, byte[] input) {
        HMac mac = new HMac(blake ? new Blake2sDigest(256) : new SHA256Digest());
        mac.init(new KeyParameter(key)); mac.update(input,0,input.length);
        byte[] out = new byte[32]; mac.doFinal(out,0); mac.reset(); return out;
    }
    public static byte[] hmacSha256(byte[] key, byte[] input) { return hmac(false,key,input); }
    public static byte[] extract(byte[] salt, byte[] ikm) { return hmacSha256(salt.length == 0 ? new byte[32] : salt, ikm); }
    public static byte[] expand(byte[] prk, byte[] info, int size) {
        if (size < 0 || size > 255*32) throw new IllegalArgumentException("HKDF の長さが範囲外です");
        HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(HKDFParameters.skipExtractParameters(prk, info));
        byte[] out = new byte[size]; generator.generateBytes(out,0,size); return out;
    }
    public static byte[] x25519Public(byte[] secret) {
        length(secret,32); byte[] pub = new byte[32]; X25519.generatePublicKey(secret,0,pub,0); return pub;
    }
    /**
     * @throws SecurityException 相手の公開鍵との共有値がゼロのとき。
     * @throws IllegalArgumentException 鍵が null または32バイトでないとき。
     */
    public static byte[] x25519(byte[] secret, byte[] pub) {
        length(secret,32); length(pub,32); byte[] out = new byte[32];
        if (!X25519.calculateAgreement(secret,0,pub,0,out,0)) { wipe(out); throw new SecurityException("X25519 の共有値がゼロです"); }
        return out;
    }
    public static byte[] ed25519Public(byte[] secret) {
        length(secret,32); byte[] pub = new byte[32]; Ed25519.generatePublicKey(secret,0,pub,0); return pub;
    }
    public static byte[] sign(byte[] secret, byte[] message) {
        length(secret,32); byte[] sig = new byte[64]; Ed25519.sign(secret,0,message,0,message.length,sig,0); return sig;
    }
    public static boolean verify(byte[] pub, byte[] message, byte[] sig) {
        length(pub,32); if (sig.length != 64) return false;
        return Ed25519.verify(sig,0,pub,0,message,0,message.length);
    }
    /**
     * @throws SecurityException 認証などの AEAD の処理に失敗したとき。
     * @throws IllegalArgumentException 鍵か nonce が null または指定された長さでないとき。
     */
    public static byte[] aead(boolean aes, boolean encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input) {
        length(key,aes ? 16 : 32); length(nonce,12);
        AEADCipher cipher = aes ? GCMBlockCipher.newInstance(AESEngine.newInstance()) : new ChaCha20Poly1305();
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key),128,nonce,aad));
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        try {
            int n = cipher.processBytes(input,0,input.length,out,0);
            n += cipher.doFinal(out,n);
            if (n != out.length) throw new IllegalStateException("AEAD の長さが一致しません");
            return out;
        } catch (InvalidCipherTextException | RuntimeException e) {
            wipe(out); throw new SecurityException("AEAD を検証できません", e);
        } finally { cipher.reset(); }
    }
}
