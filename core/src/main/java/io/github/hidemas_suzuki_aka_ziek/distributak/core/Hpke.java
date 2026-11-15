// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/** RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM。 */
public final class Hpke {
    private static final byte[] EMPTY=new byte[0];
    private static final byte[] VERSION=ascii("HPKE-v1");
    private static final byte[] KEM=Crypto.concat(ascii("KEM"),new byte[]{0,32});
    private static final byte[] SUITE=Crypto.concat(ascii("HPKE"),new byte[]{0,32,0,1,0,1});
    private Hpke() {}
    private static byte[] ascii(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] extract(byte[] suite, byte[] salt, String label, byte[] ikm) {
        byte[] input=Crypto.concat(VERSION,suite,ascii(label),ikm);
        try { return Crypto.extract(salt,input); } finally { Crypto.wipe(input); }
    }
    private static byte[] expand(byte[] suite, byte[] prk, String label, byte[] info, int size) {
        if(size<0 || size>8160) throw new IllegalArgumentException("HPKE の出力長が範囲外です");
        return Crypto.expand(prk,Crypto.concat(new byte[]{(byte)(size>>>8),(byte)size},VERSION,suite,ascii(label),info),size);
    }
    public static byte[] derivePrivateKey(byte[] ikm) {
        byte[] prk=extract(KEM,EMPTY,"dkp_prk",ikm);
        try { return expand(KEM,prk,"sk",EMPTY,32); } finally { Crypto.wipe(prk); }
    }
    private static byte[] shared(byte[] secret, byte[] remote, byte[] enc, byte[] recipient) {
        byte[] dh=Crypto.x25519(secret,remote), prk=null;
        try {
            prk=extract(KEM,EMPTY,"eae_prk",dh);
            return expand(KEM,prk,"shared_secret",Crypto.concat(enc,recipient),32);
        } finally { Crypto.wipe(dh); Crypto.wipe(prk); }
    }
    /**
     * @throws SecurityException 受け手の公開鍵との共有値がゼロのとき。
     * @throws IllegalArgumentException 公開鍵が null または32バイトでないとき。
     */
    public static Context sender(byte[] recipient, byte[] info) {
        byte[] ikm=new byte[32], ephemeral=null; new SecureRandom().nextBytes(ikm);
        try { ephemeral=derivePrivateKey(ikm); return sender(recipient,info,ephemeral); }
        finally { Crypto.wipe(ikm); Crypto.wipe(ephemeral); }
    }
    static Context sender(byte[] recipient, byte[] info, byte[] ephemeral) {
        byte[] enc=Crypto.x25519Public(ephemeral), shared=shared(ephemeral,recipient,enc,recipient);
        try { return schedule(true,enc,shared,info); } finally { Crypto.wipe(shared); }
    }
    /**
     * @throws SecurityException enc との共有値がゼロのとき。
     * @throws IllegalArgumentException 鍵か enc が null または32バイトでないとき。
     */
    public static Context recipient(byte[] recipientSecret, byte[] enc, byte[] info) {
        byte[] pk=Crypto.x25519Public(recipientSecret), shared=shared(recipientSecret,enc,enc,pk);
        try { return schedule(false,enc,shared,info); } finally { Crypto.wipe(shared); }
    }
    private static Context schedule(boolean sender, byte[] enc, byte[] shared, byte[] info) {
        byte[] pskIdHash=extract(SUITE,EMPTY,"psk_id_hash",EMPTY), infoHash=extract(SUITE,EMPTY,"info_hash",info);
        byte[] context=Crypto.concat(new byte[]{0},pskIdHash,infoHash), secret=extract(SUITE,shared,"secret",EMPTY);
        byte[] key=null, nonce=null, exporter=null;
        try {
            key=expand(SUITE,secret,"key",context,16);
            nonce=expand(SUITE,secret,"base_nonce",context,12);
            exporter=expand(SUITE,secret,"exp",context,32);
            return new Context(sender,enc,key,nonce,exporter);
        } finally { Crypto.wipe(secret); Crypto.wipe(key); Crypto.wipe(nonce); Crypto.wipe(exporter); }
    }
    public static final class Context implements AutoCloseable {
        private final boolean sender;
        private final byte[] enc,key,baseNonce,exporter,sequence=new byte[12];
        private boolean closed, exhausted;
        private Context(boolean sender, byte[] enc, byte[] key, byte[] nonce, byte[] exporter) {
            this.sender=sender; this.enc=enc.clone(); this.key=key.clone(); baseNonce=nonce.clone(); this.exporter=exporter.clone();
        }
        public byte[] encapsulation() { return enc.clone(); }
        byte[] keyForTest() { return key.clone(); }
        byte[] nonceForTest() { return baseNonce.clone(); }
        private void usable() { if(closed || exhausted) throw new IllegalStateException("HPKE のコンテキストは使えません"); }
        private byte[] crypt(boolean seal, byte[] aad, byte[] input) {
            usable(); if(seal!=sender) throw new IllegalStateException("HPKE の方向が違います");
            byte[] nonce=baseNonce.clone();
            for(int i=0;i<12;i++) nonce[i]^=sequence[i];
            try {
                byte[] result=Crypto.aead(true,seal,key,nonce,aad,input);
                // RFC 9180: seq >= 2^(8*Nn)-1 の呼び出しは出力を返さない。
                boolean last=true; for(byte b:sequence) last &= (b & 255)==255;
                if(last) { Crypto.wipe(result); exhausted=true; throw new SecurityException("HPKE の番号を使い切りました"); }
                for(int i=11;i>=0;i--) if(++sequence[i]!=0) break;
                return result;
            } finally { Crypto.wipe(nonce); }
        }
        /** @throws SecurityException AEAD の処理に失敗したか、番号を使い切ったとき。 */
        public synchronized byte[] seal(byte[] aad, byte[] plaintext) { return crypt(true,aad,plaintext); }
        /** @throws SecurityException 認証に失敗したか、番号を使い切ったとき。 */
        public synchronized byte[] open(byte[] aad, byte[] ciphertext) { return crypt(false,aad,ciphertext); }
        public synchronized byte[] export(byte[] context, int size) { usable(); return expand(SUITE,exporter,"sec",context,size); }
        @Override public synchronized void close() { closed=true; Crypto.wipe(key); Crypto.wipe(baseNonce); Crypto.wipe(exporter); Crypto.wipe(sequence); }
    }
}
