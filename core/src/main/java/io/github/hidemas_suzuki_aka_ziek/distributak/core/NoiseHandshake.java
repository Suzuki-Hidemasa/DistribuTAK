// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.LongSupplier;

/** Noise revision 34 の IKpsk2。証明書や TAI64N の解釈は上位の層が行う。失敗した握手は再利用しない。 */
public final class NoiseHandshake implements AutoCloseable {
    public static final String PROTOCOL = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    private final boolean initiator;
    private final byte[] s, e, psk;
    private byte[] rs, re, ck, h, k;
    private long nonce;
    private int step;
    private boolean closed, split;

    /** @throws IllegalArgumentException 必須の引数が null、または鍵が32バイトでないとき。 */
    public NoiseHandshake(boolean initiator, byte[] staticSecret, byte[] remoteStatic, byte[] psk, byte[] prologue) {
        this(initiator,staticSecret,remoteStatic,psk,prologue,null);
    }
    // ベクトルの試験だけで一時鍵を固定する。通常の呼び出しでは SecureRandom を使う。
    NoiseHandshake(boolean initiator, byte[] staticSecret, byte[] remoteStatic, byte[] psk, byte[] prologue, byte[] ephemeral) {
        Crypto.length(staticSecret,32); if(ephemeral!=null) Crypto.length(ephemeral,32); Crypto.length(psk,32);
        if (initiator) Crypto.length(remoteStatic,32);
        if(prologue==null) throw new IllegalArgumentException("prologue は null にできません");
        this.initiator=initiator; this.s=staticSecret.clone(); this.e=ephemeral==null ? randomSecret() : ephemeral.clone(); this.psk=psk.clone();
        this.rs=initiator ? remoteStatic.clone() : null;
        byte[] name=PROTOCOL.getBytes(StandardCharsets.US_ASCII);
        h=Crypto.blake2s(name); ck=h.clone(); mixHash(prologue);
        mixHash(initiator ? rs : Crypto.x25519Public(s));
    }
    private static byte[] randomSecret() { byte[] out=new byte[32]; new SecureRandom().nextBytes(out); return out; }
    boolean isInitiator() { return initiator; }
    private void require(boolean write) {
        if(closed || step>=2 || write != (initiator == (step==0))) throw new IllegalStateException("握手の順序が違います");
    }
    private void mixHash(byte[] value) {
        byte[] old=h, joined=Crypto.concat(h,value);
        try { h=Crypto.blake2s(joined); }
        finally { Crypto.wipe(joined); Crypto.wipe(old); }
    }
    static byte[][] hkdf(byte[] salt, byte[] input, int count) {
        byte[] temp=Crypto.hmac(true,salt,input), previous=new byte[0]; byte[][] out=new byte[count][];
        try {
            for(int n=0;n<count;n++) {
                byte[] joined=Crypto.concat(previous,new byte[]{(byte)(n+1)});
                try { out[n]=Crypto.hmac(true,temp,joined); previous=out[n]; } finally { Crypto.wipe(joined); }
            }
            return out;
        } finally { Crypto.wipe(temp); }
    }
    private void mixKey(byte[] input) {
        byte[][] values=hkdf(ck,input,2); Crypto.wipe(ck); Crypto.wipe(k); ck=values[0]; k=values[1]; nonce=0;
    }
    private void mixPsk() {
        byte[][] values=hkdf(ck,psk,3); Crypto.wipe(ck); Crypto.wipe(k); ck=values[0]; mixHash(values[1]);
        Crypto.wipe(values[1]); k=values[2]; nonce=0;
    }
    private void dh(byte[] secret, byte[] pub) {
        byte[] shared=Crypto.x25519(secret,pub); try { mixKey(shared); } finally { Crypto.wipe(shared); }
    }
    static byte[] nonce(long count) { return ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN).putInt(0).putLong(count).array(); }
    private byte[] crypt(boolean encrypt, byte[] value) {
        byte[] out=Crypto.aead(false,encrypt,k,nonce(nonce),h,value);
        nonce++; mixHash(encrypt ? out : value); return out;
    }
    /** @throws SecurityException 相手の公開鍵との X25519 の共有値がゼロのとき。握手は閉じる。 */
    public synchronized byte[] writeMessage(byte[] payload) {
        require(true);
        if(payload.length>65535-(step==0 ? 96 : 48)) throw new IllegalArgumentException("Noise のメッセージは65535バイトまでです");
        try {
            byte[] ep=Crypto.x25519Public(e); mixHash(ep); mixKey(ep);
            byte[] result;
            if(step==0) {
                dh(e,rs); byte[] encryptedStatic=crypt(true,Crypto.x25519Public(s)); dh(s,rs);
                result=Crypto.concat(ep,encryptedStatic,crypt(true,payload));
            } else {
                dh(e,re); dh(e,rs); mixPsk(); result=Crypto.concat(ep,crypt(true,payload));
            }
            step++; return result;
        } catch(RuntimeException failure) { close(); throw failure; }
    }
    /** @throws SecurityException 握手の認証・DH・メッセージの検証に失敗したとき。握手は閉じる。 */
    public synchronized byte[] readMessage(byte[] message) {
        require(false);
        try {
            if(message.length < (step==0 ? 96 : 48) || message.length>65535) throw new SecurityException("握手の長さが範囲外です");
            re=Arrays.copyOfRange(message,0,32); mixHash(re); mixKey(re);
            byte[] result;
            if(step==0) {
                dh(s,re); rs=crypt(false,Arrays.copyOfRange(message,32,80)); dh(s,rs);
                result=crypt(false,Arrays.copyOfRange(message,80,message.length));
            } else {
                dh(e,re); dh(s,re); mixPsk(); result=crypt(false,Arrays.copyOfRange(message,32,message.length));
            }
            step++; return result;
        } catch(RuntimeException failure) { close(); throw new SecurityException("握手を検証できません",failure); }
    }
    public synchronized byte[] remoteStatic() {
        if(closed || rs==null) throw new IllegalStateException("相手の鍵がありません"); return rs.clone();
    }
    public synchronized byte[] handshakeHash() {
        if(closed || step!=2) throw new IllegalStateException("握手が終わっていません"); return h.clone();
    }
    public synchronized NoiseTransport transport(LongSupplier monotonicNanos) {
        if(closed || step!=2 || split) throw new IllegalStateException("鍵を取り出せません");
        byte[][] keys=hkdf(ck,new byte[0],2);
        try {
            NoiseTransport transport=new NoiseTransport(keys[initiator ? 0 : 1],keys[initiator ? 1 : 0],monotonicNanos);
            split=true; Crypto.wipe(s); Crypto.wipe(e); Crypto.wipe(psk); Crypto.wipe(ck); Crypto.wipe(k); return transport;
        } finally { Crypto.wipe(keys[0]); Crypto.wipe(keys[1]); }
    }
    @Override public synchronized void close() {
        closed=true; Crypto.wipe(s); Crypto.wipe(e); Crypto.wipe(psk); Crypto.wipe(ck); Crypto.wipe(k);
    }
}
