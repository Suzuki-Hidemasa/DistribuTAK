// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.function.LongSupplier;

/** Noise の転送鍵。順序付きの口と、明示した番号で開くデータグラムの口を持つ。混用しない。 */
public final class NoiseTransport implements AutoCloseable {
    public static final long REKEY_MESSAGES = 1L << 60;
    public static final long REJECT_AFTER = -8193L; // unsigned: 2^64 − 2^13 − 1
    private final byte[] sending, receiving;
    private final LongSupplier ticker;
    private final long created;
    private long sent, received;
    private boolean closed;
    private final ReplayWindow replay=new ReplayWindow();
    private int mode;
    NoiseTransport(byte[] sending, byte[] receiving, LongSupplier monotonicNanos) {
        this(sending,receiving,monotonicNanos,0,0);
    }
    NoiseTransport(byte[] sending, byte[] receiving, LongSupplier monotonicNanos, long sent, long received) {
        Crypto.length(sending,32); Crypto.length(receiving,32);
        this.sending=sending.clone(); this.receiving=receiving.clone();
        ticker=monotonicNanos; created=ticker.getAsLong(); this.sent=sent; this.received=received;
    }
    private long age() { return ticker.getAsLong()-created; }
    public synchronized boolean needsRehandshake() {
        return closed || age()>=Duration.ofMinutes(2).toNanos() || Long.compareUnsigned(sent,REKEY_MESSAGES)>=0;
    }
    private void usable(long counter) {
        if(closed) throw new IllegalStateException("セッションは閉じています");
        if(age()>Duration.ofMinutes(3).toNanos() || Long.compareUnsigned(counter,REJECT_AFTER)>0) {
            close(); throw new SecurityException("鍵の使用上限を超えました");
        }
    }
    public synchronized byte[] send(byte[] plaintext) {
        mode(1);
        if(plaintext.length>65519) throw new IllegalArgumentException("Noise の中身が長すぎます");
        usable(sent); byte[] out=Crypto.aead(false,true,sending,NoiseHandshake.nonce(sent),new byte[0],plaintext); sent++; return out;
    }
    public synchronized byte[] receive(byte[] ciphertext) {
        mode(1);
        if(ciphertext.length>65535) throw new IllegalArgumentException("Noise の暗号文が長すぎます");
        usable(received); byte[] out=Crypto.aead(false,false,receiving,NoiseHandshake.nonce(received),new byte[0],ciphertext); received++; return out;
    }
    private void mode(int required) {
        if(mode!=0 && mode!=required) throw new IllegalStateException("転送の口を混用できません");
        mode=required;
    }
    public synchronized long nextSendingCounter() { return sent; }
    public synchronized boolean isClosed() { return closed; }
    /** poll で期限を反映するための口。3分ちょうどまでは使う。 */
    public synchronized void expire() { if(age()>Duration.ofMinutes(3).toNanos()) close(); }
    public synchronized byte[] sendDatagram(byte[] plaintext, byte[] aad) {
        mode(2);
        if(plaintext.length>65519) throw new IllegalArgumentException("Noise の中身が長すぎます");
        usable(sent);
        byte[] out=Crypto.aead(false,true,sending,NoiseHandshake.nonce(sent),aad,plaintext);
        sent++;return out;
    }
    public synchronized byte[] receiveDatagram(long counter, byte[] ciphertext, byte[] aad) {
        mode(2);
        if(ciphertext.length<16 || ciphertext.length>65535) throw new SecurityException("暗号文の長さが範囲外です");
        // 相手が書き換えた番号で、正しい鍵を閉じない。
        if(Long.compareUnsigned(counter,REJECT_AFTER)>0) throw new SecurityException("番号の上限を超えています");
        usable(0);replay.check(counter);
        byte[] out=Crypto.aead(false,false,receiving,NoiseHandshake.nonce(counter),aad,ciphertext);
        replay.commit(counter);return out;
    }
    @Override public synchronized void close() { closed=true; Crypto.wipe(sending); Crypto.wipe(receiving); }
}
