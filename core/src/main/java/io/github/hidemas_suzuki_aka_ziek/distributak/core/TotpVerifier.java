// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.LongSupplier;

/** 招待ごとに一つ作る。上位の層は証明書の発行時に consume を呼び、期限に expire を呼ぶ。 */
public final class TotpVerifier implements AutoCloseable {
    public enum Result { VALID, RETRANSMISSION, REJECTED }
    private final byte[] secret;
    private final Clock clock;
    private final LongSupplier ticker;
    private final long created;
    private long lastTick;
    private byte[] usedCode,usedKey;
    private long consumedAt;
    private boolean closed,consumed;
    /**
     * @param clock TOTP の30秒の区切りに使う壁時計。
     * @param monotonicNanos 招待と再送の寿命をナノ秒で数える単調時計。
     * Android では眠っている間も進む時計（elapsedRealtime の系統）を渡すこと。
     * 眠っている間に止まる時計は寿命が延びるので渡さない。
     */
    public TotpVerifier(byte[] secret, Clock clock, LongSupplier monotonicNanos) {
        Crypto.length(secret,32);
        this.clock=Objects.requireNonNull(clock,"clock");ticker=Objects.requireNonNull(monotonicNanos,"monotonicNanos");
        created=ticker.getAsLong();lastTick=created;this.secret=secret.clone();
    }
    public synchronized Result verify(byte[] joiningPublicKey, String code) {
        Crypto.length(joiningPublicKey,32);
        expire();
        if(closed || code==null || !code.matches("[0-9]{8}")) return Result.REJECTED;
        byte[] supplied=code.getBytes(StandardCharsets.US_ASCII);
        try {
            if(consumed) {
                return Crypto.equal(supplied,usedCode) & Crypto.equal(joiningPublicKey,usedKey) ? Result.RETRANSMISSION : Result.REJECTED;
            }
            Instant now=clock.instant();
            long step=Math.floorDiv(now.getEpochSecond(),30); boolean matches=false;
            for(int delta=-1;delta<=1;delta++) {
                if(step+delta<0) continue;
                byte[] candidate=Totp.atStepBytes(secret,step+delta);
                try { matches |= Crypto.equal(candidate,supplied); } finally { Crypto.wipe(candidate); }
            }
            if(!matches) return Result.REJECTED;
            return Result.VALID;
        } finally { Crypto.wipe(supplied); }
    }
    /** 新たな証明書の発行とこの呼び出しは、上位の層で一つの処理として直列に行う。 */
    public synchronized boolean consume(byte[] joiningPublicKey, String code) {
        if(verify(joiningPublicKey,code)!=Result.VALID) return false;
        consumed=true; consumedAt=lastTick;
        usedCode=code.getBytes(StandardCharsets.US_ASCII);usedKey=joiningPublicKey.clone();Crypto.wipe(secret);
        return true;
    }
    /** 第1段はタイマーを持たない。上位のループから10秒と24時間の期限に呼ぶ。 */
    public synchronized void expire() {
        if(closed) return;
        long now=ticker.getAsLong();
        if(now-lastTick<0) { close();return; }
        lastTick=now;
        if(consumed) {
            if(now-consumedAt>=Duration.ofSeconds(10).toNanos()) clearCache();
        } else {
            if(now-created>=Duration.ofHours(24).toNanos()) close();
        }
    }
    public synchronized void revoke() { close(); }
    // 第4段の所有者が、expire 後に鎖や暗号化した返事も一緒に消すための状態。
    public synchronized boolean isClosed() { return closed; }
    public synchronized boolean hasRetransmission() { return !closed && consumed && usedKey!=null; }
    private void clearCache() { Crypto.wipe(usedCode); Crypto.wipe(usedKey); usedCode=null;usedKey=null; }
    @Override public synchronized void close() { closed=true; Crypto.wipe(secret); clearCache(); }
}
