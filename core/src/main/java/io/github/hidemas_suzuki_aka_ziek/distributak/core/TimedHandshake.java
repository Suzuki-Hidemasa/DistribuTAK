// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.function.LongSupplier;
import java.util.function.Predicate;

/** TAI64N 12バイト ‖ 証明書。相手の証明書の検査後に1通目の時刻を確定する。 */
public final class TimedHandshake implements AutoCloseable {
    /** 失敗なら例外を投げる。certificate と Noise の相手の鍵を両方確かめる。 */
    @FunctionalInterface public interface CertificateVerifier { void verify(byte[] certificate, byte[] peerHandshake); }
    private final NoiseHandshake noise;
    private final boolean initiator;
    private final Clock clock;
    private final TimestampReplayGuard replay;
    private final CertificateVerifier verifier;
    private boolean closed, peerVerified;
    public TimedHandshake(NoiseHandshake noise, boolean initiator, Clock clock, TimestampReplayGuard replay, CertificateVerifier verifier) {
        if(initiator!=noise.isInitiator()) throw new IllegalArgumentException("Noise と時刻の層の役割が違います");
        this.noise=noise;this.initiator=initiator;this.clock=java.util.Objects.requireNonNull(clock);
        this.replay=java.util.Objects.requireNonNull(replay);this.verifier=java.util.Objects.requireNonNull(verifier);
    }
    public synchronized byte[] writeMessage(byte[] certificate) {
        return writeMessage(certificate,clock.instant());
    }
    // セッション層が自分の送信時刻を単調にするために使う。受信時の時計は置き換えない。
    synchronized byte[] writeMessage(byte[] certificate,Instant timestamp) {
        if(closed) throw new IllegalStateException("握手は閉じています");
        if(!initiator && !peerVerified) throw new IllegalStateException("相手の証明書をまだ確かめていません");
        byte[] payload=Crypto.concat(Tai64n.encode(timestamp),certificate);
        try { return noise.writeMessage(payload); } finally { Crypto.wipe(payload); }
    }
    public synchronized Received readMessage(byte[] message) {
        return readMessage(message,received->true);
    }
    /** 証明書を検査した後、1通目を受けるか決める。false なら時刻を確定せず握手を閉じる。 */
    synchronized Received readMessage(byte[] message,Predicate<Received> acceptFirst) {
        if(closed) throw new IllegalStateException("握手は閉じています");
        byte[] payload=noise.readMessage(message);
        try {
            if(payload.length<12) throw new SecurityException("時刻の値がありません");
            byte[] timestamp=Arrays.copyOf(payload,12); Instant peerTime=Tai64n.decode(timestamp);
            byte[] peer=noise.remoteStatic(), certificate=Arrays.copyOfRange(payload,12,payload.length);
            if(!initiator) replay.check(peer,timestamp);
            verifier.verify(certificate.clone(),peer.clone());
            var received=new Received(peerTime,Duration.between(clock.instant(),peerTime),certificate);
            if(!initiator && !acceptFirst.test(received)) { close();return received; }
            if(!initiator) replay.commit(peer,timestamp);
            peerVerified=true;
            return received;
        } catch(RuntimeException failure) { close();throw new SecurityException("握手の中身を検証できません",failure); }
        finally { Crypto.wipe(payload); }
    }
    public synchronized NoiseTransport transport(LongSupplier monotonicNanos) {
        if(closed) throw new IllegalStateException("握手は閉じています");
        if(!peerVerified) throw new IllegalStateException("相手の証明書をまだ確かめていません");
        return noise.transport(monotonicNanos);
    }
    public synchronized byte[] remoteStatic() { return noise.remoteStatic(); }
    @Override public synchronized void close() { closed=true;noise.close(); }
    public record Received(Instant peerTime, Duration peerClockOffset, byte[] certificate) {
        public Received { certificate=certificate.clone(); }
        @Override public byte[] certificate() { return certificate.clone(); }
    }
}
