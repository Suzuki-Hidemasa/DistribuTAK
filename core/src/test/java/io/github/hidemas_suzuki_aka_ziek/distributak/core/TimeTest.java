// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TimeTest {
    @Test void tai64nEncodingAndValidation() {
        Instant time=Instant.ofEpochSecond(1,123456789);
        assertArrayEquals(CryptoTest.hex("400000000000000b075bcd15"),Tai64n.encode(time));
        assertEquals(time,Tai64n.decode(Tai64n.encode(time)));
        assertThrows(IllegalArgumentException.class,()->Tai64n.decode(new byte[11]));
        assertThrows(IllegalArgumentException.class,()->Tai64n.decode(CryptoTest.hex("400000000000000b3b9aca00")));
    }
    @Test void newestTimestampPerPeerWithoutClockBound() {
        var replay=new TimestampReplayGuard(); byte[] a=new byte[32],b=new byte[32];b[0]=1;
        byte[] future=Tai64n.encode(Instant.ofEpochSecond(9999999999L));
        replay.accept(a,future); replay.accept(b,future);
        assertThrows(SecurityException.class,()->replay.accept(a,future));
        assertThrows(SecurityException.class,()->replay.accept(a,Tai64n.encode(Instant.EPOCH)));
        replay.accept(a,Tai64n.encode(Instant.ofEpochSecond(10000000000L)));
    }
    @Test void transportTimeAndUnsignedCounterLimits() {
        var clock=new AtomicLong();
        try(var t=new NoiseTransport(new byte[32],new byte[32],clock::get)) {
            clock.set(119_999_999_999L);assertFalse(t.needsRehandshake());
            clock.set(120_000_000_000L);assertTrue(t.needsRehandshake());
            clock.set(180_000_000_000L);t.send(new byte[0]);
            clock.incrementAndGet();assertThrows(SecurityException.class,()->t.send(new byte[0]));
        }
        try(var t=new NoiseTransport(new byte[32],new byte[32],()->0L,NoiseTransport.REKEY_MESSAGES,0)) { assertTrue(t.needsRehandshake()); }
        try(var t=new NoiseTransport(new byte[32],new byte[32],()->0L,NoiseTransport.REJECT_AFTER,0)) {
            t.send(new byte[0]); assertThrows(SecurityException.class,()->t.send(new byte[0]));
        }
        try(var t=new NoiseTransport(new byte[32],new byte[32],()->0L,0,NoiseTransport.REJECT_AFTER+1)) {
            assertThrows(SecurityException.class,()->t.receive(new byte[16]));
        }
        try(var t=new NoiseTransport(new byte[32],new byte[32],()->0L,0,NoiseTransport.REJECT_AFTER)) {
            byte[] ct=Crypto.aead(false,true,new byte[32],NoiseHandshake.nonce(NoiseTransport.REJECT_AFTER),new byte[0],new byte[]{1});
            assertArrayEquals(new byte[]{1},t.receive(ct));
            assertThrows(SecurityException.class,()->t.receive(ct));
        }
        try(var t=new NoiseTransport(new byte[32],new byte[32],()->0L,NoiseTransport.REKEY_MESSAGES-1,0)) {
            assertFalse(t.needsRehandshake());t.send(new byte[0]);assertTrue(t.needsRehandshake());
        }
    }
}
