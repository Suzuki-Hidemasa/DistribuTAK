// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TotpTest {
    static final byte[] SECRET="12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
    static class MutableClock extends Clock {
        Instant now=Instant.ofEpochSecond(1234567890);
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return now; }
    }
    @Test void rfc6238AppendixBSha256() {
        long[] times={59,1111111109,1111111111,1234567890,2000000000,20000000000L};
        String[] values={"46119246","68084774","67062674","91819424","90698825","77737706"};
        for(int i=0;i<times.length;i++) assertEquals(values[i],Totp.generate(SECRET,Instant.ofEpochSecond(times[i])));
    }
    @Test void windowAndReplayCache() {
        for(int offset=-2;offset<=2;offset++) {
            var clock=new MutableClock();
            var ticker=new AtomicLong();
            try(var verifier=new TotpVerifier(SECRET,clock,ticker::get)) {
                byte[] key=new byte[32]; String code=Totp.generate(SECRET,clock.now.plusSeconds(offset*30L));
                var first=verifier.verify(key,code);
                if(Math.abs(offset)>1) { assertEquals(TotpVerifier.Result.REJECTED,first);continue; }
                assertEquals(TotpVerifier.Result.VALID,first);
                assertEquals(TotpVerifier.Result.VALID,verifier.verify(key,code));
                assertTrue(verifier.consume(key,code));
                assertFalse(verifier.consume(key,code));
                String another=Totp.generate(SECRET,clock.now.plusSeconds(offset==1 ? -30 : 30));
                assertNotEquals(code,another);
                assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(key,another));
                assertEquals(TotpVerifier.Result.RETRANSMISSION,verifier.verify(key,code));
                key[0]=1;assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(key,code));
                key[0]=0;clock.now=clock.now.plusSeconds(10);ticker.set(10_000_000_000L);verifier.expire();
                assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(key,code));
                assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(key,Totp.generate(SECRET,clock.now.plusSeconds(30))));
            }
        }
    }
    @Test void invalidConsumeAndRevocation() {
        var clock=new MutableClock();
        try(var verifier=new TotpVerifier(SECRET,clock,()->0L)) {
            byte[] key=new byte[32]; String valid=Totp.generate(SECRET,clock.now);
            assertFalse(verifier.consume(key,"not-code"));
            assertEquals(TotpVerifier.Result.VALID,verifier.verify(key,valid));
            verifier.revoke();
            assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(key,valid));
            assertFalse(verifier.consume(key,valid));
        }
    }
    @Test void expiredInvitationAndMalformedCodes() {
        var clock=new MutableClock();
        var ticker=new AtomicLong();
        try(var verifier=new TotpVerifier(SECRET,clock,ticker::get)) {
            assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(new byte[32],"abcd1234"));
            clock.now=clock.now.plusSeconds(24*3600);ticker.set(Duration.ofHours(24).toNanos());verifier.expire();
            assertEquals(TotpVerifier.Result.REJECTED,verifier.verify(new byte[32],Totp.generate(SECRET,clock.now)));
        }
    }
}
