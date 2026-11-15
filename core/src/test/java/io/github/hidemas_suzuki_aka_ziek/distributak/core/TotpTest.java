// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TotpTest {
    // 乱数から作った32バイトの鍵（RFC の例の鍵ではない）。 / A 32-byte secret generated randomly (not the RFC example secret).
    static final byte[] SECRET=java.util.HexFormat.of().parseHex("4a1477f26c5e8365109de8c79154523811a6cd3a19da2465b0eb19f84e351225");
    static class MutableClock extends Clock {
        Instant now=Instant.ofEpochSecond(1234567890);
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return now; }
    }
    // 期待値は Python の hmac（HMAC-SHA256、30秒、8桁）で独立に計算した。0 と 29 は同じ区間、30 は次の区間。
    // Expected values were computed independently with Python hmac (HMAC-SHA256, 30 s, 8 digits). 0 and 29 fall in the same step; 30 is the next.
    @Test void totpSha256EightDigits() {
        long[] times={0,29,30,1700000000,1999999999,4102444800L};
        String[] values={"32865893","32865893","84364601","95571510","66810721","28208882"};
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
