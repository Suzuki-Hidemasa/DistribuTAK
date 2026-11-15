// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class TotpLifetimeTest {
    private static final long DAY=Duration.ofHours(24).toNanos();
    private static final long CACHE=Duration.ofSeconds(10).toNanos();

    @Test void wallClockRollbackKeepsInvitationAndUsesCurrentWallTimeForCode() throws Exception {
        var wall=new TotpTest.MutableClock();var ticker=new AtomicLong();
        try(var v=new TotpVerifier(TotpTest.SECRET,wall,ticker::get)) {
            String original=Totp.generate(TotpTest.SECRET,wall.now);
            wall.now=wall.now.minusSeconds(86400);ticker.set(Duration.ofHours(1).toNanos());v.expire();
            assertEquals(TotpVerifier.Result.VALID,v.verify(new byte[32],Totp.generate(TotpTest.SECRET,wall.now)));
            assertEquals(TotpVerifier.Result.REJECTED,v.verify(new byte[32],original));
            assertArrayEquals(TotpTest.SECRET,SecretAssertions.bytes(v,"secret"));
        }
    }
    @Test void wallClockJumpForwardKeepsInvitationUntilMonotonicDeadlineAndExpiryWipes() throws Exception {
        var wall=new TotpTest.MutableClock();var ticker=new AtomicLong();
        try(var v=new TotpVerifier(TotpTest.SECRET,wall,ticker::get)) {
            byte[] secret=SecretAssertions.bytes(v,"secret");
            wall.now=wall.now.plusSeconds(10*86400);ticker.set(DAY-1);
            assertEquals(TotpVerifier.Result.VALID,v.verify(new byte[32],Totp.generate(TotpTest.SECRET,wall.now)));
            ticker.set(DAY);v.expire();SecretAssertions.zero(secret);
            wall.now=wall.now.minusSeconds(10*86400);
            assertEquals(TotpVerifier.Result.REJECTED,v.verify(new byte[32],Totp.generate(TotpTest.SECRET,wall.now)));
        }
    }
    @Test void consumeWipesSecretAndCacheExpiresByMonotonicTimeDespiteWallChanges() throws Exception {
        long consumedAt=Duration.ofHours(23).toNanos();
        for(int direction:new int[]{-1,1}) {
            var wall=new TotpTest.MutableClock();var ticker=new AtomicLong();
            try(var v=new TotpVerifier(TotpTest.SECRET,wall,ticker::get)) {
                byte[] key=TotpTest.SECRET.clone();String code=Totp.generate(TotpTest.SECRET,wall.now);
                byte[] secret=SecretAssertions.bytes(v,"secret");
                ticker.set(consumedAt);
                assertTrue(v.consume(key,code));SecretAssertions.zero(secret);
                byte[] usedCode=SecretAssertions.bytes(v,"usedCode"),usedKey=SecretAssertions.bytes(v,"usedKey");
                wall.now=wall.now.plusSeconds(direction*2*86400);ticker.set(consumedAt+CACHE-1);v.expire();
                assertEquals(TotpVerifier.Result.RETRANSMISSION,v.verify(key,code));
                assertNotNull(SecretAssertions.field(v,"usedCode"));
                ticker.set(consumedAt+CACHE);v.expire();SecretAssertions.zero(usedCode);SecretAssertions.zero(usedKey);
                assertNull(SecretAssertions.field(v,"usedCode"));assertNull(SecretAssertions.field(v,"usedKey"));
                wall.now=wall.now.minusSeconds(direction*2*86400);
                assertEquals(TotpVerifier.Result.REJECTED,v.verify(key,code));
                ticker.set(consumedAt+CACHE-1);
                assertEquals(TotpVerifier.Result.REJECTED,v.verify(key,code));
            }
        }
    }
    @Test void monotonicClockRollbackInvalidatesInvitationAndCache() throws Exception {
        for(boolean consume:new boolean[]{false,true}) {
            var wall=new TotpTest.MutableClock();var ticker=new AtomicLong(100);
            try(var v=new TotpVerifier(TotpTest.SECRET,wall,ticker::get)) {
                byte[] key=TotpTest.SECRET.clone();String code=Totp.generate(TotpTest.SECRET,wall.now);
                byte[] secret=SecretAssertions.bytes(v,"secret");
                if(consume) assertTrue(v.consume(key,code));
                byte[] usedCode=SecretAssertions.bytes(v,"usedCode"),usedKey=SecretAssertions.bytes(v,"usedKey");
                ticker.set(200);v.expire();ticker.set(150);v.expire();
                SecretAssertions.zero(secret);
                if(consume) { SecretAssertions.zero(usedCode);SecretAssertions.zero(usedKey); }
                assertNull(SecretAssertions.field(v,"usedCode"));assertNull(SecretAssertions.field(v,"usedKey"));
                assertEquals(TotpVerifier.Result.REJECTED,v.verify(key,code));
                ticker.set(201);assertEquals(TotpVerifier.Result.REJECTED,v.verify(key,code));
            }
        }
    }
}
