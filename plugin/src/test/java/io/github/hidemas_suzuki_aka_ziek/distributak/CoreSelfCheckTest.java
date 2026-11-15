// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import static org.junit.Assert.*;

public class CoreSelfCheckTest {
    @Test public void handshakeTransportAndTotpUseInjectedTicker() {
        AtomicInteger calls = new AtomicInteger();
        CoreSelfCheck.run(Clock.fixed(Instant.ofEpochSecond(1700000010), ZoneOffset.UTC),
                () -> { calls.incrementAndGet(); return 123L; });
        assertTrue("転送と TOTP が時計を読む", calls.get() >= 6);
    }
}
