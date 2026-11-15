// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ReplayOrderingTest {
    @Test void unsignedTimestampBytesAndDistinctPeers() {
        var guard = new TimestampReplayGuard();
        byte[] a = new byte[32], b = new byte[32];
        a[0] = (byte) 0x80; b[0] = (byte) 0x81;
        byte[] before = Tai64n.encode(Instant.ofEpochSecond(117)); // 秒の末尾は 0x7f
        byte[] after = Tai64n.encode(Instant.ofEpochSecond(118)); // 秒の末尾は 0x80
        guard.accept(a, before);
        guard.accept(a, after);
        guard.accept(b, before);
        assertThrows(SecurityException.class, () -> guard.accept(a, before));
        assertThrows(SecurityException.class, () -> guard.accept(a, after));
        guard.accept(b, after);
    }
}
