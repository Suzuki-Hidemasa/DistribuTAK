// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.SOURCE;

class RandomFailureTest {
    @Test void memberSessionRandomFailureAlsoStopsEndpoint() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var notices=new LinkedBlockingQueue<UdpEndpoint.CloseReason>();
        try(var a=f.new Node(1);var b=f.new Node(2);
            var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1),notices::add)) {
            endpoint.rememberPeer(b.cert);
            var random=SessionManager.class.getDeclaredField("random");random.setAccessible(true);
            random.set(a.sessions,new SecureRandom() {
                @Override public void nextBytes(byte[] value) { throw new IllegalStateException("乱数の試験"); }
            });
            assertThrows(RandomFailure.class,()->endpoint.start(b.id));
            assertEquals(UdpEndpoint.CloseReason.RANDOM_FAILURE,notices.poll(3,TimeUnit.SECONDS));
            assertTrue(a.sessions.isClosed());assertTrue(io.output.isEmpty());
        }
    }
    @Test void cookieRandomFailureClosesWithSeparateReasonAndWipesBeforeNotice() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var ticks=new AtomicLong();
        var notices=new LinkedBlockingQueue<UdpEndpoint.CloseReason>();
        try(var a=f.new Node(1);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1),ticks::get,notices::add)) {
            var gate=(FirstPacketGate)SessionManagerTest.field(endpoint,"firstPackets");
            byte[] secret=(byte[])SessionManagerTest.field(gate.cookies,"current");
            var random=AddressCookies.class.getDeclaredField("random");random.setAccessible(true);
            random.set(gate.cookies,new SecureRandom() {
                @Override public void nextBytes(byte[] value) { throw new IllegalStateException("乱数の試験"); }
            });
            ticks.set(60_000_000_000L);io.inject(AddressCookiesTest.first(200),SOURCE);
            assertEquals(UdpEndpoint.CloseReason.RANDOM_FAILURE,notices.poll(3,TimeUnit.SECONDS));
            assertArrayEquals(new byte[32],secret);assertTrue(a.sessions.isClosed());
            endpoint.close();assertEquals(UdpEndpoint.CloseReason.RANDOM_FAILURE,endpoint.closeReason());assertTrue(notices.isEmpty());
        }
    }
}
