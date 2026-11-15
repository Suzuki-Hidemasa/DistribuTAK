// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

class SessionIdentityTest {
    @Test void capturedDataIdentityDoesNotChangeWhenTheActiveSessionRotates() {
        var fixture=new SessionManagerTest();
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)){
            fixture.connect(a,b);byte[] old=a.sessions.sessionId(b.id),wire=fixture.data(a,b,7);
            var received=b.sessions.receive(wire);assertArrayEquals(old,received.sessionId());
            Arrays.fill(a.sessions.sessionId(b.id),(byte)0);assertArrayEquals(old,a.sessions.sessionId(b.id));
            fixture.time.advance(120);var first=a.sessions.poll().get(0);
            var second=b.sessions.receive(first.packet());var confirm=a.sessions.receive(second.outbound().get(0).packet());
            b.sessions.receive(confirm.outbound().get(0).packet());
            assertFalse(Arrays.equals(old,a.sessions.sessionId(b.id)));assertArrayEquals(old,received.sessionId());
            assertArrayEquals(a.sessions.sessionId(b.id),b.sessions.sessionId(a.id));
        }
    }
    @Test void noActiveSessionIdentityIsExposedBeforeHandshakeConfirmation() {
        var fixture=new SessionManagerTest();
        try(var a=fixture.new Node(1);var b=fixture.new Node(2)){
            a.remember(b);b.remember(a);assertNull(a.sessions.sessionId(b.id));
            var second=b.sessions.receive(a.sessions.start(b.id).packet());assertNull(b.sessions.sessionId(a.id));
            var confirm=a.sessions.receive(second.outbound().get(0).packet());
            var data=b.sessions.receive(confirm.outbound().get(0).packet());
            assertEquals(16,data.sessionId().length);assertArrayEquals(a.sessions.sessionId(b.id),data.sessionId());
        }
    }
    @Test void endpointCarriesTheReceivingIdentityAndRejectsASendForAnOldSession()throws Exception {
        var fixture=new UdpEndpointTest();
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")){
            fixture.connect(a,b);byte[] old=a.endpoint.sessionId(b.id);assertNotNull(old);
            byte[] wrong=old.clone();wrong[0]^=1;
            assertFalse(a.endpoint.sendIfSession(b.id,wrong,new byte[]{8}));
            assertTrue(a.endpoint.sendIfSession(b.id,old,new byte[]{9}));assertArrayEquals(new byte[]{9},UdpEndpointTest.take(b));
            byte[] captured=b.sessionInbox.poll(5,TimeUnit.SECONDS),borrowed=b.borrowedSessions.poll(5,TimeUnit.SECONDS);
            assertArrayEquals(old,captured);assertNotNull(borrowed);
            UdpEndpointTest.await(()->Arrays.equals(new byte[16],borrowed));
            a.endpoint.start(b.id);UdpEndpointTest.await(()->!Arrays.equals(old,a.endpoint.sessionId(b.id))
                    &&Arrays.equals(a.endpoint.sessionId(b.id),b.endpoint.sessionId(a.id)));
            assertFalse(a.endpoint.sendIfSession(b.id,old,new byte[]{10}));
            assertTrue(a.endpoint.sendIfSession(b.id,a.endpoint.sessionId(b.id),new byte[]{11}));
            assertArrayEquals(new byte[]{11},UdpEndpointTest.take(b));assertArrayEquals(old,captured);
        }
    }
}
