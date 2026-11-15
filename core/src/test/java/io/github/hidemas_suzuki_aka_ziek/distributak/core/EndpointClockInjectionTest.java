// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EndpointClockInjectionTest {
    @Test void memberGateAndJoinPortUseSameInjectedClockIncludingCookieBoundary() throws Exception {
        var fixture=new UdpEndpointTest();AtomicLong time=new AtomicLong();LongSupplier ticker=time::get;
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.close();
            var manager=new SessionManager(a.state,a.cert,a.secret,fixture.psk,0,fixture.clock,ticker,256);
            var socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",0));
            try(var endpoint=new UdpEndpoint(manager,a.state,new UdpEndpoint.SocketIo(socket),(id,plain)->{},Duration.ofDays(1),ticker,reason->{})) {
                b.endpoint.rememberPeer(a.cert);byte[] first=b.sessions.start(a.id).packet();
                var gate=(FirstPacketGate)SessionManagerTest.field(endpoint,"firstPackets");
                byte[] wire=gate.challenge(first,b.address());
                try(var challenge=CookieWire.decode(wire)) {
                    time.set(29_999_999_999L);assertTrue(gate.accept(challenge.cookie(),first,b.address()));
                    time.set(30_000_000_000L);assertFalse(gate.accept(challenge.cookie(),first,b.address()));
                }
                Object joins=SessionManagerTest.field(endpoint,"joins");
                assertSame(ticker,SessionManagerTest.field(joins,"clock"));
                Crypto.wipe(first);Crypto.wipe(wire);
            }
        }
    }
}
