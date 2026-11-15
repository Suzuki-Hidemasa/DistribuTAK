// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class UdpEndpointFloodTest {
    static List<byte[]> noise(byte[] valid) {
        byte[] bad=valid.clone();bad[bad.length-1]^=1;byte[] random=new byte[100];new Random(163).nextBytes(random);
        return List.of(random,bad,new byte[]{'D','T','C',1,0,0,0,1},AddressCookiesTest.first(200));
    }
    @ParameterizedTest @ValueSource(strings={"127.0.0.1","::1"})
    void realSocketSurvives2048DatagramsThenNewHandshakeAndPlaintext(String host) throws Exception {
        var f=new UdpEndpointTest();
        try(var a=f.new Node(1,host);var b=f.new Node(2,host);var socket=new DatagramSocket(new InetSocketAddress(host,0))) {
            f.connect(a,b);a.inbox.clear();b.inbox.clear();
            var noise=noise(a.sessions.send(b.id,new byte[]{1}).get(0).packet());
            for(int i=0;i<2048;i++) { byte[] wire=noise.get(i%noise.size());socket.send(new DatagramPacket(wire,wire.length,b.address())); }
            try(var c=f.new Node(3,host)) {
                f.connect(c,b);c.inbox.clear();b.inbox.clear();
                assertTrue(c.endpoint.send(b.id,new byte[]{8}));assertArrayEquals(new byte[]{8},UdpEndpointTest.take(b));
                assertTrue(b.endpoint.send(c.id,new byte[]{9}));assertArrayEquals(new byte[]{9},UdpEndpointTest.take(c));
                assertEquals(UdpEndpoint.CloseReason.RUNNING,b.endpoint.closeReason());
            }
        }
    }
    @Test void injected16384DatagramsDoNotRepeatSignaturesOrReachHandshake() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var received=new LinkedBlockingQueue<byte[]>();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            f.connect(a,b);
            try(var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,plain)->received.add(plain.clone()),Duration.ofDays(1))) {
                a.sessions.refresh();
                var local=(AdminState.CertificateChecks)SessionManagerTest.field(a.sessions,"localChecks");
                var peer=(AdminState.CertificateChecks)SessionManagerTest.field(f.peerState(a,b),"checks");
                long before=local.checks+peer.checks,heavy=(long)SessionManagerTest.field(a.sessions,"firstCalculations");
                var noise=noise(f.data(b,a,1));
                for(int i=0;i<16384;i++)io.inject(noise.get(i%noise.size()),JoinPortLimitsTest.SOURCE);
                io.inject(f.data(b,a,7),JoinPortLimitsTest.SOURCE);assertArrayEquals(new byte[]{7},received.poll(10,TimeUnit.SECONDS));
                assertEquals(before,local.checks+peer.checks);assertEquals(heavy,SessionManagerTest.field(a.sessions,"firstCalculations"));
                assertTrue(endpoint.rejectedPackets()>=12000);assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());
                var gate=(FirstPacketGate)SessionManagerTest.field(endpoint,"firstPackets");assertEquals(0,gate.sourceCount());
            }
        }
    }
}
