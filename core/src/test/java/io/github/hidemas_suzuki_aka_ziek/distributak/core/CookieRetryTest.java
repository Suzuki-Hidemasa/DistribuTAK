// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.SOURCE;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.OTHER;

class CookieRetryTest {
    static byte[] challenge(AddressCookies cookies,byte[] first) { return CookieWire.challenge(Crypto.blake2s(first),cookies.issue(first,SOURCE)); }
    static void reject(UdpEndpoint endpoint,JoinPortLimitsTest.MemoryIo io,byte[] challenge,java.net.InetSocketAddress source) throws Exception {
        long before=endpoint.rejectedPackets();io.inject(challenge,source);UdpEndpointTest.await(()->endpoint.rejectedPackets()>before);assertTrue(io.output.isEmpty());
    }
    static byte[] answer(UdpEndpoint endpoint,JoinPortLimitsTest.MemoryIo io,byte[] challenge,byte[] first) throws Exception {
        reject(endpoint,io,challenge,OTHER);
        byte[] bad=challenge.clone();bad[8]^=1;reject(endpoint,io,bad,SOURCE);
        io.inject(challenge,SOURCE);byte[] proof=io.take().wire();
        try(var frame=CookieWire.decode(proof)) { assertEquals(CookieWire.PROOF,frame.kind());assertArrayEquals(first,frame.first()); }
        reject(endpoint,io,challenge,SOURCE);return proof;
    }
    @Test void memberLostChallengeAndProofRecoverWithoutExtendingAttempt() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var cookies=new AddressCookies(()->f.time.nanos);
            var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofMillis(10))) {
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,SOURCE);endpoint.start(b.id);
            byte[] first=io.take().wire();byte[] lostChallenge=challenge(cookies,first);
            f.time.advance(5);assertArrayEquals(first,io.take().wire());
            answer(endpoint,io,lostChallenge,first); // PROOFを落とす。
            f.time.advance(5);assertArrayEquals(first,io.take().wire());
            byte[] current=challenge(cookies,first),proof=answer(endpoint,io,current,first);
            try(var frame=CookieWire.decode(proof)) {
                io.inject(b.sessions.receive(frame.first()).outbound().get(0).packet(),SOURCE);
            }
            b.sessions.receive(io.take().wire());UdpEndpointTest.await(()->endpoint.isEstablished(b.id));
            assertTrue(endpoint.send(b.id,new byte[]{7}));assertArrayEquals(new byte[]{7},b.sessions.receive(io.take().wire()).plaintext());
            reject(endpoint,io,current,SOURCE);endpoint.close();io.inject(current,SOURCE);assertTrue(io.output.isEmpty());
        }
        var time=new SessionManagerTest();var otherIo=new JoinPortLimitsTest.MemoryIo();
        try(var a=time.new Node(1);var b=time.new Node(2);var cookies=new AddressCookies(()->time.time.nanos);
            var endpoint=new UdpEndpoint(a.sessions,a.state,otherIo,(id,p)->{},Duration.ofDays(1))) {
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,SOURCE);endpoint.start(b.id);byte[] first=otherIo.take().wire();
            time.time.advance(90);reject(endpoint,otherIo,challenge(cookies,first),SOURCE);assertFalse(a.sessions.isHandshaking(b.id));
            endpoint.start(b.id);assertEquals(SessionPacket.FIRST,SessionPacket.decode(otherIo.take().wire()).kind());
        }
    }
    @Test void joinLostChallengeAndProofRecoverWithinOriginalTenSeconds() throws Exception {
        var f=new JoinHandshakeTest();var io=new JoinPortLimitsTest.MemoryIo();
        try(var invite=f.invitation();var joiner=f.joiner(invite);var admin=f.admin(invite);var material=f.material();
            var cookies=new AddressCookies(f.tick::get);var endpoint=new UdpEndpoint(io,(id,p)->{},f.tick::get)) {
            var done=endpoint.join(invite,joiner,joined->{
                byte[] key=joined.groupKey();
                try { return new SessionManager(joined.state(),joined.certificate(),f.f.handshake,key,joined.groupKeyVersion(),f.f.clock,f.tick::get,256); }
                finally { Crypto.wipe(key); }
            });
            byte[] first=io.take().wire();challenge(cookies,first); // CHALLENGEを落とす。
            f.tick.set(JoinPort.SECOND);assertArrayEquals(first,io.take().wire());
            answer(endpoint,io,challenge(cookies,first),first); // PROOFを落とす。
            f.tick.set(2*JoinPort.SECOND);assertArrayEquals(first,io.take().wire());
            byte[] current=challenge(cookies,first);byte[] proof=answer(endpoint,io,current,first),response;
            try(var outer=CookieWire.decode(proof);var request=JoinWire.decode(outer.first())) {
                response=admin.respond(request.body(),f.adminX,f.f.a,material);
                var engine=(JoinPort)SessionManagerTest.field(endpoint,"joins");
                synchronized(engine) { assertEquals(0L,SessionManagerTest.field(SessionManagerTest.field(engine,"pending"),"started")); }
                io.inject(JoinWire.ready(request.invitation(),request.transfer(),response.length),SOURCE);
                long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
                while(!done.isDone()) {
                    assertTrue(System.nanoTime()<deadline,"加入の試験の期限");
                    var outgoing=io.output.poll(100,TimeUnit.MILLISECONDS);if(outgoing==null)continue;
                    try(var fetch=JoinWire.decode(outgoing.wire())) {
                        assertEquals(JoinWire.FETCH,fetch.kind());io.inject(JoinWire.data(fetch.invitation(),fetch.transfer(),response,fetch.index()),SOURCE);
                    }
                }
            }
            assertNotNull(done.get(1,TimeUnit.SECONDS));Crypto.wipe(response);reject(endpoint,io,current,SOURCE);
            endpoint.close();io.inject(current,SOURCE);assertTrue(io.output.isEmpty());
        }
    }
    @Test void expiredJoinChallengeCannotExtendDeadlineOrSendProof() throws Exception {
        var f=new JoinHandshakeTest();var io=new JoinPortLimitsTest.MemoryIo();
        try(var invite=f.invitation();var joiner=f.joiner(invite);var cookies=new AddressCookies(f.tick::get);
            var endpoint=new UdpEndpoint(io,(id,p)->{},f.tick::get)) {
            var done=endpoint.join(invite,joiner,joined->null);byte[] first=io.take().wire();f.tick.set(JoinPort.LIFETIME);
            io.inject(challenge(cookies,first),SOURCE);UdpEndpointTest.await(endpoint::isTerminated);
            assertTrue(done.isDone());assertThrows(Exception.class,done::get);assertTrue(io.output.isEmpty());assertEquals(UdpEndpoint.CloseReason.JOIN_FAILURE,endpoint.closeReason());
        }
    }
}
