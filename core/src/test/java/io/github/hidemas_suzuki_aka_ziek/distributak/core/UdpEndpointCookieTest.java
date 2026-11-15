// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.SOURCE;

class UdpEndpointCookieTest {
    @Test void nakedFirstDoesNoHandshakeAndProofCompletesWithUnchangedInnerBytes() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(b.sessions,b.state,io,(id,plain)->{},Duration.ofDays(1))) {
            a.remember(b);endpoint.setPeerAddress(a.id,SOURCE);byte[] first=a.sessions.start(b.id).packet();
            io.inject(first,SOURCE);var challenge=io.take();
            assertTrue(CookieWire.isCookie(challenge.wire()));assertEquals(SOURCE,challenge.source());assertTrue(challenge.wire().length<=first.length);
            assertFalse(b.sessions.isHandshaking(a.id));assertEquals(0L,SessionManagerTest.field(b.sessions,"firstCalculations"));
            try(var frame=CookieWire.decode(challenge.wire())) {
                io.inject(CookieWire.proof(frame.cookie(),first),SOURCE);
            }
            byte[] second=io.take().wire();assertEquals(1L,SessionManagerTest.field(b.sessions,"firstCalculations"));assertEquals(SessionPacket.SECOND,SessionPacket.decode(second).kind());
            io.inject(a.sessions.receive(second).outbound().get(0).packet(),SOURCE);
            UdpEndpointTest.await(()->endpoint.isEstablished(a.id));
            assertTrue(endpoint.send(a.id,new byte[]{9}));assertArrayEquals(new byte[]{9},a.sessions.receive(io.take().wire()).plaintext());
        }
    }
    @Test void nakedRequestDoesNotPinAndCopiedProofFromOtherAddressIsRejected() throws Exception {
        try(var f=new JoinPortLimitsTest.AdminFixture()) {
            byte[] request=JoinWire.request(f.id,f.transfer,f.request);f.io.inject(request,SOURCE);
            try(var frame=CookieWire.decode(f.io.take().wire())) {
                assertEquals(0,f.calls.get());assertNull(SessionManagerTest.field(SessionManagerTest.field(f.endpoint,"joins"),"active"));
                long before=f.endpoint.rejectedPackets();f.io.inject(CookieWire.proof(frame.cookie(),request),JoinPortLimitsTest.OTHER);
                UdpEndpointTest.await(()->f.endpoint.rejectedPackets()>before);assertEquals(0,f.calls.get());
                f.io.inject(CookieWire.proof(frame.cookie(),request),SOURCE);
                assertEquals(JoinWire.READY,JoinWire.decode(f.io.take().wire()).kind());assertEquals(1,f.calls.get());
            }
        }
    }
    @Test void invalidProofsAt128PerSecondLeaveCapacityForRealHandshake() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var ticks=new java.util.concurrent.atomic.AtomicLong();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(b.sessions,b.state,io,(id,p)->{},Duration.ofDays(1),ticks::get)) {
            a.remember(b);endpoint.setPeerAddress(a.id,SOURCE);byte[] first=a.sessions.start(b.id).packet();io.inject(first,SOURCE);
            byte[] cookie;try(var challenge=CookieWire.decode(io.take().wire())) { cookie=challenge.cookie().clone(); }
            for(int second=0;second<3;second++) {
                ticks.set(second*1_000_000_000L);long before=endpoint.rejectedPackets();
                for(int n=0;n<128;n++)io.inject(CookieWire.proof(new byte[40],first),SOURCE);
                UdpEndpointTest.await(()->endpoint.rejectedPackets()>=before+128);
                assertEquals(0L,SessionManagerTest.field(b.sessions,"firstCalculations"));
            }
            io.inject(CookieWire.proof(cookie,first),SOURCE);byte[] second=io.take().wire();
            io.inject(a.sessions.receive(second).outbound().get(0).packet(),SOURCE);UdpEndpointTest.await(()->endpoint.isEstablished(a.id));
            assertEquals(1L,SessionManagerTest.field(b.sessions,"firstCalculations"));
        }
    }
    @Test void largestCertificateStillFitsProofAndInnerFirstKeepsVersionOne() {
        var f=new SessionManagerTest();f.time.millis=Long.MAX_VALUE-AdminRecords.CERTIFICATE_LIFETIME_MILLIS;
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            a.remember(b);byte[] first=a.sessions.start(b.id).packet();assertTrue(first.length<=1184);
            byte[] proof=CookieWire.proof(new byte[40],first);
            try(var frame=CookieWire.decode(proof)) { assertArrayEquals(first,frame.first());assertEquals(1,first[3]); }
        }
    }

    @Test void cookieClockFailureClosesAndWipesItsSecretBeforeNotification() throws Exception {
        for(boolean throwing:new boolean[]{false,true}) {
            var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var ticks=new java.util.concurrent.atomic.AtomicLong(100);
            var broken=new java.util.concurrent.atomic.AtomicBoolean();var notices=new LinkedBlockingQueue<UdpEndpoint.CloseReason>();
            try(var a=f.new Node(1);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1),
                    ()->{if(broken.get())throw new IllegalStateException("時計の試験");return ticks.get();},notices::add)) {
                var gate=(FirstPacketGate)SessionManagerTest.field(endpoint,"firstPackets");byte[] key=(byte[])SessionManagerTest.field(gate.cookies,"current");
                io.inject(AddressCookiesTest.first(200),SOURCE);io.take();
                if(throwing)broken.set(true);else ticks.set(99);
                io.inject(AddressCookiesTest.first(200),SOURCE);
                assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,notices.poll(3,TimeUnit.SECONDS));
                assertArrayEquals(new byte[32],key);endpoint.close();assertTrue(notices.isEmpty());
            }
        }
    }

    @Test void exhaustedSourceDoesNotBlockAnotherVerifiedSourceHandshake() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var ticks=new java.util.concurrent.atomic.AtomicLong();
        var other=new java.net.InetSocketAddress("127.0.0.2",50000);
        try(var a=f.new Node(1);var b=f.new Node(2);var c=f.new Node(3);
            var endpoint=new UdpEndpoint(b.sessions,b.state,io,(id,p)->{},Duration.ofDays(1),ticks::get)) {
            a.remember(b);c.remember(b);endpoint.setPeerAddress(a.id,SOURCE);endpoint.setPeerAddress(c.id,other);
            byte[] first=a.sessions.start(b.id).packet();io.inject(first,SOURCE);byte[] proof;
            try(var challenge=CookieWire.decode(io.take().wire())) { proof=CookieWire.proof(challenge.cookie(),first); }
            for(int n=0;n<64;n++)io.inject(proof,SOURCE);
            byte[] second=io.take().wire();assertEquals(SessionPacket.SECOND,SessionPacket.decode(second).kind());
            long before=endpoint.rejectedPackets();io.inject(new byte[1],SOURCE);UdpEndpointTest.await(()->endpoint.rejectedPackets()>before);
            long limit=endpoint.rejectedPackets();io.inject(proof,SOURCE);UdpEndpointTest.await(()->endpoint.rejectedPackets()>limit);assertTrue(io.output.isEmpty());
            byte[] fresh=c.sessions.start(b.id).packet();io.inject(fresh,other);
            try(var challenge=CookieWire.decode(io.take().wire())) { io.inject(CookieWire.proof(challenge.cookie(),fresh),other); }
            var sent=io.take();assertEquals(other,sent.source());io.inject(c.sessions.receive(sent.wire()).outbound().get(0).packet(),other);
            UdpEndpointTest.await(()->endpoint.isEstablished(c.id));assertTrue(endpoint.send(c.id,new byte[]{7}));
            assertArrayEquals(new byte[]{7},c.sessions.receive(io.take().wire()).plaintext());
        }
    }

    @Test void cookieOnlyPathSkipsRefreshButValidProofImmediatelyRejectsExpiredLocalCertificate() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();var notices=new LinkedBlockingQueue<UdpEndpoint.CloseReason>();
        try(var a=f.new Node(1);var b=f.new Node(2);
            var endpoint=new UdpEndpoint(b.sessions,b.state,io,(id,p)->fail("期限外の中身"),Duration.ofDays(1),notices::add)) {
            a.remember(b);endpoint.setPeerAddress(a.id,SOURCE);byte[] first=a.sessions.start(b.id).packet();
            var checks=(AdminState.CertificateChecks)SessionManagerTest.field(b.sessions,"localChecks");long before=checks.checks;
            f.time.advance(30L*24*60*60);io.inject(first,SOURCE);
            try(var challenge=CookieWire.decode(io.take().wire())) {
                assertEquals(before,checks.checks);assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());
                io.inject(CookieWire.proof(challenge.cookie(),first),SOURCE);
            }
            assertEquals(UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED,notices.poll(3,TimeUnit.SECONDS));
            assertTrue(b.sessions.isClosed());assertEquals(0L,SessionManagerTest.field(b.sessions,"firstCalculations"));assertTrue(io.output.isEmpty());
        }
        var fresh=new SessionManagerTest();var dataIo=new JoinPortLimitsTest.MemoryIo();
        try(var a=fresh.new Node(1);var b=fresh.new Node(2)) {
            fresh.connect(a,b);byte[] data=fresh.data(a,b,1);
            try(var endpoint=new UdpEndpoint(b.sessions,b.state,dataIo,(id,p)->fail("期限外の中身"),Duration.ofDays(1))) {
                fresh.time.advance(30L*24*60*60);dataIo.inject(data,SOURCE);UdpEndpointTest.await(endpoint::isTerminated);
                assertEquals(UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED,endpoint.closeReason());assertTrue(dataIo.output.isEmpty());
            }
        }
    }

    @Test void unrelatedChallengeDoesNotRefreshCertificatesOrConsumeProofAllowance() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,SOURCE);endpoint.start(b.id);byte[] first=io.take().wire();
            var checks=(AdminState.CertificateChecks)SessionManagerTest.field(a.sessions,"localChecks");long before=checks.checks;
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(),f.admin));
            CookieRetryTest.reject(endpoint,io,CookieWire.challenge(new byte[32],new byte[40]),SOURCE);
            assertEquals(before,checks.checks);
            CookieRetryTest.reject(endpoint,io,CookieWire.challenge(Crypto.blake2s(first),new byte[40]),JoinPortLimitsTest.OTHER);
            assertEquals(before,checks.checks);
            io.inject(CookieWire.challenge(Crypto.blake2s(first),new byte[40]),SOURCE);
            try(var proof=CookieWire.decode(io.take().wire())) { assertArrayEquals(first,proof.first()); }
            assertEquals(before+1,checks.checks);
        }
    }

}
