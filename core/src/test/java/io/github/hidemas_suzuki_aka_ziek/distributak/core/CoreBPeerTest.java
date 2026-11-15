// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.SOURCE;
class CoreBPeerTest {
    final SessionManagerTest f=new SessionManagerTest();
    @Test void newerFirstIsOnlyAHintAndSuccessfulHandshakeClearsIt() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            a.sessions.rotateGroupKey(f.psk,1);b.sessions.rotateGroupKey(f.psk,1);
            a.remember(b);byte[] first=a.sessions.start(b.id).packet();var packet=SessionPacket.decode(first);
            for(long delta:new long[]{0,-1,1}) {
                long version=packet.version()+delta;if(version<0)continue;
                var changed=new SessionPacket(SessionPacket.FIRST,packet.id(),version,0,new byte[108]).encode();
                assertThrows(RuntimeException.class,()->b.sessions.receive(changed));
                assertEquals(delta==1,b.sessions.sawNewerKeyVersion());assertFalse(b.sessions.isClosed());
            }
            var response=b.sessions.receive(first);var confirm=a.sessions.receive(response.outbound().get(0).packet());
            b.sessions.receive(confirm.outbound().get(0).packet());assertFalse(b.sessions.sawNewerKeyVersion());
        }
    }
    @Test void acceptedCertificateCanBeQueriedAndOldArrivalDoesNotReplaceIt() {
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            a.remember(b);assertArrayEquals(b.cert.encode(),a.sessions.peerCertificate(b.id).encode());
            f.time.millis++;var next=b.certificate(b.secret,f.time.millis);a.sessions.rememberPeer(next);
            assertArrayEquals(next.encode(),a.sessions.peerCertificate(b.id).encode());
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(b.cert));
            assertArrayEquals(next.encode(),a.sessions.peerCertificate(b.id).encode());
        }
    }
    @Test void forgettingRevokedPeerClearsSessionReplayAddressCookieAndMatchingPin() throws Exception {
        var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            f.connect(b,a);
            try(var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
                endpoint.setPeerAddress(b.id,SOURCE);endpoint.pinPeerAddress(b.cert.field(1),SOURCE);
                assertThrows(SecurityException.class,()->endpoint.forgetPeer(b.id));assertNotNull(endpoint.peerAddress(b.id));
                // 次のFIRSTを待つ状態とcookieの試みも作る。
                f.time.advance(6);endpoint.start(b.id);io.take();
                assertFalse(((Map<?,?>)SessionManagerTest.field(endpoint,"cookieAttempts")).isEmpty());
                var secrets=f.secrets(a,b);
                assertFalse(((Map<?,?>)SessionManagerTest.field(SessionManagerTest.field(a.sessions,"replay"),"newest")).isEmpty());
                a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(b.id),f.admin));
                endpoint.forgetPeer(b.id);
                f.wiped(secrets);
                assertTrue(((Map<?,?>)SessionManagerTest.field(SessionManagerTest.field(a.sessions,"replay"),"newest")).isEmpty());
                assertNull(endpoint.peerAddress(b.id));assertNull(SessionManagerTest.field(endpoint,"pinnedHandshake"));
                assertTrue(((Map<?,?>)SessionManagerTest.field(endpoint,"cookieAttempts")).isEmpty());
                assertTrue(((Map<?,?>)SessionManagerTest.field(a.sessions,"peers")).isEmpty());
                assertTrue(((Map<?,?>)SessionManagerTest.field(a.sessions,"routes")).isEmpty());
                assertTrue(((Map<?,?>)SessionManagerTest.field(endpoint,"addresses")).isEmpty());
                assertTrue(endpoint.knownPeers().isEmpty());assertFalse(a.sessions.isClosed());
            }
        }
    }
    @Test void forgettingOnePeerKeepsAnotherPinnedPeerAtSameAddress() throws Exception {
        var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var c=f.new Node(3);
            var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,SOURCE);endpoint.pinPeerAddress(c.cert.field(1),SOURCE);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(b.id),f.admin));
            endpoint.forgetPeer(b.id);assertArrayEquals(c.cert.field(1),(byte[])SessionManagerTest.field(endpoint,"pinnedHandshake"));
        }
    }
    @Test void pinWithoutCertificateIsClearedByRevokedAddress() throws Exception {
        var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
            endpoint.setPeerAddress(b.id,SOURCE);endpoint.pinPeerAddress(b.cert.field(1),SOURCE);
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis,List.of(b.id),f.admin));
            endpoint.forgetPeer(b.id);assertNull(SessionManagerTest.field(endpoint,"pinnedHandshake"));
            assertNull(SessionManagerTest.field(endpoint,"pinnedAddress"));assertNull(endpoint.peerAddress(b.id));
            assertTrue(((Map<?,?>)SessionManagerTest.field(endpoint,"addresses")).isEmpty());
        }
    }
    @Test void forgetAlwaysPropagatesClosedManagerToEndpoint() throws Exception {
        var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
            a.sessions.close();assertThrows(IllegalStateException.class,()->endpoint.forgetPeer(b.id));
            assertEquals(UdpEndpoint.CloseReason.CLOSED_BY_CALLER,endpoint.closeReason());
        }
    }
    @Test void expiryDoesNotAllowForgettingPeerOrItsAddress() {
        var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,SOURCE);
            f.time.millis=b.cert.expiresAt();
            assertThrows(SecurityException.class,()->endpoint.forgetPeer(b.id));assertEquals(SOURCE,endpoint.peerAddress(b.id));
        }
    }
}
