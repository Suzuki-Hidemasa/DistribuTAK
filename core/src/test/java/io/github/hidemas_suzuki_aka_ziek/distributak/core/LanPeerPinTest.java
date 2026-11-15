// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LanPeerPinTest {
    final UdpEndpointTest fixture=new UdpEndpointTest();

    @Test void pinnedInvitationPeerConnectsAndExposesOnlyPublicCopies() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.link(b);
            b.endpoint.pinPeerAddress(Crypto.x25519Public(a.secret),a.address());
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            var peers=b.endpoint.knownPeers();assertEquals(1,peers.size());
            assertArrayEquals(a.cert.encode(),peers.get(0).certificate().encode());
            assertEquals(a.address(),peers.get(0).address());
            assertThrows(UnsupportedOperationException.class,peers::clear);
            byte[] encoded=peers.get(0).certificate().encode();Arrays.fill(encoded,(byte)0);
            assertArrayEquals(a.cert.encode(),b.endpoint.knownPeers().get(0).certificate().encode());
            a.inbox.clear();b.inbox.clear();
            assertTrue(a.endpoint.send(b.id,new byte[]{1}));assertArrayEquals(new byte[]{1},UdpEndpointTest.take(b));
            assertTrue(b.endpoint.send(a.id,new byte[]{2}));assertArrayEquals(new byte[]{2},UdpEndpointTest.take(a));
            assertNull(SessionManagerTest.field(b.endpoint,"pinnedHandshake"));
            b.endpoint.close();assertTrue(b.endpoint.knownPeers().isEmpty());
        }
    }

    @Test void validOtherMemberAtPinnedAddressCannotAcquireRoute() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            a.endpoint.rememberPeer(b.cert);
            b.endpoint.pinPeerAddress(Crypto.x25519Public(c.secret),a.address());
            prove(a,b,a.sessions.start(b.id).packet());
            assertNull(b.endpoint.peerAddress(a.id));assertTrue(b.endpoint.knownPeers().isEmpty());
            assertFalse(b.sessions.isHandshaking(a.id));assertNull(b.sessions.knownCertificate(a.id));
            // 同じ予約と送り元で、正しい鍵なら直後に通る。拒否した相手の枠を残さない。
            c.sessions.rememberPeer(b.cert);prove(a,b,c.sessions.start(b.id).packet());
            UdpEndpointTest.await(()->a.address().equals(b.endpoint.peerAddress(c.id)));
            assertEquals(1,b.endpoint.knownPeers().size());assertTrue(b.sessions.isHandshaking(c.id));
        }
    }

    @Test void wrongSourceAndDamagedCertificateHaveValidControl() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            a.endpoint.rememberPeer(b.cert);
            b.endpoint.pinPeerAddress(Crypto.x25519Public(a.secret),c.address());
            prove(a,b,a.sessions.start(b.id).packet());
            assertTrue(b.endpoint.knownPeers().isEmpty());
        }
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.rememberPeer(b.cert);
            b.endpoint.pinPeerAddress(Crypto.x25519Public(a.secret),a.address());
            byte[] first=a.sessions.start(b.id).packet();first[first.length-1]^=1;
            prove(a,b,first);assertTrue(b.endpoint.knownPeers().isEmpty());
            assertNotNull(SessionManagerTest.field(b.endpoint,"pinnedHandshake"));
        }
        pinnedInvitationPeerConnectsAndExposesOnlyPublicCopies();
    }

    @Test void unprovedFirstAndAbsentPinDoNotLearnRouteAndCloseClearsPin() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.rememberPeer(b.cert);
            b.endpoint.pinPeerAddress(Crypto.x25519Public(a.secret),a.address());
            assertThrows(IllegalStateException.class,()->b.endpoint.pinPeerAddress(Crypto.x25519Public(a.secret),a.address()));
            byte[] first=a.sessions.start(b.id).packet();
            a.socket.send(new DatagramPacket(first,first.length,b.address()));
            UdpEndpointTest.await(()->b.datagrams.get()>0);
            assertTrue(b.endpoint.knownPeers().isEmpty());
            b.endpoint.close();assertNull(SessionManagerTest.field(b.endpoint,"pinnedHandshake"));
        }
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.rememberPeer(b.cert);prove(a,b,a.sessions.start(b.id).packet());
            assertNull(b.endpoint.peerAddress(a.id));assertTrue(b.endpoint.knownPeers().isEmpty());
        }
    }

    // 別のソケットでチャレンジを受けて、署名済みの1通目だけを指定の送り元から送る。
    private void prove(UdpEndpointTest.Node a,UdpEndpointTest.Node b,byte[] first) throws Exception {
        // aの受信スレッドに奪われないよう、試験用Ioのsend経由でPROOFを作る。
        byte[] cookie;
        var gate=(FirstPacketGate)SessionManagerTest.field(b.endpoint,"firstPackets");
        byte[] challenge=gate.challenge(first,a.address());
        try(var decoded=CookieWire.decode(challenge)) { cookie=decoded.cookie().clone(); }
        long before=b.datagrams.get();byte[] proof=CookieWire.proof(cookie,first);
        a.socket.send(new DatagramPacket(proof,proof.length,b.address()));
        UdpEndpointTest.await(()->b.datagrams.get()>before);
        UdpEndpointTest.await(()->b.sessions.isHandshaking(a.id)||b.endpoint.rejectedPackets()>0);
        Crypto.wipe(first);Crypto.wipe(cookie);Crypto.wipe(challenge);Crypto.wipe(proof);
    }
}
