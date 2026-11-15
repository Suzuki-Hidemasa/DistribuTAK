// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * DHT で見つけた「登録していない同じグループのメンバー」への握手の返事（核 C1 手順 6）。
 * 許可は 1 か所（UdpEndpoint の方針）で決める。PROOF と全検査の前には番地を覚えない。
 */
class UdpEndpointDiscoveredReplyTest {
    final UdpEndpointTest fixture=new UdpEndpointTest();

    /** 別のソケットでチャレンジを受け、署名済みの 1 通目だけを指定の送り元から送る（LanPeerPinTest と同じ作り）。 */
    private void prove(UdpEndpointTest.Node a,UdpEndpointTest.Node b,byte[] first) throws Exception {
        var gate=(FirstPacketGate)SessionManagerTest.field(b.endpoint,"firstPackets");
        byte[] challenge=gate.challenge(first,a.address()),cookie;
        try(var decoded=CookieWire.decode(challenge)) { cookie=decoded.cookie().clone(); }
        long before=b.datagrams.get();byte[] proof=CookieWire.proof(cookie,first);
        a.socket.send(new DatagramPacket(proof,proof.length,b.address()));
        UdpEndpointTest.await(()->b.datagrams.get()>before);
        UdpEndpointTest.await(()->b.sessions.isHandshaking(a.id)||b.endpoint.rejectedPackets()>0);
        Crypto.wipe(first);Crypto.wipe(cookie);Crypto.wipe(challenge);Crypto.wipe(proof);
    }

    @Test void defaultKeepsOldBehaviourAndDoesNotAnswerUnregisteredMember() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertNull(b.endpoint.peerAddress(a.id));
            assertFalse(b.endpoint.isEstablished(a.id));
        }
    }

    @Test void provedUnregisteredMemberGetsSecondPacketAndConnectsWithoutBeingExposed() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            AtomicInteger asked=new AtomicInteger();
            b.endpoint.allowDiscoveredReplies(source->{asked.incrementAndGet();return true;});
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            assertTrue(b.sessions.isUnregistered(a.id));
            // 登録した相手ではないので、保存用の公開コピーの一覧には出さない。
            assertTrue(b.endpoint.knownPeers().isEmpty());
            assertTrue(asked.get()>=1);
            a.inbox.clear();b.inbox.clear();
            assertTrue(a.endpoint.send(b.id,new byte[]{7}));assertArrayEquals(new byte[]{7},UdpEndpointTest.take(b));
            assertTrue(b.endpoint.send(a.id,new byte[]{8}));assertArrayEquals(new byte[]{8},UdpEndpointTest.take(a));
        }
    }

    @Test void policyThatSaysNoLeavesNoAddressAndNoSecondPacket() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->false);
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertNull(b.endpoint.peerAddress(a.id));assertFalse(b.endpoint.isEstablished(a.id));
        }
    }

    @Test void policyThatThrowsIsTreatedAsNoAndDoesNotCloseEndpoint() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->{throw new IllegalStateException("方針の例外");});
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertNull(b.endpoint.peerAddress(a.id));
            assertEquals(UdpEndpoint.CloseReason.RUNNING,b.endpoint.closeReason());
        }
    }

    @Test void nakedFirstWithoutProofDoesNotAskPolicyOrLearnAddress() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            AtomicInteger asked=new AtomicInteger();
            b.endpoint.allowDiscoveredReplies(source->{asked.incrementAndGet();return true;});
            a.endpoint.rememberPeer(b.cert);
            byte[] first=a.sessions.start(b.id).packet();
            a.socket.send(new DatagramPacket(first,first.length,b.address()));
            UdpEndpointTest.await(()->b.datagrams.get()>0);
            assertNull(b.endpoint.peerAddress(a.id));assertFalse(b.sessions.isHandshaking(a.id));
            assertEquals(0,asked.get());
        }
    }

    @Test void damagedFirstDoesNotAskPolicyOrLearnAddress() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            AtomicInteger asked=new AtomicInteger();
            b.endpoint.allowDiscoveredReplies(source->{asked.incrementAndGet();return true;});
            a.endpoint.rememberPeer(b.cert);
            byte[] first=a.sessions.start(b.id).packet();first[first.length-1]^=1;
            prove(a,b,first);
            assertNull(b.endpoint.peerAddress(a.id));assertFalse(b.sessions.isHandshaking(a.id));
            assertEquals(0,asked.get());
        }
    }

    @Test void addressAlreadyUsedByAnotherPeerIsNotTakenOver() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.rememberPeer(c.cert);b.endpoint.setPeerAddress(c.id,a.address());
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertNull(b.endpoint.peerAddress(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(c.id));
        }
    }

    @Test void alreadyRegisteredAddressIsNotChangedByFirst() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            b.link(a);b.endpoint.setPeerAddress(a.id,c.address());
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertEquals(c.address(),b.endpoint.peerAddress(a.id));
        }
    }

    @Test void policyIsAskedOnlyWithNormalizedSourceAndNeverWithNull() throws Exception {
        try(var b=fixture.new Node(2,"127.0.0.1")) {
            assertDoesNotThrow(()->b.endpoint.allowDiscoveredReplies(null));
            b.endpoint.close();
            assertThrows(IllegalStateException.class,()->b.endpoint.allowDiscoveredReplies(source->true));
        }
    }
}
