// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

/**
 * 核 C1 手順 6: 受け入れの判定は firstPeerCheck の 1 か所。揮発の相手の入口・拒否・片付け。
 */
class UdpEndpointVolatileTest {
    final UdpEndpointTest fixture=new UdpEndpointTest();

    /** 別のソケットで、署名済みの 1 通目だけを a の送り元から送る。b が処理を終えるまで待つ。 */
    private void prove(UdpEndpointTest.Node a,UdpEndpointTest.Node b,byte[] first) throws Exception {
        long rejected=b.endpoint.rejectedPackets();
        sendProof(a,b,first);
        UdpEndpointTest.await(()->b.sessions.isHandshaking(a.id)||b.endpoint.rejectedPackets()>rejected);
    }
    /** クッキーの PROOF を送り、b が受け取るまでだけ待つ（受けるか断るかは呼び出し側が見る）。 */
    private void sendProof(UdpEndpointTest.Node a,UdpEndpointTest.Node b,byte[] first) throws Exception {
        var gate=(FirstPacketGate)SessionManagerTest.field(b.endpoint,"firstPackets");
        byte[] challenge=gate.challenge(first,a.address()),cookie;
        try(var decoded=CookieWire.decode(challenge)) { cookie=decoded.cookie().clone(); }
        long before=b.datagrams.get();
        byte[] proof=CookieWire.proof(cookie,first);
        a.socket.send(new DatagramPacket(proof,proof.length,b.address()));
        UdpEndpointTest.await(()->b.datagrams.get()>before);
        Crypto.wipe(first);Crypto.wipe(cookie);Crypto.wipe(challenge);Crypto.wipe(proof);
    }
    private static int size(Object manager,String name) throws Exception {
        return ((Map<?,?>)SessionManagerTest.field(manager,name)).size();
    }

    @Test void validFirstFromOutsideThePolicyLeavesNoPeerRouteOrTimestamp() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->false);
            a.endpoint.rememberPeer(b.cert);
            byte[] first=a.sessions.start(b.id).packet();byte[] copy=first.clone();
            prove(a,b,first);
            assertEquals(0,size(b.sessions,"peers"));assertEquals(0,size(b.sessions,"routes"));
            assertFalse(b.sessions.hasPeer(a.id));assertNull(b.endpoint.peerAddress(a.id));
            // 1 通目の時刻の記録が増えていないので、条件が許せば同じ 1 通目がそのまま通る。
            b.endpoint.allowDiscoveredReplies(source->true);
            prove(a,b,copy);
            assertTrue(b.sessions.isHandshaking(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
        }
    }

    @Test void expectedPeerWithAnotherIdentityLetsDiscoveredMemberConnectAsVolatile() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            b.endpoint.expectPeerCertificate(c.cert);
            b.endpoint.allowDiscoveredReplies(source->true);
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertTrue(b.sessions.isUnregistered(a.id));
            assertTrue(b.endpoint.knownPeers().isEmpty());
        }
    }

    @Test void sameIdentityWithOlderCertificateIsStillRefused() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            fixture.wallMillis.addAndGet(1_000);
            byte[] pub=Crypto.x25519Public(a.secret);
            var newer=AdminRecords.certificate(fixture.group,Crypto.ed25519Public(key(1)),pub,SignaturePurpose.identityProof(key(1),fixture.group,pub),fixture.clock.millis(),fixture.admin);
            b.endpoint.expectPeerCertificate(newer);
            b.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertFalse(b.sessions.isHandshaking(a.id));assertFalse(b.sessions.hasPeer(a.id));
            assertNull(b.endpoint.peerAddress(a.id));
        }
    }

    @Test void pinnedInvitationStillRefusesDiscoveredMembers() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.pinPeerAddress(Crypto.x25519Public(c.secret),c.address());
            a.endpoint.rememberPeer(b.cert);
            prove(a,b,a.sessions.start(b.id).packet());
            assertFalse(b.sessions.hasPeer(a.id));assertNull(b.endpoint.peerAddress(a.id));
            assertNotNull(SessionManagerTest.field(b.endpoint,"pinnedHandshake"));
        }
    }

    @Test void networkChangeForgetsVolatilePeersAndTheirOldFirstIsNotAcceptedAgain() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            AtomicReference<byte[]> forgotten=new AtomicReference<>();
            b.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.onVolatilePeerForgotten(id->forgotten.set(id.clone()));
            a.endpoint.rememberPeer(b.cert);
            byte[] first=a.sessions.start(b.id).packet();byte[] copy=first.clone();
            prove(a,b,first);
            assertTrue(b.sessions.isHandshaking(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            b.endpoint.networkChanged();
            assertFalse(b.sessions.hasPeer(a.id));assertNull(b.endpoint.peerAddress(a.id));
            assertEquals(0,size(b.sessions,"routes"));assertTrue(b.endpoint.knownPeers().isEmpty());
            assertArrayEquals(a.id,forgotten.get());
            // 消した相手の古い 1 通目は、時刻の記録が残っているので受けない。
            prove(a,b,copy);
            assertFalse(b.sessions.hasPeer(a.id));assertNull(b.endpoint.peerAddress(a.id));
        }
    }

    @Test void networkChangeKeepsStoredPeers() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            fixture.new Node(3,"127.0.0.1").close();
            a.link(b);b.link(a);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            b.endpoint.networkChanged();
            assertTrue(b.endpoint.isEstablished(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            assertEquals(1,b.endpoint.knownPeers().size());
        }
    }

    @Test void rememberingVolatilePeerMovesItToStoredAndNetworkChangeKeepsIt() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertTrue(b.endpoint.knownPeers().isEmpty());
            b.endpoint.rememberPeer(a.cert);
            assertFalse(b.sessions.isUnregistered(a.id));
            assertEquals(1,b.endpoint.knownPeers().size());
            b.endpoint.networkChanged();
            assertTrue(b.endpoint.isEstablished(a.id));
        }
    }

    /** T6: 揮発の相手の番地が変わったら、消してから握手し直すと新しい番地へ 2 通目が出る。 */
    @Test void afterForgettingAVolatilePeerTheNewAddressGetsTheHandshake() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            assertTrue(b.endpoint.forgetVolatilePeer(a.id));
            assertNull(b.endpoint.peerAddress(a.id));assertFalse(b.sessions.hasPeer(a.id));
            // a は別の番地（別のソケット）から握手し直す。
            // 1 通目の時刻は前より新しくなければ受けないので、時計を進めてから作る。
            fixture.wallMillis.addAndGet(1_000);
            fixture.ticks.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(30));
            try(var moved=fixture.new Node(1,"127.0.0.1")) {
                moved.link(b);
                moved.endpoint.start(b.id);
                UdpEndpointTest.await(()->moved.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(moved.id));
                assertEquals(moved.address(),b.endpoint.peerAddress(moved.id));
                assertNotEquals(a.address(),b.endpoint.peerAddress(moved.id));
                assertTrue(b.endpoint.knownPeers().isEmpty());
            }
        }
    }

    /** 答え 198 (1): 席が揮発の相手で埋まっていても保存・固定できる。いちばん古い揮発の相手を手放し、番地と通知も片付く。 */
    @Test void rememberingWhenFullOfVolatilePeersReleasesTheOldestAndClearsItsAddress() throws Exception {
        try(var old=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1",3);var young=fixture.new Node(3,"127.0.0.1");var saved=fixture.new Node(4,"127.0.0.1")) {
            java.util.List<byte[]> forgotten=new java.util.concurrent.CopyOnWriteArrayList<>();
            b.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.onVolatilePeerForgotten(id->forgotten.add(id.clone()));
            old.link(b);old.endpoint.start(b.id);
            UdpEndpointTest.await(()->old.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(old.id));
            fixture.ticks.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(10));
            young.link(b);young.endpoint.start(b.id);
            UdpEndpointTest.await(()->young.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(young.id));
            assertEquals(old.address(),b.endpoint.peerAddress(old.id));
            assertEquals(young.address(),b.endpoint.peerAddress(young.id));
            assertTrue(forgotten.isEmpty());
            b.endpoint.rememberPeer(saved.cert);
            assertFalse(b.sessions.hasPeer(old.id));assertNull(b.endpoint.peerAddress(old.id));
            assertTrue(b.sessions.hasPeer(young.id));assertEquals(young.address(),b.endpoint.peerAddress(young.id));
            assertTrue(b.sessions.hasPeer(saved.id));
            assertEquals(1,forgotten.size());assertArrayEquals(old.id,forgotten.get(0));
        }
    }

    /** T7a: 別の相手がすでに使っている番地からの、登録のない相手の 1 通目は断る。 */
    @Test void aFirstFromAnAddressUsedByAnotherPeerIsRefused() throws Exception {
        try(var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1");var x=fixture.new Node(4,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            // b の表では、c の番地は別の相手 x のものとして登録されている。
            b.endpoint.setPeerAddress(x.id,c.address());
            long rejected=b.endpoint.rejectedPackets();
            c.link(b);
            c.endpoint.start(b.id);
            UdpEndpointTest.await(()->b.endpoint.rejectedPackets()>rejected);
            assertEquals(0,size(b.sessions,"peers"));
            assertFalse(b.sessions.hasPeer(c.id));
            assertNull(b.endpoint.peerAddress(c.id));
            assertFalse(c.endpoint.isEstablished(b.id));
        }
    }

    /** T7b: 揮発の相手の DATA が条件に合わない送り元から来たら、番地を更新せずにその包みを捨てる。 */
    @Test void dataFromOutsideThePolicyDoesNotMoveAVolatilePeerAddress() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");
            var proxy=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))) {
            b.endpoint.allowDiscoveredReplies(source->source.getPort()==a.address().getPort());
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertTrue(b.sessions.isUnregistered(a.id));
            // a の送り先を中継へ向け、b からは中継の番地（条件の外）から見えるようにする。
            a.endpoint.setPeerAddress(b.id,(InetSocketAddress)proxy.getLocalSocketAddress());
            long rejected=b.endpoint.rejectedPackets();
            assertTrue(a.endpoint.send(b.id,new byte[]{7}));
            var packet=new DatagramPacket(new byte[2048],2048);
            proxy.setSoTimeout(5000);proxy.receive(packet);
            proxy.send(new DatagramPacket(packet.getData(),packet.getLength(),b.address()));
            UdpEndpointTest.await(()->b.endpoint.rejectedPackets()>rejected);
            assertNull(b.inbox.poll(300,java.util.concurrent.TimeUnit.MILLISECONDS));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            assertTrue(b.endpoint.knownPeers().isEmpty());
        }
    }

    /** 未決 1: 揮発の相手が同じサブネットの別の番地から新しい 1 通目を送ったら、検査のあと番地を直す。 */
    @Test void aVolatilePeerThatMovedToAnotherAllowedAddressGetsTheNewAddress() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            fixture.wallMillis.addAndGet(1_000);
            fixture.ticks.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(30));
            try(var moved=fixture.new Node(1,"127.0.0.1")) {
                moved.link(b);
                moved.endpoint.start(b.id);
                UdpEndpointTest.await(()->moved.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(moved.id));
                assertEquals(moved.address(),b.endpoint.peerAddress(moved.id));
                assertNotEquals(a.address(),b.endpoint.peerAddress(moved.id));
                assertTrue(b.endpoint.knownPeers().isEmpty());
                assertTrue(b.sessions.isUnregistered(moved.id));
                assertEquals(1,size(b.sessions,"peers"));
                assertTrue(moved.endpoint.send(b.id,new byte[]{3}));
                assertArrayEquals(new byte[]{3},UdpEndpointTest.take(b));
            }
        }
    }

    /** 未決 1: 新しい番地をほかの相手が使っているときは断る。番地も 1 通目の時刻の記録も変わらない。 */
    @Test void aMovedFirstFromAnAddressUsedByAnotherPeerIsRefusedAndChangesNothing() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var x=fixture.new Node(4,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->true);
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            fixture.wallMillis.addAndGet(1_000);
            fixture.ticks.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(30));
            try(var moved=fixture.new Node(1,"127.0.0.1")) {
                moved.endpoint.rememberPeer(b.cert);
                // b の表では、moved の番地は別の相手 x のものになっている。
                b.endpoint.setPeerAddress(x.id,moved.address());
                byte[] first=moved.sessions.start(b.id).packet();byte[] copy=first.clone();
                long rejected=b.endpoint.rejectedPackets();
                sendProof(moved,b,first);
                UdpEndpointTest.await(()->b.endpoint.rejectedPackets()>rejected);
                assertEquals(a.address(),b.endpoint.peerAddress(a.id));
                assertEquals(moved.address(),b.endpoint.peerAddress(x.id));
                // 時刻の記録が増えていないので、番地が空いたあとは同じ 1 通目がそのまま通る。
                b.endpoint.setPeerAddress(x.id,x.address());
                sendProof(moved,b,copy);
                UdpEndpointTest.await(()->moved.address().equals(b.endpoint.peerAddress(a.id)));
            }
        }
    }

    /** 未決 1: 条件に合わない番地からの 1 通目は、揮発の相手のものでも断り、番地を変えない。 */
    @Test void aMovedFirstFromOutsideThePolicyIsRefusedAndTheAddressStays() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            b.endpoint.allowDiscoveredReplies(source->source.getPort()==a.address().getPort());
            a.link(b);
            a.endpoint.start(b.id);
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            fixture.wallMillis.addAndGet(1_000);
            fixture.ticks.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(30));
            try(var moved=fixture.new Node(1,"127.0.0.1")) {
                moved.endpoint.rememberPeer(b.cert);
                long rejected=b.endpoint.rejectedPackets();
                sendProof(moved,b,moved.sessions.start(b.id).packet());
                UdpEndpointTest.await(()->b.endpoint.rejectedPackets()>rejected);
                assertEquals(a.address(),b.endpoint.peerAddress(a.id));
                assertTrue(b.sessions.isUnregistered(a.id));
            }
        }
    }
}
