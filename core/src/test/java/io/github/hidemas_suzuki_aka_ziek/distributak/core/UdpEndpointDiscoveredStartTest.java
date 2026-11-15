// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 C1 必修 3: 発見で見つけた宛先へ握手鍵だけで始める口（startDiscovered）。
 * 検査が全部通るまで、番地は addresses・knownPeers に出ない。
 */
class UdpEndpointDiscoveredStartTest {
    final UdpEndpointTest fixture=new UdpEndpointTest();

    private static byte[] handshakeKey(UdpEndpointTest.Node node) { return Crypto.x25519Public(node.secret); }
    private static int size(Object manager,String name) throws Exception {
        return ((Map<?,?>)SessionManagerTest.field(manager,name)).size();
    }

    /** 定期処理が、今から少なくとも 2 回は丸ごとまわるまで待つ（時計を進めたあとの「何も起きない」を確かめる前に使う）。 */
    private static void awaitTicks(UdpEndpoint endpoint) throws Exception {
        long base=endpoint.completedTicks();
        UdpEndpointTest.await(()->endpoint.completedTicks()>=base+3);
    }

    @Test void unregisteredMembersConnectThroughTheDiscoveredStart() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertEquals(b.address(),a.endpoint.peerAddress(b.id));
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            assertFalse(a.endpoint.isDiscoveredPending(b.id));
            assertTrue(a.sessions.isUnregistered(b.id));
            assertTrue(a.endpoint.knownPeers().isEmpty());
            assertTrue(b.endpoint.knownPeers().isEmpty());
            assertEquals(0,a.sessions.unconfirmedCount());
            // つながったあとは、通常の DATA が通る。
            assertTrue(a.endpoint.send(b.id,new byte[]{5}));
            assertArrayEquals(new byte[]{5},UdpEndpointTest.take(b));
        }
    }

    @Test void candidateAddressIsNotKnownBeforeTheChecksPass() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            // b は条件がないので、1 通目を受けても返事をしない。
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            assertTrue(a.endpoint.isDiscoveredPending(b.id));
            assertNull(a.endpoint.peerAddress(b.id));
            assertTrue(a.endpoint.knownPeers().isEmpty());
            assertEquals(0,size(a.sessions,"peers"));assertEquals(0,size(a.sessions,"routes"));
            assertEquals(1,a.sessions.unconfirmedCount());
            assertTrue(a.sessions.hasUnconfirmed(b.id));
            assertFalse(a.sessions.hasPeer(b.id));
        }
    }

    @Test void deadCandidateIsDroppedAndSendsNoMoreFirstPackets() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            fixture.ticks.addAndGet(TimeUnit.SECONDS.toNanos(91));
            UdpEndpointTest.await(()->!a.endpoint.isDiscoveredPending(b.id)&&!a.sessions.hasUnconfirmed(b.id));
            assertNull(a.endpoint.peerAddress(b.id));
            assertEquals(0,a.sessions.unconfirmedCount());
            // 落ちた候補へは、その後 1 通も出ない（定期処理がまわり終わるまで待ってから数える）。
            awaitTicks(a.endpoint);
            int after=b.datagrams.get();
            fixture.ticks.addAndGet(TimeUnit.SECONDS.toNanos(30));
            awaitTicks(a.endpoint);
            assertEquals(after,b.datagrams.get());
        }
    }

    @Test void policyRefusalAndLimitsUseFixedMessagesWithoutAddresses() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            var refused=assertThrows(SecurityException.class,()->a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address()));
            assertFalse(refused.getMessage().contains("127.0.0.1"));
            a.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            // 同じ番地は同時に 1 件。
            var same=assertThrows(IllegalStateException.class,()->a.endpoint.startDiscovered(c.id,handshakeKey(c),b.address()));
            assertFalse(same.getMessage().contains("127.0.0.1"));
        }
    }

    /** 第12段: 確認前の相手の同時の上限を 3 から 8 に上げた（答え 192 (3)・193 の限度の表）。9 件目は決まった文で断る。 */
    @Test void eightDiscoveredStartsRunAtOnceAndTheNinthIsRefusedWithAFixedMessage() throws Exception {
        List<UdpEndpointTest.Node> nodes=new ArrayList<>();
        try(var a=fixture.new Node(1,"127.0.0.1")) {
            for(int n=2;n<=10;n++)nodes.add(fixture.new Node(n,"127.0.0.1"));
            a.endpoint.allowDiscoveredReplies(source->true);
            for(int i=0;i<8;i++)a.endpoint.startDiscovered(nodes.get(i).id,handshakeKey(nodes.get(i)),nodes.get(i).address());
            assertEquals(8,a.sessions.unconfirmedCount());
            var ninth=nodes.get(8);
            var over=assertThrows(IllegalStateException.class,()->a.endpoint.startDiscovered(ninth.id,handshakeKey(ninth),ninth.address()));
            assertFalse(over.getMessage().contains("127.0.0.1"));
            assertFalse(a.endpoint.isDiscoveredPending(ninth.id));
            assertEquals(8,a.sessions.unconfirmedCount());
        } finally {
            for(var node:nodes)node.close();
        }
    }

    @Test void wrongHandshakeKeyOrIdentityNeverBecomesAPeer() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.allowDiscoveredReplies(source->true);
            // b の番地へ、c の番号で始める（身元が違う）。
            a.endpoint.startDiscovered(c.id,handshakeKey(b),b.address());
            UdpEndpointTest.await(()->!a.endpoint.isDiscoveredPending(c.id));
            assertNull(a.endpoint.peerAddress(c.id));assertNull(a.endpoint.peerAddress(b.id));
            assertFalse(a.sessions.hasPeer(c.id));assertFalse(a.sessions.hasPeer(b.id));
            assertEquals(0,size(a.sessions,"peers"));
            assertTrue(a.endpoint.knownPeers().isEmpty());
            // b の番号で、c の握手鍵（違う鍵）で始める。
            a.endpoint.startDiscovered(b.id,handshakeKey(c),b.address());
            // b が 1 通目を受けて処理し、a の定期処理もまわったあとで確かめる。
            UdpEndpointTest.await(()->b.datagrams.get()>=1);
            awaitTicks(b.endpoint);awaitTicks(a.endpoint);
            assertNull(a.endpoint.peerAddress(b.id));
            assertFalse(a.sessions.hasPeer(b.id));
            assertTrue(a.endpoint.knownPeers().isEmpty());
        }
    }

    @Test void simultaneousStartsEndWithOneSession() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            b.endpoint.startDiscovered(a.id,handshakeKey(a),a.address());
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            UdpEndpointTest.await(()->!a.endpoint.isDiscoveredPending(b.id)&&!b.endpoint.isDiscoveredPending(a.id));
            assertEquals(1,size(a.sessions,"peers"));assertEquals(1,size(b.sessions,"peers"));
            assertEquals(0,a.sessions.unconfirmedCount());assertEquals(0,b.sessions.unconfirmedCount());
            assertTrue(a.endpoint.send(b.id,new byte[]{9}));
            assertArrayEquals(new byte[]{9},UdpEndpointTest.take(b));
        }
    }

    @Test void alreadyKnownPeerUsesTheExistingPath() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            a.link(b);b.link(a);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            UdpEndpointTest.await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id));
            assertEquals(1,size(a.sessions,"peers"));
            assertEquals(1,a.endpoint.knownPeers().size());
            assertEquals(0,a.sessions.unconfirmedCount());
        }
    }

    /** a と b の間に挟む中継。b から a への 2 通目（SECOND）は、止めている間は溜めておく。 */
    private static final class Relay implements AutoCloseable {
        final DatagramSocket socket;
        final AtomicBoolean holding=new AtomicBoolean(true);
        final List<byte[]> held=new ArrayList<>();
        volatile InetSocketAddress a,b;
        final Thread thread;
        Relay(InetSocketAddress b) throws Exception {
            socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",0));this.b=b;
            thread=new Thread(this::loop,"relay");thread.setDaemon(true);thread.start();
        }
        InetSocketAddress address() { return (InetSocketAddress)socket.getLocalSocketAddress(); }
        private void loop() {
            byte[] buffer=new byte[2048];
            try {
                while(!socket.isClosed()) {
                    var packet=new DatagramPacket(buffer,buffer.length);socket.receive(packet);
                    byte[] wire=java.util.Arrays.copyOf(buffer,packet.getLength());
                    var source=(InetSocketAddress)packet.getSocketAddress();
                    if(source.equals(b)) {
                        synchronized(this) {
                            if(!CookieWire.isCookie(wire)&&SessionPacket.decode(wire).kind()==SessionPacket.SECOND&&holding.get()) { held.add(wire);continue; }
                        }
                        if(a!=null) socket.send(new DatagramPacket(wire,wire.length,a));
                    } else { a=source;socket.send(new DatagramPacket(wire,wire.length,b)); }
                }
            } catch(java.io.IOException e) { /* 閉じられた */ }
        }
        synchronized boolean heldAny() { return !held.isEmpty(); }
        synchronized void release() throws java.io.IOException {
            holding.set(false);
            for(byte[] wire:held) socket.send(new DatagramPacket(wire,wire.length,a));
            held.clear();
        }
        @Override public void close() { socket.close(); }
    }

    @Test void startDiscoveredIsRefusedWhileAPinRemainsAndSendsNothing() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.pinPeerAddress(handshakeKey(c),c.address());
            int before=b.datagrams.get();
            var refused=assertThrows(IllegalStateException.class,()->a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address()));
            assertFalse(refused.getMessage().contains("127.0.0.1"));
            awaitTicks(a.endpoint);awaitTicks(b.endpoint);
            assertEquals(before,b.datagrams.get());
            assertEquals(0,a.sessions.unconfirmedCount());
            assertFalse(a.endpoint.isDiscoveredPending(b.id));
            assertNull(a.endpoint.peerAddress(b.id));
        }
    }

    @Test void aHandshakeStartedBeforeThePinDoesNotEnterAfterThePin() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1");var c=fixture.new Node(3,"127.0.0.1");
            var relay=new Relay(b.address())) {
            a.endpoint.allowDiscoveredReplies(source->true);
            b.endpoint.allowDiscoveredReplies(source->true);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),relay.address());
            // b の 2 通目は中継で止まっている。この間に pin を付ける。
            UdpEndpointTest.await(relay::heldAny);
            a.endpoint.pinPeerAddress(handshakeKey(c),c.address());
            relay.release();
            UdpEndpointTest.await(()->!a.endpoint.isDiscoveredPending(b.id));
            assertNull(a.endpoint.peerAddress(b.id));
            assertTrue(a.endpoint.knownPeers().isEmpty());
            assertEquals(0,a.sessions.unconfirmedCount());
            assertFalse(a.sessions.hasPeer(b.id));
            assertFalse(a.endpoint.send(b.id,new byte[]{1}));
        }
    }

    @Test void aFailedSendDropsTheNewlyPlacedCandidate() throws Exception {
        try(var a=fixture.new Node(1,"127.0.0.1");var b=fixture.new Node(2,"127.0.0.1")) {
            a.endpoint.allowDiscoveredReplies(source->true);
            // 試験の口は、ループバック以外へ送ると IOException を投げる。送り失敗は例外にならず、宛先も残らない。
            var away=new InetSocketAddress(java.net.InetAddress.getByAddress(new byte[]{(byte)192,0,2,7}),4000);
            a.endpoint.startDiscovered(b.id,handshakeKey(b),away);
            assertFalse(a.endpoint.isDiscoveredPending(b.id));
            assertEquals(0,a.sessions.unconfirmedCount());
            assertNull(a.endpoint.peerAddress(b.id));
            // 外した宛先を、あとで同じ宛先の再試行（5 秒の間隔の縛りなし）として始められる。
            a.endpoint.startDiscovered(b.id,handshakeKey(b),b.address());
            assertTrue(a.endpoint.isDiscoveredPending(b.id)||a.endpoint.isEstablished(b.id));
        }
    }
}
