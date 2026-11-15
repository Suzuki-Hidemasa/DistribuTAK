// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.IOException;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpointTest.*;

class UdpEndpointFix1Test {
    @ParameterizedTest @ValueSource(strings={"revocation","administrators","timer","receive","send","query","start"})
    void localInvalidationStopsSocketAndBothThreads(String trigger) throws Exception {
        var f=new UdpEndpointTest();
        Duration interval=trigger.equals("timer") ? Duration.ofMillis(20) : Duration.ofDays(1);
        try(var a=f.new Node(1,"127.0.0.1",false,interval);var b=f.new Node(2,"127.0.0.1",false,Duration.ofDays(1))) {
            f.connect(a,b);
            assertEquals(UdpEndpoint.CloseReason.RUNNING,a.endpoint.closeReason());
            if(trigger.equals("revocation")) {
                assertTrue(a.endpoint.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.clock.millis(),List.of(a.id),f.admin)));
            } else if(trigger.equals("administrators")) {
                assertTrue(a.endpoint.acceptAdministrators(AdminProofFixtures.list(f.group,1,f.clock.millis(),List.of(Crypto.ed25519Public(key(93))),f.admin,key(93)),v->fail()));
            } else {
                byte[] wire=b.sessions.send(a.id,new byte[]{1}).get(0).packet();
                f.wallMillis.addAndGet(AdminRecords.CERTIFICATE_LIFETIME_MILLIS);
                switch(trigger) {
                    case "receive" -> b.socket.send(new DatagramPacket(wire,wire.length,a.address()));
                    case "send" -> assertFalse(a.endpoint.send(b.id,new byte[]{1}));
                    case "query" -> assertFalse(a.endpoint.isEstablished(b.id));
                    case "start" -> assertThrows(IllegalStateException.class,()->a.endpoint.start(b.id));
                    case "timer" -> { }
                    default -> fail();
                }
            }
            await(a.endpoint::isTerminated);
            assertTrue(a.socket.isClosed());assertTrue(a.sessions.isClosed());
            var expected=trigger.equals("revocation")||trigger.equals("administrators")
                ? UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID : UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED;
            assertEquals(expected,a.endpoint.closeReason());
            assertFalse(a.endpoint.send(b.id,new byte[]{2}));
            assertThrows(IllegalStateException.class,()->a.endpoint.start(b.id));
            a.endpoint.close();assertEquals(expected,a.endpoint.closeReason());
        }
    }
    @Test void revokingOnlyOnePeerKeepsOtherPeerCommunicating() throws Exception {
        var f=new UdpEndpointTest();
        try(var a=f.new Node(1,"127.0.0.1");var b=f.new Node(2,"127.0.0.1");var c=f.new Node(3,"127.0.0.1")) {
            f.connect(a,b);f.connect(a,c);
            a.endpoint.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.clock.millis(),List.of(b.id),f.admin));
            assertFalse(a.endpoint.isEstablished(b.id));assertFalse(a.socket.isClosed());
            assertEquals(UdpEndpoint.CloseReason.RUNNING,a.endpoint.closeReason());
            assertTrue(a.endpoint.send(c.id,new byte[]{3}));assertArrayEquals(new byte[]{3},take(c));
            assertTrue(c.endpoint.send(a.id,new byte[]{4}));assertArrayEquals(new byte[]{4},take(a));
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void borrowedPlaintextIsWipedAfterNormalOrThrowingCallback(boolean throwsException) throws Exception {
        var f=new UdpEndpointTest();
        try(var a=f.new Node(1,"127.0.0.1");var b=f.new Node(2,"127.0.0.1")) {
            f.connect(a,b);b.throwCallback=throwsException;
            assertTrue(a.endpoint.send(b.id,new byte[]{1,2,3}));
            byte[] borrowed=b.borrowedPlaintext.poll(5,TimeUnit.SECONDS);assertNotNull(borrowed);
            // close の join により、受け口の後の finally まで終わったことを確認する。
            b.endpoint.close();assertArrayEquals(new byte[3],borrowed);
            assertEquals(throwsException ? 1 : 0,b.endpoint.callbackFailures());
            assertEquals(UdpEndpoint.CloseReason.CLOSED_BY_CALLER,b.endpoint.closeReason());
        }
    }
    @Test void repeatedSecondFromDifferentAddressDoesNotRoam() throws Exception {
        var f=new UdpEndpointTest();
        try(var a=f.new Node(1,"127.0.0.1");var b=f.new Node(2,"127.0.0.1");
            var stranger=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))) {
            a.link(b);b.link(a);
            byte[] first=a.sessions.start(b.id).packet();
            byte[] second=b.sessions.receive(first).outbound().get(0).packet();
            var confirm=a.sessions.receive(second);b.sessions.receive(confirm.outbound().get(0).packet());
            long before=b.datagrams.get();
            stranger.send(new DatagramPacket(second,second.length,a.address()));
            // 重複 SECOND への確認が B のソケットへ届いたあと、番地表のロックで処理完了を待つ。
            await(()->b.datagrams.get()>before);
            assertEquals(b.address(),a.endpoint.peerAddress(b.id));
            assertEquals(0,a.endpoint.rejectedPackets());
            b.endpoint.send(a.id,new byte[]{7});assertArrayEquals(new byte[]{7},take(a));
        }
    }
    @Test void receiveFailureStopsThreadsAndWipesAllKeys() throws Exception {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2);
            var socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))) {
            f.connect(a,b);
            var keys=new ArrayList<>(f.secrets(a,b));
            keys.add((byte[])SessionManagerTest.field(a.sessions,"localSecret"));keys.add((byte[])SessionManagerTest.field(a.sessions,"psk"));
            var release=new CountDownLatch(1);
            var io=new UdpEndpoint.SocketIo(socket) {
                @Override public UdpEndpoint.Datagram receive() throws IOException {
                    try { if(!release.await(5,TimeUnit.SECONDS)) throw new IOException("試験の期限"); }
                    catch(InterruptedException e) { Thread.currentThread().interrupt(); }
                    throw new IOException("試験の受信故障");
                }
            };
            try(var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,plain)->fail(),Duration.ofDays(1))) {
                release.countDown();await(endpoint::isTerminated);
                assertTrue(socket.isClosed());assertTrue(a.sessions.isClosed());
                assertEquals(UdpEndpoint.CloseReason.RECEIVE_FAILURE,endpoint.closeReason());
                for(byte[] bytes:keys) assertArrayEquals(new byte[bytes.length],bytes);
                assertFalse(endpoint.send(b.id,new byte[]{1}));
            } finally { release.countDown(); }
        }
    }
    @Test void oversizedDatagramsWithValidPrefixAreRejectedBeforePositiveControl() throws Exception {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2);
            var socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))) {
            f.connect(a,b);
            var source=new InetSocketAddress("127.0.0.1",12345);
            var input=new LinkedBlockingQueue<UdpEndpoint.Datagram>();
            var output=new LinkedBlockingQueue<byte[]>();
            var io=new UdpEndpoint.SocketIo(socket) {
                @Override public UdpEndpoint.Datagram receive() throws IOException {
                    try { return input.take(); }
                    catch(InterruptedException e) { Thread.currentThread().interrupt();throw new IOException("受信の中止"); }
                }
                @Override public void close() { super.close();input.add(new UdpEndpoint.Datagram(new byte[0],source)); }
            };
            try(var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,plain)->output.add(plain.clone()),Duration.ofDays(1))) {
                endpoint.setPeerAddress(b.id,source);
                byte[] valid=b.sessions.send(a.id,new byte[SessionPacket.MAX_PLAINTEXT]).get(0).packet();
                for(int length:new int[]{1233,65000}) {
                    long before=endpoint.rejectedPackets();
                    input.add(new UdpEndpoint.Datagram(Arrays.copyOf(valid,length),source));
                    await(()->endpoint.rejectedPackets()==before+1);assertTrue(output.isEmpty());
                }
                input.add(new UdpEndpoint.Datagram(valid,source));
                byte[] received=output.poll(5,TimeUnit.SECONDS);assertNotNull(received);
                assertEquals(1176,received.length);assertTrue(output.isEmpty());
            }
        }
    }
}
