// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class UdpEndpointTest {
    final AtomicLong wallMillis=new AtomicLong(10_000_000_000L);
    final Clock clock=new Clock() {
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return Instant.ofEpochMilli(wallMillis.get()); }
    };
    final AtomicLong ticks=new AtomicLong();
    final byte[] group=key(90),admin=key(91),psk=key(92);
    class Node implements AutoCloseable {
        final byte[] secret,id;
        final AdminState state;
        final AdminRecords.Record cert;
        final SessionManager sessions;
        final BlockingQueue<byte[]> inbox=new LinkedBlockingQueue<>();
        final DatagramSocket socket;
        final UdpEndpoint endpoint;
        final AtomicInteger datagrams=new AtomicInteger();
        final AtomicReference<byte[]> lastPeer=new AtomicReference<>();
        final BlockingQueue<byte[]> borrowedPlaintext=new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> sessionInbox=new LinkedBlockingQueue<>(),borrowedSessions=new LinkedBlockingQueue<>();
        volatile boolean throwCallback;
        volatile CountDownLatch callbackEntered,callbackRelease;
        Node(int n,String host) throws Exception { this(n,host,false); }
        Node(int n,String host,boolean faults) throws Exception { this(n,host,faults,Duration.ofMillis(20)); }
        Node(int n,String host,boolean faults,Duration interval) throws Exception { this(n,host,faults,interval,256); }
        Node(int n,String host,int limit) throws Exception { this(n,host,false,Duration.ofMillis(20),limit); }
        Node(int n,String host,boolean faults,Duration interval,int limit) throws Exception {
            secret=key(n+100);byte[] identity=key(n),pub=Crypto.x25519Public(secret);
            id=Crypto.blake2s(Crypto.ed25519Public(identity));
            state=new AdminState(group,Crypto.ed25519Public(admin),clock,new InMemoryAdminRecordStore());
            var list=AdminRecords.list(ADMINS,group,0,clock.millis(),List.of(Crypto.ed25519Public(admin)),admin);
            state.bootstrap(list,AdminRecords.signAnchor(list,admin));
            state.acceptRevocations(AdminRecords.list(REVOCATIONS,group,0,clock.millis(),List.of(),admin));
            cert=AdminRecords.certificate(group,Crypto.ed25519Public(identity),pub,SignaturePurpose.identityProof(identity,group,pub),clock.millis(),admin);
            sessions=new SessionManager(state,cert,secret,psk,0,clock,ticks::get,limit);
            socket=new DatagramSocket(new InetSocketAddress(InetAddress.getByName(host),0));
            UdpEndpoint.DatagramIo io=faults ? new FaultIo(socket) : new UdpEndpoint.SocketIo(socket) {
                @Override public UdpEndpoint.Datagram receive() throws java.io.IOException {
                    while(true) {
                        var result=super.receive();
                        if(!result.source().getAddress().isLoopbackAddress()) { Crypto.wipe(result.wire());continue; }
                        datagrams.incrementAndGet();return result;
                    }
                }
                @Override public void send(byte[] wire,InetSocketAddress target) throws java.io.IOException {
                    if(!target.getAddress().isLoopbackAddress())throw new java.io.IOException("試験の送り先はループバックだけです");
                    super.send(wire,target);
                }
            };
            endpoint=new UdpEndpoint(sessions,state,io,new UdpEndpoint.Receiver(){
              public void receive(byte[] peer,byte[] session,byte[] plain){
                if(plain.length!=0){sessionInbox.add(session.clone());borrowedSessions.add(session);}
                receive(peer,plain);
              }
              public void receive(byte[] peer,byte[] plain){
                assertEquals(32,peer.length);
                // 確認 DATA の受け口が成立の照会より後に動いても、試験用の中身と混ぜない。
                if(plain.length==0) return;
                borrowedPlaintext.add(plain);
                lastPeer.set(peer.clone());
                if(callbackEntered!=null) {
                    callbackEntered.countDown();
                    try { callbackRelease.await(); } catch(InterruptedException e) { Thread.currentThread().interrupt(); }
                }
                if(throwCallback) throw new IllegalStateException("受け口の試験");
                inbox.add(plain.clone());
              }
            },interval);
        }
        void link(Node other) {
            endpoint.rememberPeer(other.cert);endpoint.setPeerAddress(other.id,other.address());
        }
        InetSocketAddress address() { return (InetSocketAddress)socket.getLocalSocketAddress(); }
        public void close() { endpoint.close();Crypto.wipe(secret); }
    }
    static class FaultIo extends UdpEndpoint.SocketIo {
        boolean first=true,second=true,confirmation=true;
        byte[] held;SocketAddress target;
        FaultIo(DatagramSocket socket) { super(socket); }
        @Override public synchronized void send(byte[] wire,InetSocketAddress address) throws java.io.IOException {
            if(CookieWire.isCookie(wire)) { super.send(wire,address);return; }
            int kind=SessionPacket.decode(wire).kind();
            if(kind==SessionPacket.FIRST && first) { first=false;return; }
            if(kind==SessionPacket.SECOND && second) { second=false;return; }
            if(kind==SessionPacket.DATA && wire.length==56 && confirmation) { confirmation=false;return; }
            if(kind==SessionPacket.DATA && wire.length>56) {
                if(held==null) { held=wire.clone();target=address;return; }
                super.send(wire,address);super.send(wire,address);
                super.send(held,(InetSocketAddress)target);super.send(held,(InetSocketAddress)target);held=null;return;
            }
            super.send(wire,address);
        }
    }
    void connect(Node a,Node b) throws Exception {
        a.link(b);b.link(a);a.endpoint.start(b.id);
        await(()->a.endpoint.isEstablished(b.id) && b.endpoint.isEstablished(a.id));
    }
    interface Check { boolean ok() throws Exception; }
    static void await(Check check) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(15);
        while(!check.ok()) {
            if(System.nanoTime()>deadline) fail("条件が期限までに成立しませんでした");
            java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
    }
    static byte[] take(Node n) throws Exception {
        byte[] value=n.inbox.poll(10,TimeUnit.SECONDS);assertNotNull(value);return value;
    }
    @ParameterizedTest @ValueSource(strings={"127.0.0.1","::1"})
    void twoAndThreePeersExchangeWithoutForwarding(String host) throws Exception {
        try(var a=new Node(1,host);var b=new Node(2,host);var c=new Node(3,host)) {
            a.link(b);b.link(a);a.link(c);c.link(a);
            a.endpoint.start(b.id);a.endpoint.start(c.id);
            await(()->a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id)&&a.endpoint.isEstablished(c.id)&&c.endpoint.isEstablished(a.id));
            a.inbox.clear();b.inbox.clear();c.inbox.clear();
            int cBefore=c.datagrams.get();
            assertTrue(a.endpoint.send(b.id,new byte[]{1}));assertArrayEquals(new byte[]{1},take(b));
            assertArrayEquals(a.id,b.lastPeer.get());
            assertTrue(b.endpoint.send(a.id,new byte[]{2}));assertArrayEquals(new byte[]{2},take(a));
            assertTrue(a.endpoint.send(c.id,new byte[]{3}));assertArrayEquals(new byte[]{3},take(c));
            assertTrue(c.endpoint.send(a.id,new byte[]{4}));assertArrayEquals(new byte[]{4},take(a));
            // C の受信処理が進んだ対照のあとでも、B 宛ての平文は C に来ていない。
            assertTrue(c.inbox.isEmpty());
            assertEquals(cBefore+1,c.datagrams.get());
        }
    }
    @ParameterizedTest @ValueSource(strings={"127.0.0.1","::1"})
    void lossReorderAndDuplicatesRecover(String host) throws Exception {
        try(var a=new Node(1,host,true);var b=new Node(2,host,true)) {
            a.link(b);b.link(a);a.endpoint.start(b.id);
            long began=System.nanoTime();
            await(()-> {
                ticks.set(Math.min(70,TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-began)/100*5)*1_000_000_000L);
                return a.endpoint.isEstablished(b.id)&&b.endpoint.isEstablished(a.id);
            });
            a.inbox.clear();b.inbox.clear();
            for(int n=1;n<=4;n++) assertTrue(a.endpoint.send(b.id,new byte[]{(byte)n}));
            assertArrayEquals(new byte[]{2},take(b));assertArrayEquals(new byte[]{1},take(b));
            assertArrayEquals(new byte[]{4},take(b));assertArrayEquals(new byte[]{3},take(b));
            assertTrue(b.endpoint.send(a.id,new byte[]{9}));assertTrue(b.endpoint.send(a.id,new byte[]{10}));
            assertArrayEquals(new byte[]{10},take(a));assertArrayEquals(new byte[]{9},take(a));
            assertTrue(b.inbox.isEmpty());assertTrue(a.inbox.isEmpty());
        }
    }
    @ParameterizedTest @ValueSource(strings={"127.0.0.1","::1"})
    void malformedOversizedAndUnauthenticatedRoamingHaveValidControls(String host) throws Exception {
        try(var a=new Node(1,host);var b=new Node(2,host);
            var stranger=new DatagramSocket(new InetSocketAddress(InetAddress.getByName(host),0))) {
            connect(a,b);a.inbox.clear();b.inbox.clear();
            byte[] valid=a.sessions.send(b.id,new byte[SessionPacket.MAX_PLAINTEXT]).get(0).packet();
            assertEquals(1232,valid.length);
            for(byte[] bad:List.of(Arrays.copyOf(valid,1233),new byte[100],new byte[]{'D','T','K',1})) {
                long rejected=b.endpoint.rejectedPackets();
                stranger.send(new DatagramPacket(bad,bad.length,b.address()));
                try { await(()->b.endpoint.rejectedPackets()>=rejected+1); }
                catch(AssertionError e) { throw new AssertionError("長さ="+bad.length+" 拒否="+b.endpoint.rejectedPackets()+" 受信="+b.datagrams.get()+" 閉鎖理由="+b.endpoint.closeReason(),e); }
            }
            long beforeTampered=b.endpoint.rejectedPackets();
            byte[] tampered=valid.clone();tampered[tampered.length-1]^=1;
            stranger.send(new DatagramPacket(tampered,tampered.length,b.address()));
            await(()->b.endpoint.rejectedPackets()==beforeTampered+1);
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));assertTrue(b.inbox.isEmpty());
            a.socket.send(new DatagramPacket(valid,valid.length,b.address()));
            assertEquals(1176,take(b).length);
            assertEquals(a.address(),b.endpoint.peerAddress(a.id));
            // 認証に通る新しい DATA でだけ番地を更新する。
            byte[] next=a.sessions.send(b.id,new byte[]{7}).get(0).packet();
            stranger.send(new DatagramPacket(next,next.length,b.address()));assertArrayEquals(new byte[]{7},take(b));
            assertEquals(stranger.getLocalSocketAddress(),b.endpoint.peerAddress(a.id));
            long rejected=b.endpoint.rejectedPackets();
            a.socket.send(new DatagramPacket(next,next.length,b.address()));
            await(()->b.endpoint.rejectedPackets()>rejected);
            assertEquals(stranger.getLocalSocketAddress(),b.endpoint.peerAddress(a.id));
        }
    }
    @Test void unknownAddressIsNotSentAndFirstDoesNotChangeAddress() throws Exception {
        try(var a=new Node(1,"127.0.0.1");var b=new Node(2,"127.0.0.1");
            var stranger=new DatagramSocket(new InetSocketAddress("127.0.0.1",0))) {
            a.endpoint.rememberPeer(b.cert);assertFalse(a.endpoint.send(b.id,new byte[]{1}));
            assertFalse(a.endpoint.isEstablished(b.id));
            b.link(a);
            byte[] first=a.sessions.start(b.id).packet();
            stranger.send(new DatagramPacket(first,first.length,b.address()));
            stranger.setSoTimeout(3000);var reply=new DatagramPacket(new byte[1232],1232);stranger.receive(reply);
            try(var challenge=CookieWire.decode(Arrays.copyOf(reply.getData(),reply.getLength()))) {
                assertFalse(b.sessions.isHandshaking(a.id));byte[] proof=CookieWire.proof(challenge.cookie(),first);
                stranger.send(new DatagramPacket(proof,proof.length,b.address()));
            }
            await(()->b.sessions.isHandshaking(a.id));assertEquals(a.address(),b.endpoint.peerAddress(a.id));
        }
    }
    @Test void adminUpdateClosesRevokedPeerBeforeReturnAndCallbackFailureSurvives() throws Exception {
        try(var a=new Node(1,"127.0.0.1");var b=new Node(2,"127.0.0.1")) {
            connect(a,b);a.inbox.clear();b.inbox.clear();
            b.throwCallback=true;a.endpoint.send(b.id,new byte[]{4});await(()->b.endpoint.callbackFailures()==1);
            b.throwCallback=false;a.endpoint.send(b.id,new byte[]{5});assertArrayEquals(new byte[]{5},take(b));
            var invalid=AdminRecords.list(REVOCATIONS,group,1,clock.millis(),List.of(b.id),key(93));
            assertThrows(SecurityException.class,()->a.endpoint.acceptRevocations(invalid));
            assertTrue(a.endpoint.isEstablished(b.id));
            var admins=AdminRecords.list(ADMINS,group,1,clock.millis(),List.of(Crypto.ed25519Public(admin)),admin);
            assertTrue(a.endpoint.acceptAdministrators(admins,v->fail("鎖はつながっています")));
            var revoked=AdminRecords.list(REVOCATIONS,group,1,clock.millis(),List.of(b.id),admin);
            assertTrue(CompletableFuture.supplyAsync(()->a.endpoint.acceptRevocations(revoked)).get(5,TimeUnit.SECONDS));
            assertFalse(a.endpoint.isEstablished(b.id));assertThrows(SecurityException.class,()->a.endpoint.send(b.id,new byte[]{1}));
        }
    }
    @Test void closeWaitsForCallbackWithoutHoldingSessionLock() throws Exception {
        try(var a=new Node(1,"127.0.0.1");var b=new Node(2,"127.0.0.1")) {
            connect(a,b);a.inbox.clear();b.inbox.clear();
            b.callbackEntered=new CountDownLatch(1);b.callbackRelease=new CountDownLatch(1);
            a.endpoint.send(b.id,new byte[]{1});assertTrue(b.callbackEntered.await(5,TimeUnit.SECONDS));
            var done=new CompletableFuture<Void>();
            Thread closer=new Thread(()-> { b.endpoint.close();done.complete(null); });closer.start();
            try {
                await(()->b.socket.isClosed());assertFalse(done.isDone());
                assertFalse(b.endpoint.send(a.id,new byte[]{2}));
            } finally { b.callbackRelease.countDown(); }
            done.get(5,TimeUnit.SECONDS);assertTrue(b.endpoint.isTerminated());
        }
    }
    @Test void sendFailureDoesNotKillTimerOrReceiving() throws Exception {
        try(var node=new Node(3,"127.0.0.1")) {
            var socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",0));
            var io=new UdpEndpoint.SocketIo(socket) {
                @Override public void send(byte[] wire,InetSocketAddress target) throws java.io.IOException { throw new java.io.IOException("試験"); }
            };
            // 新しい管理とソケットの所有を移し、失敗した送信でも受信待ちは続く。
            node.endpoint.close();
            try(var other=new Node(4,"127.0.0.1")) {
                var sessions=new SessionManager(node.state,node.cert,node.secret,psk,0,clock,ticks::get,256);
                try(var endpoint=new UdpEndpoint(sessions,node.state,io,(id,plain)->{},Duration.ofMillis(20))) {
                    endpoint.rememberPeer(other.cert);endpoint.setPeerAddress(other.id,other.address());endpoint.start(other.id);
                    assertEquals(1,endpoint.sendFailures());
                    ticks.addAndGet(TimeUnit.SECONDS.toNanos(5));await(()->endpoint.sendFailures()>=2);
                    assertFalse(endpoint.isTerminated());
                }
                assertTrue(socket.isClosed());
            }
        }
    }
    @Test void closeStopsThreadsSocketAndZeroesKeys() throws Exception {
        try(var a=new Node(1,"127.0.0.1");var b=new Node(2,"127.0.0.1")) {
            connect(a,b);
            byte[] local=(byte[])SessionManagerTest.field(a.sessions,"localSecret");
            byte[] groupKey=(byte[])SessionManagerTest.field(a.sessions,"psk");
            Object peer=((Map<?,?>)SessionManagerTest.field(a.sessions,"peers")).values().iterator().next();
            Object transport=SessionManagerTest.field(SessionManagerTest.field(peer,"active"),"transport");
            byte[] sending=(byte[])SessionManagerTest.field(transport,"sending");
            byte[] receiving=(byte[])SessionManagerTest.field(transport,"receiving");
            a.endpoint.close();a.endpoint.close();
            assertTrue(a.socket.isClosed());assertTrue(a.endpoint.isTerminated());
            assertArrayEquals(new byte[32],local);assertArrayEquals(new byte[32],groupKey);
            assertArrayEquals(new byte[32],sending);assertArrayEquals(new byte[32],receiving);
            assertFalse(a.endpoint.send(b.id,new byte[]{1}));assertTrue(a.sessions.poll().isEmpty());
        }
    }
}
