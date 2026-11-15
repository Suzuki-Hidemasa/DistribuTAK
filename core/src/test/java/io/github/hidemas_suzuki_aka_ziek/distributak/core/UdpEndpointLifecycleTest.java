// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpointTest.await;

class UdpEndpointLifecycleTest {
    static final class Io implements UdpEndpoint.DatagramIo {
        final BlockingQueue<Boolean> input=new LinkedBlockingQueue<>();
        volatile boolean closed;
        public UdpEndpoint.Datagram receive() throws IOException {
            try { input.take();throw new IOException("受信の故障の試験"); }
            catch(InterruptedException e) { Thread.currentThread().interrupt();throw new IOException("終了"); }
        }
        public void send(byte[] bytes,java.net.InetSocketAddress address) {}
        public void close() { closed=true;input.offer(false); }
    }
    @ParameterizedTest @ValueSource(strings={"revocation","expiry","receive","clock-backwards","clock-throws","member-clock-throws","expired-and-clock-throws","join","caller"})
    void eachReasonIsReportedOnceAfterCleanup(String trigger) throws Exception {
        var sessions=new SessionManagerTest();var io=new Io();
        var notices=new LinkedBlockingQueue<UdpEndpoint.CloseReason>();var calls=new AtomicInteger();
        var tick=new AtomicLong(100);var broken=new AtomicBoolean();
        LongSupplier ticker=()->{if(broken.get())throw new IllegalStateException("時計の故障の試験");return tick.get();};
        try(var node=sessions.new Node(1)) {
            SessionManager manager=trigger.equals("member-clock-throws")||trigger.equals("expired-and-clock-throws")
                ? new SessionManager(node.state,node.cert,node.secret,sessions.psk,0,sessions.time,ticker,256) : node.sessions;
            UdpEndpoint endpoint=trigger.equals("join")
                ? new UdpEndpoint(io,(id,plain)->{},ticker,reason->{calls.incrementAndGet();notices.add(reason);})
                : new UdpEndpoint(manager,node.state,io,(id,plain)->{},Duration.ofMillis(10),
                    trigger.startsWith("member-")||trigger.startsWith("expired-and-") ? System::nanoTime : ticker,
                    reason->{assertTrue(io.closed);assertTrue(manager.isClosed());calls.incrementAndGet();notices.add(reason);});
            try {
                var expected=switch(trigger) {
                    case "revocation" -> UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID;
                    case "expiry","expired-and-clock-throws" -> UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED;
                    case "receive" -> UdpEndpoint.CloseReason.RECEIVE_FAILURE;
                    case "clock-backwards","clock-throws","member-clock-throws" -> UdpEndpoint.CloseReason.CLOCK_FAILURE;
                    case "join" -> UdpEndpoint.CloseReason.JOIN_FAILURE;
                    default -> UdpEndpoint.CloseReason.CLOSED_BY_CALLER;
                };
                switch(trigger) {
                    case "revocation" -> endpoint.acceptRevocations(AdminRecords.list(REVOCATIONS,sessions.group,1,sessions.time.millis(),List.of(node.id),sessions.admin));
                    case "expiry" -> sessions.time.advance(30L*24*60*60);
                    case "receive" -> io.input.offer(true);
                    case "member-clock-throws" -> broken.set(true);
                    case "expired-and-clock-throws" -> {
                        sessions.time.advance(30L*24*60*60);broken.set(true);
                        assertFalse(endpoint.isEstablished(new byte[32]));
                    }
                    case "clock-backwards","clock-throws" -> {
                        var joins=(JoinPort)SessionManagerTest.field(endpoint,"joins");
                        await(()->{synchronized(joins){return (long)SessionManagerTest.field(joins,"lastTime")==100;}});
                        if(trigger.equals("clock-backwards"))tick.set(50);else broken.set(true);
                    }
                    case "join" -> {
                        var join=new JoinHandshakeTest();
                        try(var invitation=join.invitation();var joiner=join.joiner(invitation)) {
                            var future=endpoint.join(invitation,joiner,joined->null);
                            tick.addAndGet(JoinPort.LIFETIME);
                            await(future::isDone);assertTrue(future.isDone());assertThrows(Exception.class,future::get);
                        }
                    }
                    default -> endpoint.close();
                }
                assertEquals(expected,notices.poll(3,TimeUnit.SECONDS));
                endpoint.close();endpoint.close();assertTrue(endpoint.isTerminated());
                assertEquals(1,calls.get());assertTrue(notices.isEmpty());assertEquals(expected,endpoint.closeReason());
            } finally { endpoint.close(); }
        }
    }
    @Test void notificationCanCloseAndThrowWithoutLosingTermination() throws Exception {
        var f=new SessionManagerTest();var io=new Io();var ref=new AtomicReference<UdpEndpoint>();
        var calls=new AtomicInteger();var returned=new CountDownLatch(1);
        try(var node=f.new Node(1)) {
            var endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1),reason->{
                calls.incrementAndGet();ref.get().close();returned.countDown();throw new IllegalStateException("通知の試験");
            });ref.set(endpoint);
            try {
                endpoint.close();assertTrue(returned.await(3,TimeUnit.SECONDS));
                assertEquals(1,calls.get());assertEquals(1,endpoint.callbackFailures());assertTrue(endpoint.isTerminated());
            } finally { endpoint.close(); }
        }
    }
    @Test void externalCloseWaitsForNotificationWithoutHoldingTheLock() throws Exception {
        var f=new SessionManagerTest();var io=new Io();var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
        try(var node=f.new Node(1)) {
            var endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1),reason->{
                entered.countDown();
                try { if(!release.await(3,TimeUnit.SECONDS))throw new IllegalStateException("試験の期限"); }
                catch(InterruptedException e) { Thread.currentThread().interrupt(); }
            });
            var done=CompletableFuture.runAsync(endpoint::close);
            try {
                assertTrue(entered.await(3,TimeUnit.SECONDS));assertFalse(done.isDone());
                assertFalse(endpoint.send(new byte[32],new byte[0]));
            } finally { release.countDown();done.get(3,TimeUnit.SECONDS);endpoint.close(); }
            assertTrue(endpoint.isTerminated());
        }
    }
    @Test void notificationWaitsForBorrowedPlaintextToBeWiped() throws Exception {
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var notified=new AtomicBoolean();
        var borrowed=new AtomicReference<byte[]>();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            f.connect(a,b);
            var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,plain)->{
                borrowed.set(plain);entered.countDown();
                try { release.await(3,TimeUnit.SECONDS); }
                catch(InterruptedException e) { Thread.currentThread().interrupt(); }
            },Duration.ofDays(1),reason->{
                assertArrayEquals(new byte[3],borrowed.get());notified.set(true);
            });
            io.inject(b.sessions.send(a.id,new byte[]{1,2,3}).get(0).packet(),JoinPortLimitsTest.SOURCE);
            var done=new CompletableFuture<Void>();
            try {
                assertTrue(entered.await(3,TimeUnit.SECONDS));
                new Thread(()->{endpoint.close();done.complete(null);}).start();
                await(()->io.closed);assertFalse(notified.get());assertFalse(done.isDone());
            } finally { release.countDown();done.get(3,TimeUnit.SECONDS);endpoint.close(); }
            assertTrue(notified.get());assertEquals(0,endpoint.callbackFailures());
        }
    }
    @Test void notificationWaitsForProviderSecretsToBeWiped() throws Exception {
        var f=new JoinHandshakeTest();var sessions=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var notified=new AtomicBoolean();
        byte[] handshake=f.adminX.clone(),administrator=f.f.a.clone();
        try(var node=sessions.new Node(1);var invitation=f.invitation();var admin=f.admin(invitation);var joiner=f.joiner(invitation)) {
            var endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1),reason->{
                assertArrayEquals(new byte[32],handshake);assertArrayEquals(new byte[32],administrator);notified.set(true);
            });
            endpoint.registerInvitation(admin,()->{
                JoinPortFix1Test.releaseAfter(entered,release);
                return new UdpEndpoint.JoinMaterials(handshake,administrator,f.material());
            },result->{});
            io.prove(JoinWire.request(admin.invitationId(),new byte[16],joiner.request()),JoinPortLimitsTest.SOURCE);
            var done=new CompletableFuture<Void>();
            try {
                assertTrue(entered.await(3,TimeUnit.SECONDS));
                new Thread(()->{endpoint.close();done.complete(null);}).start();
                await(()->io.closed);assertFalse(notified.get());assertFalse(done.isDone());
            } finally { release.countDown();done.get(3,TimeUnit.SECONDS);endpoint.close(); }
            assertTrue(notified.get());assertEquals(0,endpoint.callbackFailures());
        } finally { Crypto.wipe(handshake);Crypto.wipe(administrator); }
    }
}
