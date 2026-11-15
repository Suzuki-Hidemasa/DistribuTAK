// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.*;

class JoinPortFix1Test {
    static void await(UdpEndpointTest.Check check) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
        while(!check.ok()) {
            if(System.nanoTime()>=deadline)fail("条件が3秒以内に成立しませんでした");
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
        }
    }
    static void releaseAfter(CountDownLatch entered,CountDownLatch release) {
        entered.countDown();
        try { if(!release.await(5,TimeUnit.SECONDS))throw new IllegalStateException("試験の期限です"); }
        catch(InterruptedException e) { Thread.currentThread().interrupt();throw new IllegalStateException(e); }
    }
    @Test void simultaneousReceiverAndJoinCallbackCloseReturnAndWipeCopies() throws Exception {
        var f=new SessionManagerTest();var join=new JoinHandshakeTest();var io=new MemoryIo();
        var both=new CyclicBarrier(2);var returned=new CountDownLatch(2);var endpointRef=new AtomicReference<UdpEndpoint>();
        var plain=new AtomicReference<byte[]>();var cached=new AtomicReference<byte[]>();var request=new AtomicReference<byte[]>();
        var materialsSecret=new AtomicReference<byte[]>();var errors=new ConcurrentLinkedQueue<Throwable>();
        Runnable close=()->{
            try { both.await(3,TimeUnit.SECONDS);endpointRef.get().close();returned.countDown(); }
            catch(Throwable error) { errors.add(error); }
        };
        try(var a=f.new Node(1);var b=f.new Node(2);var invite=join.invitation();var admin=join.admin(invite);var joiner=join.joiner(invite)) {
            f.connect(a,b);
            var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,value)->{plain.set(value);close.run();},Duration.ofDays(1));endpointRef.set(endpoint);
            var engine=(JoinPort)SecretAssertions.field(endpoint,"joins");
            var registration=(JoinPort.Registration)endpoint.registerInvitation(admin,()->{
                byte[] secret=join.adminX.clone();materialsSecret.set(secret);
                return new UdpEndpoint.JoinMaterials(secret,join.f.a.clone(),join.material());
            },result->{
                try {
                    cached.set(SecretAssertions.bytes(admin,"cachedReply"));
                    synchronized(engine) { request.set(((JoinPort.Registration)SecretAssertions.field(engine,"active")).request); }
                } catch(Exception e) { errors.add(e); }
                close.run();
            });
            try {
                io.prove(JoinWire.request(admin.invitationId(),new byte[16],joiner.request()),SOURCE);
                io.inject(f.data(b,a,7),OTHER);
                assertTrue(returned.await(5,TimeUnit.SECONDS),"両方の通知からのcloseが戻りませんでした");assertTrue(errors.isEmpty());
                await(endpoint::isTerminated);endpoint.close();
                assertEquals(UdpEndpoint.CloseReason.CLOSED_BY_CALLER,endpoint.closeReason());
                SecretAssertions.zero(plain.get());SecretAssertions.zero(cached.get());SecretAssertions.zero(request.get());SecretAssertions.zero(materialsSecret.get());
                synchronized(engine) { assertEquals(0,SecretAssertions.field(engine,"adminJobs"));assertNull(registration.reply); }
            } finally {
                // 修正前の循環待ちを試したときは、テスト自身までcloseで止めない。
                if(returned.getCount()==0)endpoint.close();
                else io.close();
            }
        }
    }
    @Test void externalCloseWaitsUntilJoinCallbackAndFinallyFinish() throws Exception {
        var f=new JoinHandshakeTest();var sessions=new SessionManagerTest();var io=new MemoryIo();
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var cached=new AtomicReference<byte[]>();
        try(var node=sessions.new Node(1);var invite=f.invitation();var admin=f.admin(invite);var joiner=f.joiner(invite);
            var endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1))) {
            var engine=(JoinPort)SecretAssertions.field(endpoint,"joins");
            var registration=(JoinPort.Registration)endpoint.registerInvitation(admin,
                    ()->new UdpEndpoint.JoinMaterials(f.adminX.clone(),f.f.a.clone(),f.material()),result->{
                try { cached.set(SecretAssertions.bytes(admin,"cachedReply")); }
                catch(Exception e) { throw new IllegalStateException(e); }
                releaseAfter(entered,release);
            });
            io.prove(JoinWire.request(admin.invitationId(),new byte[16],joiner.request()),SOURCE);
            assertTrue(entered.await(3,TimeUnit.SECONDS));
            byte[] request;
            synchronized(engine) { request=registration.request;assertEquals(1,SecretAssertions.field(engine,"adminJobs")); }
            var closed=CompletableFuture.runAsync(endpoint::close);
            try {
                await(()->io.closed);assertFalse(closed.isDone());
                synchronized(engine) { assertEquals(1,SecretAssertions.field(engine,"adminJobs")); }
            } finally { release.countDown(); }
            closed.get(5,TimeUnit.SECONDS);assertTrue(endpoint.isTerminated());
            synchronized(engine) { assertEquals(0,SecretAssertions.field(engine,"adminJobs")); }
            SecretAssertions.zero(request);SecretAssertions.zero(cached.get());
        } finally { release.countDown(); }
    }
    @ParameterizedTest @ValueSource(strings={"admin-backwards","admin-throws","joiner-backwards","joiner-throws"})
    void backwardsAndThrowingClockCloseBothRolesWithClockFailure(String scenario) throws Exception {
        var f=new JoinHandshakeTest();var io=new MemoryIo();var ticks=new AtomicLong(100);var broken=new AtomicBoolean();
        java.util.function.LongSupplier clock=()->{
            if(broken.get())throw new IllegalStateException("時計の試験");return ticks.get();
        };
        if(scenario.startsWith("admin")) {
            var sessions=new SessionManagerTest();
            // Adminの時計は逆行させない。口がAdminを閉じるところまで確かめる。
            try(var node=sessions.new Node(1);var invite=f.invitation();var admin=f.admin(invite);var joiner=f.joiner(invite);
                var endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1),clock)) {
                var registration=(JoinPort.Registration)endpoint.registerInvitation(admin,
                        ()->new UdpEndpoint.JoinMaterials(f.adminX.clone(),f.f.a.clone(),f.material()),result->{});
                io.prove(JoinWire.request(admin.invitationId(),new byte[16],joiner.request()),SOURCE);io.take();
                var engine=(JoinPort)SecretAssertions.field(endpoint,"joins");
                byte[] reply;
                synchronized(engine) { reply=registration.reply; }
                byte[] cached=SecretAssertions.bytes(admin,"cachedReply"),local=SecretAssertions.bytes(node.sessions,"localSecret"),psk=SecretAssertions.bytes(node.sessions,"psk");
                await(()->{synchronized(engine){return (long)SecretAssertions.field(engine,"lastTime")==100;}});
                if(scenario.endsWith("throws"))broken.set(true);else ticks.set(50);
                await(endpoint::isTerminated);assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,endpoint.closeReason());assertTrue(admin.isClosed());
                SecretAssertions.zero(reply);SecretAssertions.zero(cached);SecretAssertions.zero(local);SecretAssertions.zero(psk);
            }
        } else {
            try(var invite=f.invitation();var joiner=f.joiner(invite);var endpoint=new UdpEndpoint(io,(id,plain)->{},clock)) {
                byte[] secret=SecretAssertions.bytes(joiner,"handshakeSecret");var done=endpoint.join(invite,joiner,joined->null);
                try(var request=JoinWire.decode(io.take().wire())) {
                    byte[] response=new byte[2048];Arrays.fill(response,(byte)7);
                    io.inject(JoinWire.ready(request.invitation(),request.transfer(),response.length),SOURCE);io.take();
                    io.inject(JoinWire.data(request.invitation(),request.transfer(),response,0),SOURCE);
                    var engine=(JoinPort)SecretAssertions.field(endpoint,"joins");
                    var pending=(JoinPort.Pending)SecretAssertions.field(engine,"pending");
                    await(()->{synchronized(engine){return pending.assembly.bytes()[0]==7;}});
                    byte[] assembled=pending.assembly.bytes(),heldRequest=pending.request;
                    await(()->{synchronized(engine){return (long)SecretAssertions.field(engine,"lastTime")==100;}});
                    if(scenario.endsWith("throws"))broken.set(true);else ticks.set(50);
                    await(endpoint::isTerminated);assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,endpoint.closeReason());assertTrue(done.isDone());assertThrows(Exception.class,done::get);
                    SecretAssertions.zero(secret);SecretAssertions.zero(assembled);SecretAssertions.zero(heldRequest);
                }
            }
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void issuedCertificateIsReportedOnceEvenWhenRespondExceedsTransportLifetime(boolean expired) throws Exception {
        var f=new JoinHandshakeTest();var sessions=new SessionManagerTest();var io=new MemoryIo();
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var notifications=new AtomicInteger();
        try(var node=sessions.new Node(1);var invite=f.invitation();
            var admin=new JoinHandshake.Admin(invite,f.chain().get(0),AdminRecords.signAnchor(f.chain().get(0),f.f.a),f.f.clock,f.tick::get,
                    ignored->releaseAfter(entered,release));var joiner=f.joiner(invite);
            var endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1),f.tick::get)) {
            var registration=(JoinPort.Registration)endpoint.registerInvitation(admin,
                    ()->new UdpEndpoint.JoinMaterials(f.adminX.clone(),f.f.a.clone(),f.material()),result->notifications.incrementAndGet());
            var engine=(JoinPort)SecretAssertions.field(endpoint,"joins");
            io.prove(JoinWire.request(admin.invitationId(),new byte[16],joiner.request()),SOURCE);
            assertTrue(entered.await(3,TimeUnit.SECONDS));byte[] request;
            synchronized(engine) { request=registration.request; }
            if(expired)f.tick.set(JoinPort.LIFETIME+1);release.countDown();
            await(()->{synchronized(engine){return (int)SecretAssertions.field(engine,"adminJobs")==0;}});
            assertTrue(admin.isConsumed());assertEquals(1,notifications.get());assertNotNull(registration.lastJoined());
            assertArrayEquals(admin.issuedCertificate().encode(),registration.lastJoined().certificate().encode());
            if(expired) {
                assertTrue(io.output.isEmpty());SecretAssertions.zero(request);
                synchronized(engine) { assertNull(registration.reply);assertNull(registration.request); }
            } else assertEquals(JoinWire.READY,JoinWire.decode(io.take().wire()).kind());
            endpoint.close();assertNull(registration.lastJoined());
        } finally { release.countDown(); }
    }
}
