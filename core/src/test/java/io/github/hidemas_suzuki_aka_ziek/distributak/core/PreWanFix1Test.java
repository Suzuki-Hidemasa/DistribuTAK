// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.LongSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.JoinPortLimitsTest.*;

/** scopeのある番地はMemoryIoにだけ渡し、ソケットでは送らない。 */
class PreWanFix1Test {
    static InetSocketAddress scoped(int scope) throws Exception {
        return new InetSocketAddress(Inet6Address.getByAddress(null,InetAddress.getByName("fe80::1").getAddress(),scope),50000);
    }
    static void scope(int expected,UdpEndpoint.Datagram sent) {
        assertEquals(expected,((Inet6Address)sent.source().getAddress()).getScopeId());
    }
    static void reject(UdpEndpoint endpoint,MemoryIo io,byte[] wire,InetSocketAddress source) throws Exception {
        long before=endpoint.rejectedPackets();io.inject(wire,source);
        UdpEndpointTest.await(()->endpoint.rejectedPackets()>before);assertTrue(io.output.isEmpty());
    }
    @Test void comparisonNormalizesMappedV4AndComparesIpPortAndScope() throws Exception {
        var v4=new InetSocketAddress("127.0.0.1",50000);var mapped=UdpEndpointDualStackTest.mapped(50000);
        assertTrue(EndpointAddress.same(v4,mapped));assertTrue(EndpointAddress.same(mapped,v4));
        assertFalse(EndpointAddress.same(v4,new InetSocketAddress("127.0.0.1",50001)));
        assertFalse(EndpointAddress.same(v4,new InetSocketAddress("127.0.0.2",50000)));
        assertTrue(EndpointAddress.same(scoped(1),scoped(1)));assertFalse(EndpointAddress.same(scoped(1),scoped(2)));
    }
    @Test void memberChallengeRequiresSameScopeAndWrongScopeDoesNotConsumeAllowance() throws Exception {
        var f=new SessionManagerTest();var io=new MemoryIo();var one=scoped(1);var two=scoped(2);
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))) {
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,one);endpoint.start(b.id);byte[] first=io.take().wire();
            byte[] challenge=CookieWire.challenge(Crypto.blake2s(first),new byte[40]);
            reject(endpoint,io,challenge,two);io.inject(challenge,one);var sent=io.take();scope(1,sent);
            try(var proof=CookieWire.decode(sent.wire())) { assertEquals(CookieWire.PROOF,proof.kind());assertArrayEquals(first,proof.first()); }
        }
    }
    static void pinPending(UdpEndpoint endpoint,InetSocketAddress address) throws Exception {
        var engine=(JoinPort)SessionManagerTest.field(endpoint,"joins");
        synchronized(engine) {
            Object pending=SessionManagerTest.field(engine,"pending");
            // Invitationはscopeを載せないため、内部の照合の試験用に固定番地を置く。
            var field=pending.getClass().getDeclaredField("address");field.setAccessible(true);field.set(pending,address);
        }
    }
    @Test void joinChallengeRequiresSameScopeAndWrongScopeDoesNotConsumeAllowance() throws Exception {
        var f=new JoinHandshakeTest();var io=new MemoryIo();var one=scoped(1);var two=scoped(2);
        try(var invite=f.invitation();var joiner=f.joiner(invite);var endpoint=new UdpEndpoint(io,(id,p)->{},f.tick::get)) {
            endpoint.join(invite,joiner,j->null);byte[] first=io.take().wire();pinPending(endpoint,one);
            byte[] challenge=CookieWire.challenge(Crypto.blake2s(first),new byte[40]);
            reject(endpoint,io,challenge,two);io.inject(challenge,one);var sent=io.take();scope(1,sent);
            try(var proof=CookieWire.decode(sent.wire())) { assertArrayEquals(first,proof.first()); }
        }
    }
    @Test void fetchRequiresPinnedScopeAndSameScopeStillReceivesData() throws Exception {
        var one=scoped(1);var two=scoped(2);
        try(var f=new AdminFixture()) {
            f.io.prove(JoinWire.request(f.id,f.transfer,f.request),one);
            try(var ready=JoinWire.decode(f.io.take().wire())) {
                byte[] fetch=JoinWire.fetch(f.id,f.transfer,ready.total(),0);
                reject(f.endpoint,f.io,fetch,two);f.io.inject(fetch,one);var sent=f.io.take();scope(1,sent);
                try(var frame=JoinWire.decode(sent.wire())) { assertEquals(JoinWire.DATA,frame.kind()); }
            }
        }
    }
    static UdpEndpoint.JoinedFactory factory(JoinHandshakeTest f) {
        return joined->{
            byte[] key=joined.groupKey();
            try { return new SessionManager(joined.state(),joined.certificate(),f.f.handshake,key,joined.groupKeyVersion(),f.f.clock,f.tick::get,256); }
            finally { Crypto.wipe(key); }
        };
    }
    @Test void readyAndDataRequirePinnedScopeAndCorrectScopeCompletesJoin() throws Exception {
        var f=new JoinHandshakeTest();var io=new MemoryIo();var one=scoped(1);var two=scoped(2);
        try(var invite=f.invitation();var admin=f.admin(invite);var material=f.material();var joiner=f.joiner(invite);
            var endpoint=new UdpEndpoint(io,(id,p)->{},f.tick::get)) {
            var done=endpoint.join(invite,joiner,factory(f));byte[] first=io.take().wire();pinPending(endpoint,one);
            try(var request=JoinWire.decode(first)) {
                byte[] reply=admin.respond(request.body(),f.adminX,f.f.a,material);
                try {
                    byte[] ready=JoinWire.ready(request.invitation(),request.transfer(),reply.length);
                    reject(endpoint,io,ready,two);io.inject(ready,one);
                    var outgoing=io.take();scope(1,outgoing);
                    try(var fetch=JoinWire.decode(outgoing.wire())) {
                        byte[] data=JoinWire.data(fetch.invitation(),fetch.transfer(),reply,fetch.index());
                        long before=endpoint.rejectedPackets();io.inject(data,two);UdpEndpointTest.await(()->endpoint.rejectedPackets()>before);
                        assertFalse(done.isDone());io.inject(data,one);
                    }
                    long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
                    while(!done.isDone()) {
                        assertTrue(System.nanoTime()<deadline);outgoing=io.output.poll(50,TimeUnit.MILLISECONDS);if(outgoing==null)continue;scope(1,outgoing);
                        try(var fetch=JoinWire.decode(outgoing.wire())) { io.inject(JoinWire.data(fetch.invitation(),fetch.transfer(),reply,fetch.index()),one); }
                    }
                    assertNotNull(done.get(1,TimeUnit.SECONDS));assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());
                } finally { Crypto.wipe(reply); }
            }
        }
    }
    static final class OneShotClock implements LongSupplier {
        final AtomicBoolean armed=new AtomicBoolean();final AtomicInteger failures=new AtomicInteger();
        String fault;
        public long getAsLong() {
            if(Thread.currentThread().getName().equals("distributak-udp-receive")&&armed.compareAndSet(true,false)) {
                failures.incrementAndGet();
                if(fault.equals("state"))throw new IllegalStateException("時計の試験");
                if(fault.equals("runtime"))throw new RuntimeException("時計の試験");
                return 99;
            }
            return 100;
        }
    }
    @ParameterizedTest @CsvSource({"challenge,state","challenge,runtime","challenge,backwards","ready,state","ready,runtime","ready,backwards"})
    void oneReadFailureDuringReceiveClosesOnceAfterWiping(String stage,String fault) throws Exception {
        var f=new JoinHandshakeTest();var io=new MemoryIo();var clock=new OneShotClock();clock.fault=fault;
        var notices=new LinkedBlockingQueue<UdpEndpoint.CloseReason>();var notified=new AtomicInteger();var held=new ArrayList<byte[]>();
        try(var invite=f.invitation();var joiner=f.joiner(invite);
            var endpoint=new UdpEndpoint(io,(id,p)->{},clock,reason->{
                held.forEach(SecretAssertions::zero);notified.incrementAndGet();notices.add(reason);
            })) {
            var done=endpoint.join(invite,joiner,factory(f));byte[] first=io.take().wire();
            var engine=(JoinPort)SessionManagerTest.field(endpoint,"joins");
            synchronized(engine) {
                Object pending=SessionManagerTest.field(engine,"pending");
                for(String name:List.of("id","transfer","request"))held.add(SecretAssertions.bytes(pending,name));
            }
            held.add(SecretAssertions.bytes(joiner,"handshakeSecret"));held.add(SecretAssertions.bytes(joiner,"requestPacket"));
            var gate=(FirstPacketGate)SessionManagerTest.field(endpoint,"firstPackets");held.add(SecretAssertions.bytes(gate.cookies,"current"));
            clock.armed.set(true);
            if(stage.equals("challenge"))io.inject(CookieWire.challenge(Crypto.blake2s(first),new byte[40]),SOURCE);
            else try(var request=JoinWire.decode(first)) { io.inject(JoinWire.ready(request.invitation(),request.transfer(),100),SOURCE); }
            assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,notices.poll(3,TimeUnit.SECONDS));
            endpoint.close();assertTrue(endpoint.isTerminated());assertTrue(done.isDone());assertThrows(Exception.class,done::get);assertEquals(1,clock.failures.get());
            assertEquals(1,notified.get());assertTrue(notices.isEmpty());assertTrue(io.output.isEmpty());assertTrue(joiner.isClosed());held.forEach(SecretAssertions::zero);
            // 呼び出し元の招待の所有は移していない。
            assertArrayEquals(f.secret,invite.totpSecret());
        }
    }
}
