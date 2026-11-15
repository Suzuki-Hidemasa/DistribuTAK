// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.IOException;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class JoinPortLimitsTest {
    static final InetSocketAddress SOURCE=new InetSocketAddress("127.0.0.1",50000),OTHER=new InetSocketAddress("127.0.0.1",50001);
    static final class MemoryIo implements UdpEndpoint.DatagramIo {
        final BlockingQueue<UdpEndpoint.Datagram> input=new LinkedBlockingQueue<>(),output=new LinkedBlockingQueue<>();
        volatile boolean closed;
        void inject(byte[] wire,InetSocketAddress source) { input.add(new UdpEndpoint.Datagram(wire.clone(),source)); }
        void prove(byte[] wire,InetSocketAddress source) throws Exception {
            inject(wire,source);var response=take();assertEquals(source,response.source());
            try(var challenge=CookieWire.decode(response.wire())) {
                assertEquals(CookieWire.CHALLENGE,challenge.kind());assertArrayEquals(Crypto.blake2s(wire),challenge.hash());
                inject(CookieWire.proof(challenge.cookie(),wire),source);
            }
        }
        public UdpEndpoint.Datagram receive() throws IOException {
            try { var result=input.take();if(closed)throw new IOException("終了");return result; }
            catch(InterruptedException e) { Thread.currentThread().interrupt();throw new IOException("終了"); }
        }
        public void send(byte[] wire,InetSocketAddress target) { output.add(new UdpEndpoint.Datagram(wire.clone(),target)); }
        public void close() { closed=true;input.add(new UdpEndpoint.Datagram(new byte[0],SOURCE)); }
        UdpEndpoint.Datagram take() throws Exception { var result=output.poll(5,TimeUnit.SECONDS);assertNotNull(result);return result; }
    }
    static final class AdminFixture implements AutoCloseable {
        final JoinHandshakeTest f=new JoinHandshakeTest();
        final SessionManagerTest sf=new SessionManagerTest();
        final SessionManagerTest.Node node=sf.new Node(1);
        final Invitation invitation=f.invitation();
        final JoinHandshake.Admin admin=f.admin(invitation);
        final JoinHandshake.Joiner joiner=f.joiner(invitation);
        final MemoryIo io=new MemoryIo();
        final AtomicInteger calls=new AtomicInteger();
        final AtomicBoolean clockBroken=new AtomicBoolean();
        final UdpEndpoint endpoint=new UdpEndpoint(node.sessions,node.state,io,(id,plain)->{},Duration.ofDays(1),()->{
            if(clockBroken.get())throw new IllegalStateException("時計の試験");return f.tick.get();
        });
        final byte[] transfer=new byte[16],request=joiner.request(),id=admin.invitationId();
        UdpEndpoint.InvitationRegistration registration;
        AdminFixture() {
            registration=endpoint.registerInvitation(admin,()->{
                calls.incrementAndGet();return new UdpEndpoint.JoinMaterials(f.adminX.clone(),f.f.a.clone(),f.material());
            },result->{});
        }
        void begin() throws Exception { io.prove(JoinWire.request(id,transfer,request),SOURCE); }
        byte[] ready() throws Exception { begin();return io.take().wire(); }
        public void close() { endpoint.close();joiner.close();admin.close();invitation.close();node.close(); }
    }
    @Test void unknownInvitationAndUnknownHeadersDoNoCryptoAndThenValidRequestWorks() throws Exception {
        try(var f=new AdminFixture()) {
            byte[] unknown=f.id.clone();unknown[0]^=1;
            for(byte[] bad:List.of(JoinWire.request(unknown,f.transfer,f.request),new byte[]{'B','A','D',1},new byte[1233])) {
                long before=f.endpoint.rejectedPackets();f.io.inject(bad,SOURCE);UdpEndpointTest.await(()->f.endpoint.rejectedPackets()>before);
                assertEquals(0,f.calls.get());assertFalse(f.admin.isConsumed());assertTrue(f.io.output.isEmpty());
            }
            byte[] ready=f.ready();assertEquals(64,ready.length);assertEquals(1,f.calls.get());assertTrue(f.admin.isConsumed());
        }
    }
    @ParameterizedTest @ValueSource(strings={"expire","revoke","close"})
    void closedInvitationRejectsBeforeProviderWithOpenControl(String action) throws Exception {
        try(var good=new AdminFixture()) { good.ready();assertEquals(1,good.calls.get()); }
        try(var f=new AdminFixture()) {
            switch(action) {
                case "expire" -> f.f.tick.set(Duration.ofHours(24).toNanos());
                case "revoke" -> f.admin.revoke();
                case "close" -> f.admin.close();
                default -> fail();
            }
            var engine=(JoinPort)SecretAssertions.field(f.endpoint,"joins");
            UdpEndpointTest.await(()->{synchronized(engine){return ((JoinPort.Registration)f.registration).ended;}});
            long before=f.endpoint.rejectedPackets();f.io.inject(JoinWire.request(f.id,f.transfer,f.request),SOURCE);
            UdpEndpointTest.await(()->f.endpoint.rejectedPackets()>before);assertEquals(0,f.calls.get());assertTrue(f.io.output.isEmpty());
            assertTrue(f.admin.isClosed());
        }
    }
    @Test void cachedReplyExpiresAtTenSecondsAndCannotBeExtendedByFetch() throws Exception {
        try(var f=new AdminFixture()) {
            try(var ready=JoinWire.decode(f.ready())) {
                var engine=(JoinPort)SecretAssertions.field(f.endpoint,"joins");
                var registration=(JoinPort.Registration)f.registration;
                byte[] transportReply;
                synchronized(engine) { transportReply=registration.reply; }
                byte[] coreReply=SecretAssertions.bytes(f.admin,"cachedReply");
                f.f.tick.set(JoinPort.LIFETIME-1);f.io.inject(JoinWire.fetch(f.id,f.transfer,ready.total(),0),SOURCE);
                assertEquals(JoinWire.DATA,JoinWire.decode(f.io.take().wire()).kind());
                f.f.tick.set(JoinPort.LIFETIME);
                UdpEndpointTest.await(()->{synchronized(engine){return registration.reply==null;}});
                SecretAssertions.zero(transportReply);SecretAssertions.zero(coreReply);
                long before=f.endpoint.rejectedPackets();f.io.inject(JoinWire.request(f.id,f.transfer,f.request),SOURCE);UdpEndpointTest.await(()->f.endpoint.rejectedPackets()>before);
                assertTrue(f.io.output.isEmpty());assertEquals(1,f.calls.get());
            }
        }
    }
    @Test void joinClockFailureStopsEndpointAndWipesBothReplyCopies() throws Exception {
        try(var f=new AdminFixture()) {
            f.ready();var engine=(JoinPort)SecretAssertions.field(f.endpoint,"joins");
            byte[] transportReply;
            synchronized(engine) { transportReply=((JoinPort.Registration)f.registration).reply; }
            byte[] coreReply=SecretAssertions.bytes(f.admin,"cachedReply");
            f.clockBroken.set(true);UdpEndpointTest.await(f.endpoint::isTerminated);
            assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,f.endpoint.closeReason());assertTrue(f.admin.isClosed());
            SecretAssertions.zero(transportReply);SecretAssertions.zero(coreReply);
        }
    }
    @Test void spoofedRequestAndFetchCannotAmplifyOrRedirectAndRatesAreBounded() throws Exception {
        try(var f=new AdminFixture()) {
            byte[] ready=f.ready();assertTrue(ready.length<=JoinWire.HEADER+f.request.length);
            try(var metadata=JoinWire.decode(ready)) {
                assertTrue(f.io.output.isEmpty());
                long before=f.endpoint.rejectedPackets();
                f.io.inject(JoinWire.fetch(f.id,f.transfer,metadata.total(),0),OTHER);
                UdpEndpointTest.await(()->f.endpoint.rejectedPackets()>before);assertTrue(f.io.output.isEmpty());
                byte[] fetch=JoinWire.fetch(f.id,f.transfer,metadata.total(),0);
                f.io.inject(fetch,SOURCE);var response=f.io.take();assertEquals(SOURCE,response.source());assertTrue(response.wire().length<=fetch.length);
                // 同じREQUESTへのREADYは返すが、DATAの一斉送信はしない。
                f.begin();assertEquals(JoinWire.READY,JoinWire.decode(f.io.take().wire()).kind());assertTrue(f.io.output.isEmpty());
                assertEquals(1,f.calls.get());
            }
        }
        var peer=new JoinPort.Budget(4096);var total=new JoinPort.Budget(8192);
        for(int i=0;i<8192;i++) { assertTrue(total.take(0));if(i<4096)assertTrue(peer.take(0));else assertFalse(peer.take(0)); }
        assertFalse(total.take(0));assertTrue(total.take(JoinPort.SECOND));assertTrue(peer.take(JoinPort.SECOND));
    }
    @Test void malformedFragmentsAndOversizeHaveValidControls() throws Exception {
        byte[] raw=new byte[1169],id=key(1),transfer=new byte[16];Arrays.fill(raw,(byte)7);
        var assembly=new JoinWire.Assembly(raw.length);
        byte[] good=JoinWire.data(id,transfer,raw,0),bad=good.clone();bad[63]^=1;
        assertThrows(IllegalArgumentException.class,()->assembly.add(JoinWire.decode(bad)));
        try(var frame=JoinWire.decode(good)) { assertTrue(assembly.add(frame)); }
        byte[] shortTail=Arrays.copyOf(JoinWire.data(id,transfer,raw,1),64);
        assertThrows(IllegalArgumentException.class,()->JoinWire.decode(shortTail));
        try(var frame=JoinWire.decode(JoinWire.data(id,transfer,raw,1))) { assertTrue(assembly.add(frame)); }
        assertTrue(assembly.complete());assertArrayEquals(raw,assembly.bytes());assembly.close();
        assertThrows(IllegalArgumentException.class,()->JoinWire.ready(id,transfer,JoinHandshake.MAX_RESPONSE_BYTES+1));
        assertDoesNotThrow(()->JoinWire.ready(id,transfer,JoinHandshake.MAX_RESPONSE_BYTES));
    }
    @ParameterizedTest @ValueSource(strings={"timeout","cancel","backwards"})
    void timeoutAndCancellationWipeJoinerAndAssembly(String action) throws Exception {
        var f=new JoinHandshakeTest();var ticks=new AtomicLong();var io=new MemoryIo();
        try(var invitation=f.invitation();var joiner=f.joiner(invitation);var endpoint=new UdpEndpoint(io,(id,plain)->{},ticks::get)) {
            byte[] secret=SecretAssertions.bytes(joiner,"handshakeSecret");
            var done=endpoint.join(invitation,joiner,joined->{throw new IllegalStateException("呼ばれない");});
            try(var request=JoinWire.decode(io.take().wire())) {
                io.inject(JoinWire.ready(request.invitation(),request.transfer(),4096),SOURCE);
                io.take(); // FETCHが出たので配列は確保済み。
                Object engine=SecretAssertions.field(endpoint,"joins"),pending=SecretAssertions.field(engine,"pending");
                var assembly=(JoinWire.Assembly)SecretAssertions.field(pending,"assembly");byte[] held=assembly.bytes();
                if(action.equals("cancel")) endpoint.close();else ticks.set(action.equals("backwards")?-1:JoinPort.LIFETIME);
                UdpEndpointTest.await(endpoint::isTerminated);assertTrue(done.isDone());assertThrows(Exception.class,done::get);SecretAssertions.zero(secret);SecretAssertions.zero(held);
            }
        }
    }
    @Test void requestRetriesRemainFiveAtOneSecondAndLatePollDoesNotBurst() throws Exception {
        var f=new JoinHandshakeTest();var ticks=new AtomicLong();var io=new MemoryIo();
        try(var invitation=f.invitation();var joiner=f.joiner(invitation);var endpoint=new UdpEndpoint(io,(id,plain)->{},ticks::get)) {
            endpoint.join(invitation,joiner,joined->null);byte[] first=io.take().wire();
            for(int n=1;n<=5;n++) { ticks.set(n*JoinPort.SECOND);assertArrayEquals(first,io.take().wire()); }
            ticks.set(9*JoinPort.SECOND);
            var engine=(JoinPort)SecretAssertions.field(endpoint,"joins");
            UdpEndpointTest.await(()->{synchronized(engine){return (long)SecretAssertions.field(engine,"lastTime")==ticks.get();}});
            assertTrue(io.output.isEmpty());assertThrows(IllegalStateException.class,joiner::retry);
            ticks.set(JoinPort.LIFETIME);UdpEndpointTest.await(endpoint::isTerminated);
        }
    }
    @Test void callbackFailureKeepsPublishedResultAndProviderFailureWipesSecrets() throws Exception {
        try(var f=new AdminFixture()) {
            f.registration.close();
            // 別のAdminで招待を開き直す。取り消したAdminは再利用しない。
            try(var admin=f.f.admin(f.invitation)) {
                var registration=f.endpoint.registerInvitation(admin,()->new UdpEndpoint.JoinMaterials(f.f.adminX.clone(),f.f.f.a.clone(),f.f.material()),result->{throw new IllegalStateException("試験");});
                f.begin();assertEquals(JoinWire.READY,JoinWire.decode(f.io.take().wire()).kind());
                assertEquals(1,f.endpoint.callbackFailures());assertNotNull(registration.lastJoined());
                assertArrayEquals(Crypto.ed25519Public(f.f.f.identity),registration.lastJoined().identityKey());
                assertArrayEquals(Crypto.x25519Public(f.f.f.handshake),registration.lastJoined().handshakeKey());
                registration.close();assertNull(registration.lastJoined());
            }
        }
        var x=key(1);var sign=key(2);var fixture=new JoinHandshakeTest();var materials=fixture.material();
        try(var owned=new UdpEndpoint.JoinMaterials(x,sign,materials)) {
            assertThrows(SecurityException.class,()->{
                try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite)) {
                    try(owned) { admin.respond(joiner.request(),owned.handshakeSecret(),owned.administratorSecret(),owned.materials()); }
                }
            });
            SecretAssertions.zero(x);SecretAssertions.zero(sign);SecretAssertions.zero(SecretAssertions.bytes(materials,"groupKey"));
        }
    }
    @Test void invitationLimitAndDuplicateRegistrationHaveValidControl() throws Exception {
        try(var f=new AdminFixture()) {
            assertThrows(IllegalArgumentException.class,()->f.endpoint.registerInvitation(f.admin,()->null,r->{}));
            List<JoinHandshake.Admin> admins=new ArrayList<>();
            try {
                for(int i=0;i<8;i++) {
                    try(var invitation=new Invitation(f.invitation.adminAddress(),50000,f.invitation.handshakePublicKey(),f.invitation.adminPublicKey(),key(100+i), f.invitation.groupId())) {
                        var admin=f.f.admin(invitation);admins.add(admin);
                        if(i<7)assertNotNull(f.endpoint.registerInvitation(admin,()->null,r->{}));
                        else assertThrows(IllegalArgumentException.class,()->f.endpoint.registerInvitation(admin,()->null,r->{}));
                    }
                }
            } finally { for(var admin:admins)admin.close(); }
        }
    }
    @Test void mismatchedAddressFamilyFailsBeforeAnyDatagram() throws Exception {
        var f=new JoinHandshakeTest();
        try(var socket=new DatagramSocket(new InetSocketAddress("::1",0));var endpoint=new UdpEndpoint(socket,(id,plain)->{});
            var invite=f.invitation();var joiner=f.joiner(invite)) {
            assertThrows(IllegalArgumentException.class,()->endpoint.join(invite,joiner,result->null));
            assertEquals(UdpEndpoint.CloseReason.RUNNING,endpoint.closeReason());
        }
    }
    @ParameterizedTest @ValueSource(strings={"small-corrupt","small-exhaust","2MiB","15MiB"})
    void injectedReceiverTransfersLargeAuthenticatedRepliesAndRecoversCorruption(String size) throws Exception {
        var f=new JoinHandshakeTest();var io=new MemoryIo();byte[] reply=null;
        List<byte[]> entries=new ArrayList<>();
        if(!size.startsWith("small")) for(int i=0;i<65536;i++)entries.add(AdminRecordsFix1Test.id(i));
        List<AdminRecords.Record> history=f.chain();
        if(size.equals("15MiB")) {
            entries.set(0,f.f.ap);history=new ArrayList<>();history.add(AdminProofFixtures.unboundHistory(f.chain().get(0),f.f.b));
            for(int n=1;n<=7;n++) history.add(AdminProofFixtures.unboundHistory(AdminRecords.list(AdminRecords.Kind.ADMINS,f.f.group,n,f.f.now,entries,n==1?f.f.b:f.f.a),n==1?f.f.b:f.f.a));
        }
        var revocations=f.f.revocations(0,f.f.now,size.equals("2MiB")?entries:List.of(),f.f.a);
        try(var invite=f.invitation();var admin=new JoinHandshake.Admin(invite,history.get(0),AdminRecords.signAnchor(history.get(0),f.f.a),f.f.clock,f.tick::get);var joiner=f.joiner(invite);
            var materials=new JoinHandshake.Materials(history,revocations,0,f.groupKey);
            var endpoint=new UdpEndpoint(io,(id,plain)->{},System::nanoTime)) {
            long began=System.nanoTime();
            var done=endpoint.join(invite,joiner,joined->{
                byte[] psk=joined.groupKey();
                try { return new SessionManager(joined.state(),joined.certificate(),f.f.handshake,psk,joined.groupKeyVersion(),f.f.clock,System::nanoTime,256); }
                finally { Crypto.wipe(psk); }
            });
            try(var request=JoinWire.decode(io.take().wire())) {
                reply=admin.respond(request.body(),f.adminX,f.f.a,materials);
                io.inject(JoinWire.ready(request.invitation(),request.transfer(),reply.length),SOURCE);
                boolean corrupt=size.equals("small-corrupt");int pieces=0,zero=0;
                while(!done.isDone()) {
                    var outgoing=io.output.poll(100,TimeUnit.MILLISECONDS);
                    if(outgoing==null) { if(System.nanoTime()-began>TimeUnit.SECONDS.toNanos(12))fail("加入が期限を超えました");continue; }
                    try(var fetch=JoinWire.decode(outgoing.wire())) {
                        if(fetch.kind()!=JoinWire.FETCH)continue;
                        if(fetch.index()==0)zero++;
                        byte[] data=JoinWire.data(fetch.invitation(),fetch.transfer(),reply,fetch.index());
                        if(corrupt||size.equals("small-exhaust")&&fetch.index()==0) { data[data.length-1]^=1;corrupt=false; }
                        io.inject(data,SOURCE);Crypto.wipe(data);pieces++;
                    }
                }
                if(size.equals("small-exhaust")) {
                    assertThrows(ExecutionException.class,()->done.get(1,TimeUnit.SECONDS));assertEquals(3,zero);UdpEndpointTest.await(endpoint::isTerminated);
                } else assertNotNull(done.get(1,TimeUnit.SECONDS));
                assertTrue(joiner.isClosed());
                if(size.equals("small-corrupt")) { assertTrue(zero>=2);assertTrue(endpoint.rejectedPackets()>0); }
                if(size.equals("15MiB"))assertTrue(pieces>10000);
                System.out.printf(Locale.ROOT,"join-measure size=%s bytes=%d fragments=%d elapsed_ms=%.1f%n",size,reply.length,pieces,(System.nanoTime()-began)/1_000_000.0);
            }
        } finally { Crypto.wipe(reply); }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void slowProviderDoesNotBlockDtkAndCloseWaitsForItsSecretCleanup(boolean insideCrypto) throws Exception {
        var f=new SessionManagerTest();var join=new JoinHandshakeTest();
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);var io=new MemoryIo();
        var inbox=new LinkedBlockingQueue<byte[]>();var borrowed=new AtomicReference<byte[]>();
        Runnable block=()->{
            entered.countDown();
            try { assertTrue(release.await(5,TimeUnit.SECONDS)); } catch(InterruptedException e) { throw new IllegalStateException(e); }
        };
        try(var a=f.new Node(1);var b=f.new Node(2);var invite=join.invitation();
            var admin=new JoinHandshake.Admin(invite,join.chain().get(0),AdminRecords.signAnchor(join.chain().get(0),join.f.a),join.f.clock,join.tick::get,
                    ignored->{if(insideCrypto)block.run();});var joiner=join.joiner(invite);
            var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,plain)->{if(plain.length>0)inbox.add(plain.clone());},Duration.ofDays(1))) {
            f.connect(a,b);endpoint.setPeerAddress(b.id,OTHER);
            endpoint.registerInvitation(admin,()->{
                if(!insideCrypto)block.run();
                byte[] x=join.adminX.clone();borrowed.set(x);
                return new UdpEndpoint.JoinMaterials(x,join.f.a.clone(),join.material());
            },result->{});
            byte[] request=JoinWire.request(admin.invitationId(),new byte[16],joiner.request());io.prove(request,SOURCE);
            assertTrue(entered.await(5,TimeUnit.SECONDS));
            try {
                // 暗号の核のロックを持つ間にも、重複REQUESTの後のDTKを受けられる。
                io.inject(request,SOURCE);io.inject(f.data(b,a,7),OTHER);assertArrayEquals(new byte[]{7},inbox.poll(2,TimeUnit.SECONDS));
            } catch(Throwable failure) { release.countDown();throw failure; }
            var closed=new CompletableFuture<Void>();var thread=new Thread(()->{endpoint.close();closed.complete(null);});thread.start();
            try { UdpEndpointTest.await(()->io.closed);assertFalse(closed.isDone()); }
            finally { release.countDown(); }
            closed.get(5,TimeUnit.SECONDS);assertTrue(endpoint.isTerminated());SecretAssertions.zero(borrowed.get());
        } finally { release.countDown(); }
    }
    @Test void futureWaiterCanCloseEndpointDuringCallerClose() throws Exception {
        var f=new JoinHandshakeTest();var io=new MemoryIo();
        try(var invitation=f.invitation();var joiner=f.joiner(invitation);var endpoint=new UdpEndpoint(io,(id,plain)->{},System::nanoTime)) {
            var done=endpoint.join(invitation,joiner,joined->null);
            var callback=CompletableFuture.runAsync(()->{
                try{done.get(5,TimeUnit.SECONDS);throw new AssertionError("閉じた加入が成功しました");}
                catch(ExecutionException|CancellationException expected){}
                catch(InterruptedException|TimeoutException error){throw new CompletionException(error);}
                endpoint.close();
            });
            CompletableFuture.runAsync(endpoint::close).get(5,TimeUnit.SECONDS);
            callback.get(5,TimeUnit.SECONDS);assertTrue(endpoint.isTerminated());assertTrue(done.isDone());assertThrows(Exception.class,done::get);
        }
    }
    @Test void endpointWipesFailedIssuanceMaterialsAndThenAcceptsRetry() throws Exception {
        try(var f=new AdminFixture();var admin=f.f.admin(f.invitation)) {
            f.registration.close();var fail=new AtomicBoolean(true);var borrowed=new ArrayList<byte[]>();
            f.endpoint.registerInvitation(admin,()->{
                byte[] x=fail.get()?key(90):f.f.adminX.clone(),s=f.f.f.a.clone();borrowed.add(x);borrowed.add(s);
                return new UdpEndpoint.JoinMaterials(x,s,f.f.material());
            },result->{});
            long rejected=f.endpoint.rejectedPackets();f.begin();UdpEndpointTest.await(()->f.endpoint.rejectedPackets()>rejected);
            // 次の受け付けと0埋めはworkerのfinallyが終わってから確かめる。
            var engine=(JoinPort)SecretAssertions.field(f.endpoint,"joins");
            UdpEndpointTest.await(()->{synchronized(engine){return SecretAssertions.field(engine,"active")==null;}});
            for(byte[] secret:borrowed)SecretAssertions.zero(secret);assertFalse(admin.isConsumed());assertTrue(f.io.output.isEmpty());
            fail.set(false);f.begin();assertEquals(JoinWire.READY,JoinWire.decode(f.io.take().wire()).kind());assertTrue(admin.isConsumed());
            for(byte[] secret:borrowed)SecretAssertions.zero(secret);
        }
    }
    @Test void invalidProviderMaterialsWipeAllTransferredSecrets() throws Exception {
        var f=new JoinHandshakeTest();byte[] owned=key(1);var material=f.material();
        assertThrows(IllegalArgumentException.class,()->new UdpEndpoint.JoinMaterials(owned,null,material));
        SecretAssertions.zero(owned);SecretAssertions.zero(SecretAssertions.bytes(material,"groupKey"));
    }
}
