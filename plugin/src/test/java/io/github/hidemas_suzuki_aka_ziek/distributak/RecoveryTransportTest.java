// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.time.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RecoveryTransportTest {
    static final class Time extends Clock {
        long now;
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(now);}
        public long millis(){return now;}
    }
    static final class Wire implements RevocationRecovery.Transport {
        final List<byte[]> sent=new ArrayList<>();int starts;
        final List<ManagementPageSender.Offer> rejected=new ArrayList<>();
        public boolean send(byte[] peer,byte[] session,byte[] wire){sent.add(wire.clone());return true;}
        public void start(byte[] peer){starts++;}
        public void rejected(ManagementPageSender.Offer result){rejected.add(result);}
    }
    static final class Pair implements AutoCloseable {
        final Time time=new Time();final Wire requestWire=new Wire(),responseWire=new Wire();
        final LanGroup a,b;final SessionManager sa,sb;final CorePersistenceCoordinator ca,cb;
        final RevocationRecovery receiver,responder;final byte[] subject=StoredUpdatesTest.key(81);
        int saves;Runnable duringSave=()->{};
        Pair()throws Exception{this(true);}
        Pair(boolean recovering)throws Exception{
            a=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());
            b=LanGroup.decode(a.encode(),StorageGroupTest.CLOCK,true);
            Crypto.wipe(b.identitySecret);Crypto.wipe(b.handshakeSecret);Crypto.wipe(b.administratorSecret);
            b.identitySecret=StoredUpdatesTest.key(71);b.handshakeSecret=StoredUpdatesTest.key(72);b.administratorSecret=new byte[0];
            b.certificate=StoredUpdatesTest.peer(a,71,72,StorageGroupTest.NOW);
            a.peerCertificate=b.certificate;b.peerCertificate=a.certificate;
            a.peerAddress=b.peerAddress=new java.net.InetSocketAddress(java.net.InetAddress.getByAddress(new byte[]{(byte)192,0,2,1}),54322);
            if(recovering){a.recoveryRequirement=CorePersistenceCoordinator.RecoveryRequirement.candidateLess(2,List.of(subject));a.storageBlocked=true;}
            sa=a.sessions(StorageGroupTest.CLOCK,()->time.now*1_000_000);sb=b.sessions(StorageGroupTest.CLOCK,()->time.now*1_000_000);
            ca=new CorePersistenceCoordinator(a.state,sa,new RevocationUnion(a.groupId,new AdminStateTrust(a.state)),StorageGroupTest.CLOCK,time,a.recoveryRequirement);
            cb=new CorePersistenceCoordinator(b.state,sb,new RevocationUnion(b.groupId,new AdminStateTrust(b.state)),StorageGroupTest.CLOCK,time);
            var second=sb.receive(sa.start(b.id()).packet());var confirm=sa.receive(second.outbound().get(0).packet());sb.receive(confirm.outbound().get(0).packet());
            receiver=new RevocationRecovery(a,sa,ca,time,new java.security.SecureRandom(),requestWire,new CorePersistenceCoordinator.PersistenceHooks(){public void save(AdminRecordStore.Snapshot s){saves++;duringSave.run();}});
            responder=new RevocationRecovery(b,sb,cb,time,new java.security.SecureRandom(),responseWire,null);
        }
        AdminRecords.Record body(long version,List<byte[]> subjects){return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,a.groupId,version,StorageGroupTest.NOW,subjects,a.administratorSecret);}
        byte[] request(){receiver.poll(List.of(b.id()));return requestWire.sent.get(requestWire.sent.size()-1);}
        void deliver(AdminRecords.Record body){
            var request=RevocationsRecoveryRequest.decodeEnvelope(request());
            for(var page:ManagementPage.split(ManagementPage.Kind.REVOCATION,request.operationId(),a.groupId,body.encode(),body.entries().size()))
                assertTrue(receiver.receive(b.id(),sa.sessionId(b.id()),page.envelope()));
        }
        public void close(){receiver.close();responder.close();sa.close();sb.close();a.close();b.close();}
    }
    @Test public void ordinaryMemberReturnsOriginalAdministratorSignedBytes()throws Exception{
        try(var p=new Pair()){
            var body=p.body(2,List.of(p.subject));p.b.state.acceptRevocations(body);
            assertTrue(p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),p.request()));assertEquals(1,p.responseWire.sent.size());
            assertArrayEquals(body.encode(),ManagementPage.decodeEnvelope(p.responseWire.sent.get(0)).data());assertFalse(p.b.isAdministrator());
            p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),p.responseWire.sent.get(0));
            assertEquals(1,p.saves);assertEquals(CorePersistenceCoordinator.State.RUNNING,p.ca.state());
            assertTrue(ManagementPageAck.decodeEnvelope(p.requestWire.sent.get(p.requestWire.sent.size()-1)).complete());
        }
    }
    @Test public void lowerVersionCannotClearStop()throws Exception{
        try(var p=new Pair()){p.deliver(p.body(1,List.of(p.subject)));assertEquals(0,p.saves);assertEquals(CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,p.ca.state());}
    }
    @Test public void replyRefusalIsReportedWithoutRestartingCurrentTransmission()throws Exception{
        try(var p=new Pair()){
            p.b.state.acceptRevocations(p.body(2,List.of(p.subject)));byte[] request=p.request();
            p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),request);
            p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),request);
            assertEquals(List.of(ManagementPageSender.Offer.PEER_BUSY),p.responseWire.rejected);
            assertEquals(1,p.responseWire.sent.size());
        }
    }
    @Test public void missingSavedSubjectCannotClearStop()throws Exception{
        try(var p=new Pair()){p.deliver(p.body(2,List.of()));assertEquals(0,p.saves);assertEquals(CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,p.ca.state());}
    }
    @Test public void unauthorizedInnerSignerCannotClearStop()throws Exception{
        try(var p=new Pair()){
            p.deliver(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,2,StorageGroupTest.NOW,List.of(p.subject),StoredUpdatesTest.key(83)));
            assertEquals(0,p.saves);assertEquals(CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,p.ca.state());
        }
    }
    @Test public void successfulRecoveryRequiresSavedUnionEvenWhenNewListHasHigherVersion()throws Exception{
        try(var p=new Pair()){p.deliver(p.body(3,List.of(p.subject,StoredUpdatesTest.key(82))));assertEquals(1,p.saves);assertEquals(2,p.a.state.revokedSubjects().size());}
    }
    @Test public void unboundSessionCannotTriggerResponse()throws Exception{
        try(var p=new Pair()){assertFalse(p.responder.receive(p.a.id(),new byte[16],p.request()));assertTrue(p.responseWire.sent.isEmpty());}
    }
    @Test public void anotherOperationCannotCompleteBoundRecovery()throws Exception{
        try(var p=new Pair()){
            var r=RevocationsRecoveryRequest.decodeEnvelope(p.request());byte[] op=r.operationId();op[0]^=1;
            var body=p.body(2,List.of(p.subject));var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,op,p.a.groupId,body.encode(),1).get(0);
            p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope());assertEquals(0,p.saves);
        }
    }
    @Test public void requestRetriesKeepOriginalOperationAndStopAtFour()throws Exception{
        try(var p=new Pair()){
            byte[] first=p.request();for(int i=1;i<=5;i++){p.time.now=i*1000;p.receiver.poll(List.of(p.b.id()));}
            assertEquals(4,p.requestWire.sent.size());for(byte[] wire:p.requestWire.sent)assertArrayEquals(first,wire);
        }
    }
    @Test public void replacedSessionCanReplyWithinFourNewRequests()throws Exception{
        try(var p=new Pair()){
            p.time.now=5000;p.b.state.acceptRevocations(p.body(2,List.of(p.subject)));
            byte[] firstRequest=p.request();
            p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),firstRequest);
            byte[] oldSession=p.sa.sessionId(p.b.id());
            var second=p.sb.receive(p.sa.start(p.b.id()).packet());
            var confirm=p.sa.receive(second.outbound().get(0).packet());p.sb.receive(confirm.outbound().get(0).packet());
            assertFalse(Arrays.equals(oldSession,p.sa.sessionId(p.b.id())));
            byte[] operation=null;
            for(int i=0;i<4;i++){
                p.time.now=5000+i*1000;p.receiver.poll(List.of(p.b.id()));
                byte[] request=p.requestWire.sent.get(p.requestWire.sent.size()-1);
                var decoded=RevocationsRecoveryRequest.decodeEnvelope(request);
                if(operation==null){operation=decoded.operationId();assertFalse(Arrays.equals(operation,RevocationsRecoveryRequest.decodeEnvelope(firstRequest).operationId()));}
                else assertArrayEquals(operation,decoded.operationId());
                p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),request);p.responder.poll(List.of());
            }
            int delivered=0;
            for(byte[] wire:p.responseWire.sent)if(Arrays.equals(operation,ManagementPage.decodeEnvelope(wire).operationId())){
                if(delivered++==0)p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),wire);
            }
            assertTrue("replacement session received no reply",delivered>0);
            assertEquals(1,p.saves);assertEquals(CorePersistenceCoordinator.State.RUNNING,p.ca.state());
            assertEquals(5,p.requestWire.sent.stream().filter(w->{try{RevocationsRecoveryRequest.decodeEnvelope(w);return true;}catch(IllegalArgumentException invalid){return false;}}).count());
        }
    }
    @Test public void candidateWithoutSessionTimesOutWithoutRestartingGlobalDeadline()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            var clock=new Time();var wire=new Wire();
            var c=new CorePersistenceCoordinator(g.state,sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),StorageGroupTest.CLOCK,clock,
                    new CorePersistenceCoordinator.RecoveryRequirement(1,CorePersistenceCoordinator.revocationDigest(List.of()),List.of()));
            var recovery=new RevocationRecovery(g,sessions,c,clock,new java.security.SecureRandom(),wire,new CorePersistenceCoordinator.PersistenceHooks(){public void save(AdminRecordStore.Snapshot s){fail();}});
            recovery.poll(List.of(StoredUpdatesTest.key(81),StoredUpdatesTest.key(82)));assertEquals(1,wire.starts);
            clock.now=30_000;recovery.poll(List.of(StoredUpdatesTest.key(81),StoredUpdatesTest.key(82)));assertEquals(2,wire.starts);
            clock.now=60_000;recovery.poll(List.of(StoredUpdatesTest.key(81),StoredUpdatesTest.key(82)));assertEquals(2,wire.starts);
            clock.now=240_000;recovery.poll(List.of(StoredUpdatesTest.key(81),StoredUpdatesTest.key(82)));assertFalse(c.permits(CorePersistenceCoordinator.Operation.HANDSHAKE));
            assertEquals("保存がいっぱい",c.statusText());assertTrue(wire.sent.isEmpty());
        }
    }
    @Test public void noCandidatesNeverGeneratesNormalTraffic()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            var time=new Time();var wire=new Wire();var c=new CorePersistenceCoordinator(g.state,sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),StorageGroupTest.CLOCK,time,
                    CorePersistenceCoordinator.RecoveryRequirement.candidateLess(1,List.of()));
            var r=new RevocationRecovery(g,sessions,c,time,new java.security.SecureRandom(),wire,new CorePersistenceCoordinator.PersistenceHooks(){public void save(AdminRecordStore.Snapshot s){fail();}});
            r.poll(List.of());assertEquals(0,wire.starts);assertTrue(wire.sent.isEmpty());assertEquals("保存がいっぱい",c.statusText());
        }
    }
}
