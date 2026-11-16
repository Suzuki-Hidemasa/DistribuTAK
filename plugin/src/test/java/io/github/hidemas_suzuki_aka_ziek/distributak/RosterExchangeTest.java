// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import java.time.*;
import java.security.SecureRandom;
import org.junit.Test;
import static org.junit.Assert.*;

public class RosterExchangeTest {
    static final class Frame {
        final boolean toB;final byte[] wire;
        Frame(boolean toB,byte[] wire){this.toB=toB;this.wire=wire.clone();}
    }
    static final class Pair implements AutoCloseable {
        final LanGroup a,b;
        final SessionManager sa,sb;
        final CorePersistenceCoordinator ca,cb;
        final LanControllerHarness.Disk da=new LanControllerHarness.Disk(54321),db=new LanControllerHarness.Disk(54322);
        final RevocationRecovery ra,rb;
        final RosterExchange xa,xb;
        final ArrayDeque<Frame> frames=new ArrayDeque<>();
        final Map<String,Integer> sendCounts=new HashMap<>();
        long now,wallAdvance;
        final Clock wall=new Clock(){
            public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}
            public Instant instant(){return Instant.ofEpochMilli(StorageGroupTest.NOW+wallAdvance);}
        };
        final Clock deadlines=new Clock(){
            public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}
            public Instant instant(){return Instant.ofEpochMilli(now);}
        };
        Pair()throws Exception{this(false);}
        Pair(boolean fixedSessionClock)throws Exception{
            a=LanGroup.create(54321,wall,new SecureRandom());b=LanGroup.decode(a.encode(),wall,true);
            b.identitySecret=StoredUpdatesTest.key(120);b.handshakeSecret=StoredUpdatesTest.key(121);b.administratorSecret=StoredUpdatesTest.key(122);
            b.certificate=StoredUpdatesTest.peer(a,120,121,StorageGroupTest.NOW);
            var bindings=new ArrayList<AdminBinding>();
            for(var g:List.of(a,b)){
                var proof=AdminControl.keyProof(a.groupId,new byte[16],0,g.identitySecret,g.administratorSecret);
                bindings.add(AdminBinding.bound(proof.administratorKey(),g.id(),proof.encode()));
            }
            var list=AdminRecords.administrators(a.groupId,1,StorageGroupTest.NOW,bindings,a.administratorSecret);
            a.state.acceptAdministrators(list,v->fail());b.state.acceptAdministrators(list,v->fail());
            da.enableSix();db.enableSix();da.save(a);db.save(b);
            sa=a.sessions(wall,()->fixedSessionClock?0:now*1000000);sb=b.sessions(wall,()->fixedSessionClock?0:now*1000000);
            sa.rememberPeer(b.certificate);sb.rememberPeer(a.certificate);
            var second=sb.receive(sa.start(b.id()).packet());var third=sa.receive(second.outbound().get(0).packet());sb.receive(third.outbound().get(0).packet());
            ca=new CorePersistenceCoordinator(a.state,sa,new RevocationUnion(a.groupId,new AdminStateTrust(a.state)),wall,deadlines);
            cb=new CorePersistenceCoordinator(b.state,sb,new RevocationUnion(b.groupId,new AdminStateTrust(b.state)),wall,deadlines);
            ra=recovery(a,sa,ca,da,true);rb=recovery(b,sb,cb,db,false);
            xa=new RosterExchange(a,sa,ca,deadlines,da,ra);xb=new RosterExchange(b,sb,cb,deadlines,db,rb);
        }
        RevocationRecovery recovery(LanGroup g,SessionManager s,CorePersistenceCoordinator c,LanControllerHarness.Disk d,boolean toB){
            return new RevocationRecovery(g,s,c,deadlines,new SecureRandom(){public void nextBytes(byte[] value){Arrays.fill(value,(byte)0);}},new RevocationRecovery.Transport(){
                public boolean send(byte[] peer,byte[] session,byte[] wire){int count=sendCounts.merge(toB+":"+(now/1000),1,Integer::sum);assertTrue(count<=4);frames.add(new Frame(toB,wire));return true;}
                public void start(byte[] peer){}public void rejected(ManagementPageSender.Offer result){fail();}
            },d.persistenceHooks(g));
        }
        void step(){
            xa.poll(List.of(b.id()));xb.poll(List.of(a.id()));ra.poll(List.of());rb.poll(List.of());
            int count=frames.size();
            for(int i=0;i<count;i++){
                var frame=frames.remove();var g=frame.toB?a:b;var s=frame.toB?sb:sa;var x=frame.toB?xb:xa;var r=frame.toB?rb:ra;
                if(!x.receive(g.id(),s.sessionId(g.id()),frame.wire,now))r.receive(g.id(),s.sessionId(g.id()),frame.wire,now);
            }
            now+=100;
        }
        public void close(){ra.close();rb.close();sa.close();sb.close();a.close();b.close();}
    }
    @Test public void administratorsPullOnlyMissingCertificatesAndPersistWithoutChangingRevocationsOrCheckpoint()throws Exception{
        try(var p=new Pair()){
            byte[] revoked=StoredUpdatesTest.key(250);
            for(var g:List.of(p.a,p.b)){
                var coordinator=g==p.a?p.ca:p.cb;var disk=g==p.a?p.da:p.db;
                assertTrue(coordinator.receiveRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(revoked),g.administratorSecret),disk.persistenceHooks(g)));
                assertTrue(coordinator.receiveRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,2,StorageGroupTest.NOW,List.of(),g.administratorSecret),disk.persistenceHooks(g)));
            }
            var da=new MemberDirectory(p.a.state);var db=new MemberDirectory(p.b.state);
            for(int n=1;n<=70;n++)(n%2==0?da:db).saved(StoredUpdatesTest.peer(p.a,n,n+100,StorageGroupTest.NOW));
            p.da.saveDirectory(p.a,da,Map.of());p.db.saveDirectory(p.b,db,Map.of());
            p.xa.reload();p.xb.reload();
            long checkpoint=p.a.management.checkpoint.number;byte[] revocations=p.a.state.revocations().encode(),marker=p.da.stopMarker.bytes.clone();
            for(int i=0;i<500&&(p.xa.directory().size()<70||p.xb.directory().size()<70);i++)p.step();
            assertEquals(70,p.xa.directory().size());assertEquals(70,p.xb.directory().size());
            assertEquals(checkpoint,p.a.management.checkpoint.number);assertArrayEquals(revocations,p.a.state.revocations().encode());assertArrayEquals(marker,p.da.stopMarker.bytes);
            assertEquals(1,p.a.state.revokedSubjects().size());assertArrayEquals(revoked,p.a.state.revokedSubjects().get(0));
            assertEquals(1,p.a.management.union.size());assertArrayEquals(revoked,p.a.management.union.get(0));
            try(var loaded=p.da.load(StorageGroupTest.CLOCK)){
                assertEquals(70,loaded.management.roster.size());assertFalse(loaded.storageBlocked);
                assertEquals(1,loaded.state.revokedSubjects().size());assertArrayEquals(revoked,loaded.state.revokedSubjects().get(0));
                assertEquals(checkpoint,loaded.management.checkpoint.number);assertArrayEquals(revocations,loaded.state.revocations().encode());
            }
        }
    }
    @Test public void unsolicitedRosterDoesNotSaveOrAcknowledge()throws Exception{
        try(var p=new Pair()){
            var batch=new RosterMessage.Batch(List.of(p.b.certificate),true);long before=p.a.saveSeq;
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER,new byte[16],p.a.groupId,batch.encode(),1).get(0);
            assertTrue(p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),0));
            assertTrue(p.frames.isEmpty());assertEquals(before,p.a.saveSeq);assertEquals(1,p.xa.directory().size());
        }
    }
    static ManagementPage request(Pair p){
        p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());
        var frame=p.frames.stream().filter(f->f.toB&&ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.DIRECTORY_SUMMARY_PAGE).findFirst().orElseThrow();
        var page=ManagementPage.decodeEnvelope(frame.wire);p.frames.clear();
        var ack=new ManagementPageAck(p.a.groupId,page.operationId(),page.objectDigest(),new int[]{0},true);
        p.ra.receive(p.b.id(),p.sa.sessionId(p.b.id()),ack.envelope(),p.now);return page;
    }
    static ManagementPage response(Pair p,ManagementPage request,RosterMessage.Batch batch){
        return ManagementPage.split(ManagementPage.Kind.ROSTER,request.operationId(),p.a.groupId,batch.encode(),batch.certificates().size()).get(0);
    }
    @Test public void responseIsBoundToOperationIntervalAndSingleOutstandingRequest()throws Exception{
        try(var p=new Pair()){
            var request=request(p);var batch=new RosterMessage.Batch(List.of(p.b.certificate),true);var page=response(p,request,batch);
            byte[] wrong=request.operationId();wrong[0]^=1;
            var other=ManagementPage.split(ManagementPage.Kind.ROSTER,wrong,p.a.groupId,batch.encode(),1).get(0);
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),other.envelope(),p.now);assertEquals(1,p.xa.directory().size());assertTrue(p.frames.isEmpty());
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertEquals(2,p.xa.directory().size());assertEquals(1,p.frames.size());
            p.frames.clear();p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertEquals(1,p.frames.size());
            assertTrue(ManagementPageAck.decodeEnvelope(p.frames.peek().wire).complete());
        }
    }
    @Test public void expiredRequestAndChangedSessionDoNotAcceptResponse()throws Exception{
        for(boolean expired:new boolean[]{false,true})try(var p=new Pair()){
            var request=request(p);var page=response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            if(expired)p.now+=30000;else p.sa.close();
            p.xa.receive(p.b.id(),p.sb.sessionId(p.a.id()),page.envelope(),p.now);assertEquals(1,p.xa.directory().size());assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void threeInvalidBatchesStopFurtherRequestsWithoutSaveOrAck()throws Exception{
        try(var p=new Pair()){
            byte[] broken=p.b.certificate.encode();broken[broken.length-1]^=1;var invalid=AdminRecords.decode(broken);
            for(int n=0;n<3;n++){
                var request=request(p);var page=response(p,request,new RosterMessage.Batch(List.of(invalid),true));
                p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertTrue(p.frames.isEmpty());
            }
            p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());assertTrue(p.frames.isEmpty());assertEquals(1,p.xa.directory().size());
        }
    }
    @Test public void authenticatedFirstPersistsOnlyAfterValidationAndFailureStopsTraffic()throws Exception{
        for(boolean fail:new boolean[]{false,true})try(var p=new Pair()){
            p.db.managementFiles.fail=fail;p.xb.registerFirst(p.a.id());
            if(fail){assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,p.cb.state());assertTrue(p.b.storageBlocked);assertEquals(1,p.xb.directory().size());}
            else try(var loaded=p.db.load(StorageGroupTest.CLOCK)){assertEquals(2,loaded.management.roster.size());assertEquals(2,p.xb.directory().size());}
        }
    }

    @Test public void responseOutsideRequestedIntervalIsRejectedWithoutAckOrCursorAdvance()throws Exception{
        try(var p=new Pair()){
            for(int n=1;n<=65;n++)p.xa.directory().saved(StoredUpdatesTest.peer(p.a,n,n+100,StorageGroupTest.NOW));
            var request=request(p);var summary=RosterMessage.summarize(p.xa.directory(),new byte[0]);assertTrue(summary.more());
            byte[] high=summary.entries().get(31).memberId();AdminRecords.Record outside=null;
            for(int n=66;n<240;n++){
                var candidate=StoredUpdatesTest.peer(p.a,n,n+100,StorageGroupTest.NOW);
                if(AdminRecords.compareBytes(Crypto.blake2s(candidate.field(0)),high)>0){outside=candidate;break;}
            }
            assertNotNull(outside);int count=p.xa.directory().size();
            var page=response(p,request,new RosterMessage.Batch(List.of(outside),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertEquals(count,p.xa.directory().size());assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void currentSessionWithoutAdministratorBindingCannotExchangeRoster()throws Exception{
        try(var p=new Pair()){
            var binding=p.a.state.administrators().bindings().stream().filter(b->Crypto.equal(b.memberId(),p.a.id())).findFirst().orElseThrow();
            p.a.state.acceptAdministrators(AdminRecords.administrators(p.a.groupId,2,StorageGroupTest.NOW,List.of(binding),p.a.administratorSecret),v->fail());
            var summary=RosterMessage.summarize(p.xb.directory(),new byte[0]);
            var page=ManagementPage.split(ManagementPage.Kind.ROSTER_SUMMARY,new byte[16],p.a.groupId,summary.encode(),summary.entries().size()).get(0);
            long before=p.a.saveSeq;p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertEquals(before,p.a.saveSeq);assertTrue(p.frames.isEmpty());
        }
    }

    @Test public void sameQuotedOperationAcrossKindsKeepsSenderAckAndCompletionRecordsSeparate()throws Exception{
        try(var p=new Pair()){
            for(int n=0;n<200&&(p.xa.directory().size()<2||p.xb.directory().size()<2);n++)p.step();
            assertEquals(2,p.xa.directory().size());assertEquals(2,p.xb.directory().size());
        }
    }
    @Test public void rosterSaveFailureNeverPublishesOrQueuesCompletionAck()throws Exception{
        for(boolean managementFile:new boolean[]{false,true})try(var p=new Pair()){
            var request=request(p);
            if(managementFile)p.da.managementFiles.fail=true;else p.da.failSave=true;
            var page=response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,p.ca.state());assertTrue(p.frames.isEmpty());assertEquals(1,p.xa.directory().size());
        }
    }

    @Test public void certificateExpiringDuringCommitIsNotPublishedOrAcknowledged()throws Exception{
        try(var p=new Pair()){
            var request=request(p);
            var certificate=StoredUpdatesTest.peer(p.a,90,91,StorageGroupTest.NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS+1);
            var page=response(p,request,new RosterMessage.Batch(List.of(certificate),true));
            p.da.afterDirectory=()->p.wallAdvance=2;
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertEquals(1,p.xa.directory().size());assertTrue(p.frames.isEmpty());
            assertEquals(CorePersistenceCoordinator.State.RUNNING,p.ca.state());
        }
    }

}
