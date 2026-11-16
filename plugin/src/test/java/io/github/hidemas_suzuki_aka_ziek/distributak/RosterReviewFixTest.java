// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RosterReviewFixTest {
    static void settle(RosterExchangeTest.Pair p){for(int i=0;i<300;i++)p.step();}
    static void summary(RosterExchangeTest.Pair p,MemberDirectory directory){
        var value=RosterMessage.summarize(directory,new byte[0]);
        summary(p,value);
    }
    static void summary(RosterExchangeTest.Pair p,RosterMessage.Summary value){
        byte[] operation=new byte[16];operation[0]=99;
        var page=ManagementPage.split(ManagementPage.Kind.ROSTER_SUMMARY,operation,p.a.groupId,value.encode(),value.entries().size()).get(0);
        p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
    }
    static boolean hasRequest(RosterExchangeTest.Pair p){
        return p.frames.stream().anyMatch(f->f.toB&&ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.DIRECTORY_SUMMARY_PAGE);
    }
    @Test public void remoteOnlyAdditionAfterCompletionStartsAnotherPull()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            settle(p);var fresh=StoredUpdatesTest.peer(p.a,94,95,StorageGroupTest.NOW);
            p.xb.directory().saved(fresh);p.db.saveDirectory(p.b,p.xb.directory(),Map.of());
            for(int i=0;i<1200;i++)p.step();
            assertNotNull(p.xa.directory().get(Crypto.blake2s(fresh.field(0))));
        }
    }
    @Test public void remoteOnlyNewerCertificateAfterCompletionStartsAnotherPull()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            settle(p);p.wallAdvance=1;
            var old=p.b.certificate;
            var fresh=AdminRecords.certificate(p.b.groupId,old.field(0),old.field(1),old.field(2),StorageGroupTest.NOW+1,p.b.administratorSecret);
            p.xb.directory().saved(fresh);p.db.saveDirectory(p.b,p.xb.directory(),Map.of());
            for(int i=0;i<1200;i++)p.step();
            assertEquals(fresh.issuedAt(),p.xa.directory().get(p.b.id()).certificate().issuedAt());
        }
    }
    @Test public void sameTimestampConflictDoesNotRestartCompletedPull()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            settle(p);var original=RosterMessage.summarize(p.xb.directory(),new byte[0]);
            var entries=new ArrayList<MemberDirectory.Summary>();
            for(var entry:original.entries()){byte[] digest=entry.digest();digest[0]^=1;entries.add(new MemberDirectory.Summary(entry.memberId(),entry.issuedAt(),digest));}
            var other=new RosterMessage.Summary(original.total(),original.digest(),original.after(),entries,original.more());
            p.frames.clear();summary(p,other);p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());
            assertFalse(hasRequest(p));assertTrue(p.xa.conflicts()>0);
        }
    }
    @Test public void summaryDoesNotRestartPeerAfterThreeFailures()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            byte[] broken=p.b.certificate.encode();broken[broken.length-1]^=1;
            for(int n=0;n<3;n++){
                var request=RosterExchangeTest.request(p);
                var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(AdminRecords.decode(broken)),true));
                p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            }
            p.frames.clear();summary(p,p.xb.directory());p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());
            assertFalse(hasRequest(p));
        }
    }
    @Test public void expiredStoredEvidenceDoesNotPreventValidCertificateTransfer()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var expired=StoredUpdatesTest.peer(p.a,90,91,StorageGroupTest.NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS);
            var valid=StoredUpdatesTest.peer(p.a,92,93,StorageGroupTest.NOW);
            p.xb.directory().saved(expired);p.xb.directory().saved(valid);
            p.db.saveDirectory(p.b,p.xb.directory(),Map.of());
            for(int i=0;i<1200;i++)p.step();
            assertNotNull(p.xa.directory().get(Crypto.blake2s(valid.field(0))));
            assertNull(p.xa.directory().get(Crypto.blake2s(expired.field(0))));
            assertNotNull(p.xb.directory().get(Crypto.blake2s(expired.field(0))));
        }
    }
    @Test public void summaryAndResponseUseSameFilteredSetAcrossIntervalsAndShortcut()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var all=new MemberDirectory(p.a.state);var filtered=new MemberDirectory(p.a.state);
            var revoked=StoredUpdatesTest.peer(p.a,95,96,StorageGroupTest.NOW);
            all.saved(revoked);
            for(int n=1;n<=65;n++){
                var certificate=StoredUpdatesTest.peer(p.a,n,n+100,StorageGroupTest.NOW);
                all.saved(certificate);filtered.saved(certificate);
            }
            all.saved(StoredUpdatesTest.peer(p.a,90,91,StorageGroupTest.NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS));
            assertTrue(p.ca.receiveRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,1,StorageGroupTest.NOW,List.of(Crypto.blake2s(revoked.field(0))),p.a.administratorSecret),p.da.persistenceHooks(p.a)));
            byte[] after=new byte[0];int count=0;
            do{
                var actual=RosterMessage.summarize(all,after);var expected=RosterMessage.summarize(filtered,after);
                assertArrayEquals(expected.encode(),actual.encode());
                assertTrue(RosterMessage.respond(all,expected).certificates().isEmpty());
                assertTrue(RosterMessage.respond(all,expected).intervalDone());
                count+=actual.entries().size();if(!actual.more())break;
                after=actual.entries().get(actual.entries().size()-1).memberId();
            }while(true);
            assertEquals(65,count);assertEquals(67,all.size());
        }
    }
    @Test public void rosterSavePreservesCertificateRenewedThroughAnotherPath()throws Exception{
        for(boolean beforeRequest:new boolean[]{false,true})try(var p=new RosterExchangeTest.Pair()){
            var old=p.a.certificate;p.wallAdvance=1;
            var renewed=AdminRecords.certificate(p.a.groupId,old.field(0),old.field(1),old.field(2),StorageGroupTest.NOW+1,p.a.administratorSecret);
            ManagementPage request=null;if(!beforeRequest)request=RosterExchangeTest.request(p);
            p.da.saveLocalRenewal(p.a,renewed);
            if(beforeRequest)request=RosterExchangeTest.request(p);
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            var saved=new MemberDirectory(p.a.state);saved.restoreSnapshot(p.a.management.roster);
            assertEquals(renewed.issuedAt(),saved.get(p.a.id()).issuedAt());
            assertEquals(renewed.issuedAt(),p.xa.directory().get(p.a.id()).issuedAt());
        }
    }
    @Test public void exactCompletedResponseReplayAcknowledgesWithoutAnotherSave()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            int saves=p.da.directorySaves;long revision=p.xa.directory().revision();
            p.frames.clear();p.now+=1000;
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertEquals(1,p.frames.size());assertTrue(ManagementPageAck.decodeEnvelope(p.frames.peek().wire).complete());
            assertEquals(saves,p.da.directorySaves);assertEquals(revision,p.xa.directory().revision());
            p.frames.clear();byte[] altered=page.data();altered[altered.length-1]^=1;
            var changed=new ManagementPage(page.kind(),page.operationId(),page.group(),page.objectDigest(),page.totalBytes(),page.pageIndex(),page.pageCount(),altered,page.totalEntries());
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),changed.envelope(),p.now);assertTrue(p.frames.isEmpty());
            p.now+=240000;p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void equalResponseFromAnotherPathCompletesWithoutSaveOrFailure()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);
            p.xa.directory().saved(p.b.certificate);p.da.saveDirectory(p.a,p.xa.directory(),Map.of());
            int saves=p.da.directorySaves;
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertEquals(saves,p.da.directorySaves);assertEquals(1,p.frames.size());
            assertTrue(ManagementPageAck.decodeEnvelope(p.frames.peek().wire).complete());
        }
    }
    @Test public void busyResponseOfferDoesNotConfirmSummaryAndRetransmissionRetries()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var batch=new RosterMessage.Batch(List.of(),true);byte[] operation=new byte[16];operation[0]=7;
            assertEquals(ManagementPageSender.Offer.ACCEPTED,p.ra.offerRoster(p.b.id(),ManagementPage.Kind.ROSTER,operation,batch.encode(),0));
            summary(p,p.xb.directory());assertTrue(p.frames.isEmpty());
            p.ra.poll(List.of());
            var frame=p.frames.remove();var sent=ManagementPage.decodeEnvelope(frame.wire);
            p.ra.receive(p.b.id(),p.sa.sessionId(p.b.id()),new ManagementPageAck(p.a.groupId,sent.operationId(),sent.objectDigest(),new int[]{0},true).envelope(),p.now);
            p.frames.clear();p.now+=1000;summary(p,p.xb.directory());
            assertEquals(1,p.frames.size());assertTrue(ManagementPageAck.decodeEnvelope(p.frames.peek().wire).complete());
            p.ra.poll(List.of());
            assertTrue(p.frames.stream().anyMatch(f->ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.DIRECTORY_PAGE));
        }
    }
    static void fillAckBudget(RosterExchangeTest.Pair p){
        var ack=new ManagementPageAck(p.a.groupId,new byte[16],new byte[32],new int[]{0},false);
        while(p.ra.rosterAck(p.b.id(),p.sa.sessionId(p.b.id()),ack)){}
        p.frames.clear();
    }
    static void incompleteSummary(RosterExchangeTest.Pair p){
        var entries=new ArrayList<MemberDirectory.Summary>();
        for(int i=0;i<32;i++)entries.add(new MemberDirectory.Summary(StoredUpdatesTest.key(i),StorageGroupTest.NOW,new byte[32]));
        var summary=new RosterMessage.Summary(32,new byte[32],new byte[0],entries);
        byte[] operation=new byte[16];operation[0]=98;
        var pages=ManagementPage.split(ManagementPage.Kind.ROSTER_SUMMARY,operation,p.a.groupId,summary.encode(),32);
        assertTrue(pages.size()>1);
        p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),pages.get(0).envelope(),p.now);
    }
    @Test public void completionAckBlockedByIncompleteTargetRetriesOnNextPollAndAdvances()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);fillAckBudget(p);incompleteSummary(p);
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),false));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertTrue(p.frames.isEmpty());
            p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());
            assertTrue(p.frames.stream().filter(f->ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.PAGE_ACK)
                    .map(f->ManagementPageAck.decodeEnvelope(f.wire)).anyMatch(ManagementPageAck::complete));
            assertTrue(hasRequest(p));
        }
    }
    @Test public void deferredCompletionAckDoesNotRetryAfterOriginalDeadline()throws Exception{
        for(long elapsed:new long[]{30000,240000})try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);fillAckBudget(p);incompleteSummary(p);
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),false));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            p.now+=elapsed;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());
            assertFalse(p.frames.stream().filter(f->ManagementEnvelopeFields.field(f.wire)==ManagementEnvelopeFields.PAGE_ACK)
                    .map(f->ManagementPageAck.decodeEnvelope(f.wire)).anyMatch(ManagementPageAck::complete));
        }
    }
    @Test public void unchangedSavedRosterDoesNotReloadOrResaveAuthenticatedFirst()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            p.xb.registerFirst(p.a.id());int saves=p.db.directorySaves;long revision=p.xb.directory().revision();
            for(int i=0;i<100;i++){p.xb.reload();p.xb.registerFirst(p.a.id());}
            assertEquals(saves,p.db.directorySaves);assertEquals(revision,p.xb.directory().revision());
        }
    }
    @Test public void interleavedSummaryDoesNotExtendReplayAckPastOriginalAssemblyDeadline()throws Exception{
        try(var p=new RosterExchangeTest.Pair(true)){
            var request=RosterExchangeTest.request(p);
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            p.now=239000;summary(p,p.xb.directory());p.frames.clear();
            p.now=240999;fillAckBudget(p);
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);assertTrue(p.frames.isEmpty());
            p.now=241999;p.xa.poll(List.of(p.b.id()));assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void summaryDoesNotCreateSecondOutstandingRequest()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            RosterExchangeTest.request(p);summary(p,p.xb.directory());p.frames.clear();
            p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());assertFalse(hasRequest(p));
        }
    }
    @Test public void rosterChangedDuringSavePreventsStalePublicationAndAck()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);var fresh=StoredUpdatesTest.peer(p.a,94,95,StorageGroupTest.NOW);
            p.da.afterDirectory=()->{
                var changed=new MemberDirectory(p.a.state);changed.restoreSnapshot(p.a.management.roster);changed.saved(fresh);
                p.a.management=p.a.management.directory(changed,Map.of());
            };
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertTrue(p.frames.isEmpty());assertNull(p.xa.directory().get(p.b.id()));
            p.xa.reload();assertNotNull(p.xa.directory().get(Crypto.blake2s(fresh.field(0))));
        }
    }
    @Test public void deferredCompletionIsDiscardedOnCloseSessionLossOrAuthorityLoss()throws Exception{
        for(int reason=0;reason<3;reason++)try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);fillAckBudget(p);incompleteSummary(p);
            var page=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),false));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertEquals(1,p.ca.rosterAckRetries().size());
            if(reason==0)p.xa.close();else if(reason==1)p.sa.close();else{
                var binding=p.a.state.administrators().bindings().stream().filter(b->Crypto.equal(b.memberId(),p.a.id())).findFirst().orElseThrow();
                p.a.state.acceptAdministrators(AdminRecords.administrators(p.a.groupId,2,StorageGroupTest.NOW,List.of(binding),p.a.administratorSecret),v->fail());
            }
            p.now+=1000;if(reason!=0)p.xa.poll(List.of(p.b.id()));
            assertTrue(p.ca.rosterAckRetries().isEmpty());assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void summaryCompletionWithSameOperationDoesNotAdvanceResponseCursor()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var request=RosterExchangeTest.request(p);fillAckBudget(p);
            var summary=RosterMessage.summarize(p.xb.directory(),new byte[0]);
            var incoming=ManagementPage.split(ManagementPage.Kind.ROSTER_SUMMARY,request.operationId(),p.a.groupId,summary.encode(),summary.entries().size()).get(0);
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),incoming.envelope(),p.now);
            var response=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),false));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),response.envelope(),p.now);
            p.now+=1000;
            var dummy=new ManagementPageAck(p.a.groupId,new byte[16],new byte[32],new int[]{0},false);
            for(int i=0;i<3;i++)assertTrue(p.ra.rosterAck(p.b.id(),p.sa.sessionId(p.b.id()),dummy));
            p.frames.clear();p.xa.poll(List.of(p.b.id()));
            assertEquals(1,p.frames.size());assertTrue(ManagementPageAck.decodeEnvelope(p.frames.peek().wire).complete());
            byte[] operation=new byte[16];operation[0]=97;
            assertEquals(ManagementPageSender.Offer.ACCEPTED,p.ra.offerRoster(p.b.id(),ManagementPage.Kind.ROSTER_SUMMARY,operation,summary.encode(),summary.entries().size()));
        }
    }
}
