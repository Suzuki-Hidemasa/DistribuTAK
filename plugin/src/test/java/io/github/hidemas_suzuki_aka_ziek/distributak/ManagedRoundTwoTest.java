// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagedRoundTwoTest {
    @Test public void periodicManagementLookupFetchesSavedRevocationsUsingExistingValueTransport()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var value=new ManagedDhtExchangeTest().rev(n.p,2,StoredUpdatesTest.key(235));
            assertEquals(DhtWire.StoreStatus.ACCEPTED,n.xb.store().accept(null,value,false));
            for(int i=0;i<50;i++){n.a.step();n.b.step();n.pump();n.p.now+=1000;}
            assertEquals(2,n.p.a.state.revocations().version());
        }
    }
    @Test public void announcementCompletionConfirmsValidatedObservationRatherThanKeyAdoption()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var body=p.a.state.revocations();var record=new ManagedDhtExchangeTest().announcement(p,body,2,230);
            var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],p.a.groupId,record.announcement().encode(),0).get(0);
            var method=ManagedDhtExchange.class.getDeclaredMethod("receiveAnnouncement",byte[].class,byte[].class,byte[].class,long.class);method.setAccessible(true);
            var ack=(ManagementPageAck)method.invoke(x,p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
            assertNotNull(ack);assertTrue(ack.complete());assertEquals(0,p.a.keyVersion);assertNull(p.a.state.announcement());
        }
    }
    @Test public void persistedListsArePublishedWithoutAKeyRotationAndHistoryBootstrapsTheNextVersion()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var next=new ManagedDhtExchangeTest().nextAdmins(n.p,true);
            assertTrue(n.p.ca.receiveAdministrators(next,n.p.da.persistenceHooks(n.p.a)));
            for(int i=0;i<5;i++){n.a.step();n.b.step();n.pump();n.p.now+=1000;}
            var latest=n.xa.store().get(DhtKeys.derive(n.p.a.groupId,DhtKeys.LATEST_ADMINS,new byte[32]));
            assertNotNull(latest);assertEquals(1,latest.adminVersion());
            var history=n.xa.store().get(DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(2)));
            assertNotNull(history);assertEquals(1,history.adminVersion());
            assertEquals(2,n.p.b.state.administrators().version());
        }
    }
    @Test public void savedRotationPublishesOnlyPersistedWrapsAndRetainsSignedBytes()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var directory=new MemberDirectory(n.p.a.state);directory.saved(n.p.a.certificate);directory.saved(n.p.b.certificate);
            n.p.da.saveDirectory(n.p.a,directory,Map.of());
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            for(int i=0;i<5;i++){n.a.step();n.b.step();n.pump();n.p.now+=1000;}
            var key=DhtKeys.derive(n.p.a.groupId,DhtKeys.WRAPPED_KEY,n.p.b.id());
            var first=n.xa.store().get(key);assertNotNull(first);assertEquals(1,n.p.b.keyVersion);
            n.p.now+=1000;n.a.step();n.pump();assertArrayEquals(first.encode(),n.xa.store().get(key).encode());
        }
    }
    @Test public void ordinaryMemberObservationUsesTheSharedBudgetAndExpiresWithoutExtending()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var ann=new ManagedDhtExchangeTest().announcement(p,p.a.state.revocations(),2,230).announcement();
            Crypto.wipe(p.a.administratorSecret);p.a.administratorSecret=new byte[0];
            try(var x=exchange(p)){
                var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],p.a.groupId,ann.encode(),0).get(0);
                var ack=x.receiveAnnouncement(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now);
                assertNotNull(ack);assertTrue(ack.complete());assertEquals(1,x.budget().count());
                assertNotNull(x.store().announcement(Crypto.blake2s(ann.signedBytes())));
                p.wallAdvance=86400000;x.store().retry();
                assertNull(x.store().announcement(Crypto.blake2s(ann.signedBytes())));assertEquals(0,x.budget().count());
            }
        }
    }
    @Test public void expiredManagementAttemptCannotAdmitALateValueAtTheOverallDeadline()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var target=new ManagedDhtExchangeTest().rev(n.p,2,StoredUpdatesTest.key(234));
            n.xb.store().accept(null,target,false);
            var method=ManagedDhtExchange.class.getDeclaredMethod("lookup",DhtId.class);method.setAccessible(true);method.invoke(n.xa,target.key());
            n.p.now=119999;n.a.step();
            n.p.now=120000;n.pump();
            assertEquals(0,n.p.a.state.revocations().version());
        }
    }
    @Test public void invalidatedOuterIsNeverResignedForTheSameInner()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var admins=n.p.a.state.administrators();var body=n.p.a.state.revocations();
            var old=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,n.p.a.groupId,n.p.b.administratorSecret,body,1,admins.version(),Crypto.blake2s(admins.signedBytes()),body.signedAt(),null);
            assertEquals(DhtWire.StoreStatus.ACCEPTED,n.xa.store().accept(null,old,false));
            for(int i=0;i<5;i++){n.a.step();n.b.step();n.pump();n.p.now+=1000;}
            var key=old.key();
            var next=new ManagedDhtExchangeTest().nextAdmins(n.p,false);assertTrue(n.p.ca.receiveAdministrators(next,n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.pump();
            var after=n.xa.store().get(key);
            if(after!=null)assertArrayEquals(old.encode(),after.encode());
        }
    }
    @Test public void discoveryRetriesAtSixtySecondsAndStartsNothingAtTheTwoMinuteDeadline()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var key=DhtKeys.derive(n.p.a.groupId,DhtKeys.WRAPPED_KEY,n.p.a.id());
            var lookup=ManagedDhtExchange.class.getDeclaredMethod("lookup",DhtId.class);lookup.setAccessible(true);lookup.invoke(n.xa,key);
            var times=new ArrayList<Long>();
            for(long now:new long[]{0,1000,2000,5000,15000,30000,60000,119999,120000}){
                n.p.now=now;n.a.step();
                for(var frame:n.frames){
                    var wire=frame.wire;
                    if(DhtWire.isDht(wire)){var m=DhtWire.parse(wire);
                        if(m.managed()&&m.op()==DhtWire.Op.FIND_VALUE&&key.equals(m.target()))times.add(now);
                    }
                }
                n.pump();
            }
            assertTrue(times.contains(60000L));assertFalse(times.contains(119999L));assertFalse(times.contains(120000L));
            var field=ManagedDhtExchange.class.getDeclaredField("lookups");field.setAccessible(true);
            assertFalse(((Map<?,?>)field.get(n.xa)).containsKey(key));
            for(int i=0;i<20;i++)lookup.invoke(n.xa,DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(i)));
            assertEquals(8,((Map<?,?>)field.get(n.xa)).size());
        }
    }
    @Test public void equalRevocationWinnersDoNotGuaranteeUnionEqualityOrRepeatedRecovery()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var cert=StoredUpdatesTest.peer(p.a,232,233,StorageGroupTest.NOW);var subject=Crypto.blake2s(cert.field(0));
            var low=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,1,StorageGroupTest.NOW,List.of(subject),p.a.administratorSecret);
            var winner=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,2,StorageGroupTest.NOW,List.of(),p.a.administratorSecret);
            assertTrue(p.ca.receiveRevocations(low,p.da.persistenceHooks(p.a)));assertTrue(p.ca.receiveRevocations(winner,p.da.persistenceHooks(p.a)));
            assertTrue(p.cb.receiveRevocations(winner,p.db.persistenceHooks(p.b)));failThree(p,cert);
            assertArrayEquals(p.a.state.revocations().encode(),p.b.state.revocations().encode());
            assertTrue(p.ca.isRevoked(subject));assertFalse(p.cb.isRevoked(subject));
            assertEquals(ManagementPageSender.Offer.ACCEPTED,p.ra.offerRevocations(p.b.id()));p.ra.poll(List.of());
            var outgoing=p.frames.remove();assertTrue(outgoing.toB);p.rb.receive(p.a.id(),p.sb.sessionId(p.a.id()),outgoing.wire,p.now);
            var ack=p.frames.remove();assertFalse(ack.toB);p.ra.receive(p.b.id(),p.sa.sessionId(p.b.id()),ack.wire,p.now);
            failThree(p,cert);
            delivered(p,Crypto.blake2s(winner.signedBytes()));p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());
            assertTrue(p.frames.isEmpty());assertEquals(1,p.xa.directory().size());
        }
    }
    @Test public void announcementWaitsForTheExactBodyAndRetriesWithinItsOriginalCompletionSlot()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,2,StorageGroupTest.NOW,List.of(),p.a.administratorSecret);
            var ann=new ManagedDhtExchangeTest().announcement(p,body,2,230).announcement();
            var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],p.a.groupId,ann.encode(),0).get(0);
            byte[] session=p.sa.sessionId(p.b.id());
            assertNull(x.receiveAnnouncement(p.b.id(),session,page.envelope(),p.now));
            p.xa.poll(List.of());
            var admins=p.a.state.administrators();
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,p.a.groupId,p.a.administratorSecret,body,0,admins.version(),Crypto.blake2s(admins.signedBytes()),body.signedAt(),null);
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,record,false));
            var ack=x.receiveAnnouncement(p.b.id(),session,page.envelope(),p.now);
            assertNotNull(ack);assertTrue(ack.complete());assertEquals(0,p.a.keyVersion);
        }
    }
    @Test public void failedRotationPersistenceNeverPublishesAnAnnouncementOrWrap()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.p.da.managementFiles.fail=true;
            assertEquals(KeyRotationCoordinator.Result.CANCELLED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            assertNull(n.xa.rotation().publication());
            for(int i=0;i<5;i++){n.a.step();n.b.step();n.pump();n.p.now+=1000;}
            assertNull(n.xa.store().get(DhtKeys.derive(n.p.a.groupId,DhtKeys.KEY_ANNOUNCEMENT,new byte[32])));
            assertNull(n.xa.store().get(DhtKeys.derive(n.p.a.groupId,DhtKeys.WRAPPED_KEY,n.p.b.id())));
            assertEquals(0,n.p.b.keyVersion);
        }
    }
    @Test public void completionFromAStaleBindingDoesNotReopenTheStoppedRoster()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            byte[] broken=p.b.certificate.encode();broken[broken.length-1]^=1;failThree(p,AdminRecords.decode(broken));
            p.xa.revocationsDelivered(p.b.id(),new byte[16],p.sa.generation(),new byte[32]);
            p.xa.revocationsDelivered(p.b.id(),p.sa.sessionId(p.b.id()),p.sa.generation()+1,new byte[32]);
            p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void cancelledPublicationDoesNotLeaveItsPagesInTheCommonSender()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.xa.transport(n.p.ra);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            var publication=n.xa.rotation().publication();
            var oldBody=publication.revocations().encode();var oldAnnouncement=publication.announcement().encode();
            n.a.step();
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,n.p.a.groupId,2,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(233)),n.p.a.administratorSecret);
            assertTrue(n.p.ca.receiveRevocations(body,n.p.da.persistenceHooks(n.p.a)));n.a.step();
            n.p.ra.poll(List.of());
            for(var frame:n.p.frames){
                var page=ManagementPage.decodeEnvelope(frame.wire);
                assertFalse(Arrays.equals(oldBody,page.data()));assertFalse(Arrays.equals(oldAnnouncement,page.data()));
            }
        }
    }
    @Test public void dependentAdministratorVersionsAreFetchedInOrderOverTheRealTransport()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var second=new ManagedDhtExchangeTest().nextAdmins(n.p,true);
            assertTrue(n.p.ca.receiveAdministrators(second,n.p.da.persistenceHooks(n.p.a)));
            var third=AdminRecords.administrators(n.p.a.groupId,3,StorageGroupTest.NOW,second.bindings(),n.p.a.administratorSecret);
            assertTrue(n.p.ca.receiveAdministrators(third,n.p.da.persistenceHooks(n.p.a)));
            for(int i=0;i<50;i++){n.a.step();n.b.step();n.pump();n.p.now+=1000;}
            assertEquals(3,n.p.b.state.administrators().version());assertNotNull(n.p.b.state.administratorsAt(2));
        }
    }
    @Test public void cancelledStoreTransferSendsNoMoreChunksEvenWhenAnAckArrives()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var subjects=new ArrayList<byte[]>();for(int i=0;i<400;i++)subjects.add(Crypto.blake2s(new byte[]{(byte)i,(byte)(i>>>8)}));
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,n.p.a.groupId,2,StorageGroupTest.NOW,subjects,n.p.a.administratorSecret);
            var admins=n.p.a.state.administrators();
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,n.p.a.groupId,n.p.a.administratorSecret,body,0,admins.version(),Crypto.blake2s(admins.signedBytes()),StorageGroupTest.NOW,null);
            boolean[] current={true};var results=new ArrayList<DhtWire.StoreStatus>();
            var method=DhtDispatcher.class.getMethod("storeManaged",Contact.class,byte[].class,java.util.function.Consumer.class,java.util.function.BooleanSupplier.class);
            assertEquals(true,method.invoke(n.a.dispatcherForTest(),new Contact(new DhtId(n.p.b.id())),record.encode(),(java.util.function.Consumer<DhtWire.StoreStatus>)results::add,(java.util.function.BooleanSupplier)()->current[0]));
            current[0]=false;n.pump();assertEquals(0,n.p.b.state.revocations().version());
            n.p.now+=1000;n.a.step();n.pump();assertEquals(1,results.size());assertNull(results.get(0));
        }
    }
    @Test public void administratorRevisionInvalidatesQueuedDeliveryWithoutRewritingTheAnnouncement()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.xa.transport(n.p.ra);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();
            assertTrue(n.p.ca.receiveAdministrators(new ManagedDhtExchangeTest().nextAdmins(n.p,true),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.p.ra.poll(List.of());assertTrue(n.p.frames.isEmpty());
            assertEquals(1,n.p.a.state.announcement().adminVersion());
        }
    }
    @Test public void anOlderBusyRevocationDoesNotCountAsDeliveryOfTheNewPublicationBody()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.xa.transport(n.p.ra);assertEquals(ManagementPageSender.Offer.ACCEPTED,n.p.ra.offerRevocations(n.p.b.id()));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.p.ra.poll(List.of());var first=n.p.frames.remove();
            n.p.rb.receive(n.p.a.id(),n.p.sb.sessionId(n.p.a.id()),first.wire,n.p.now);
            var ack=n.p.frames.remove();n.p.ra.receive(n.p.b.id(),n.p.sa.sessionId(n.p.b.id()),ack.wire,n.p.now);
            n.p.now+=1000;n.a.step();n.p.ra.poll(List.of());
            assertFalse(n.p.frames.isEmpty());var next=ManagementPage.decodeEnvelope(n.p.frames.remove().wire);
            assertEquals(ManagementPage.Kind.REVOCATION,next.kind());assertEquals(1,AdminRecords.decode(next.data()).version());
        }
    }
    @Test public void restoredPublicationKeepsItsOriginalSigningTimeSequenceAndExpiry()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var directory=new MemberDirectory(n.p.a.state);directory.saved(n.p.a.certificate);directory.saved(n.p.b.certificate);
            n.p.da.saveDirectory(n.p.a,directory,Map.of());
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.pump();
            var key=DhtKeys.derive(n.p.a.groupId,DhtKeys.KEY_ANNOUNCEMENT,new byte[32]);var original=n.xa.store().get(key);assertNotNull(original);
            n.p.wallAdvance=3600000;
            try(var restored=exchange(n.p)){
                assertNotNull(restored.rotation().publication());restored.poll(n.a);n.pump();
                var record=restored.store().get(key);assertNotNull(record);
                assertEquals(original.signedAt(),record.signedAt());assertEquals(0,record.publicationSeq());
                assertEquals(original.expiresAt(),record.expiresAt());assertArrayEquals(original.encode(),record.encode());
            }
        }
    }
    @SuppressWarnings("unchecked")
    @Test public void fullPublicationMetadataExpiresAndAllowsNewTargetsWithoutStoppingCommunication()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.a.step();n.pump();
            var field=ManagedDhtExchange.class.getDeclaredField("publishedInners");field.setAccessible(true);
            var metadata=(Map<DhtId,Object>)field.get(n.xa);assertFalse(metadata.isEmpty());var entry=metadata.values().iterator().next();
            for(int i=0;metadata.size()<DhtRecordBudget.MAX_RECORDS;i++)metadata.put(DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(100+i)),entry);
            assertTrue(n.p.ca.receiveAdministrators(new ManagedDhtExchangeTest().nextAdmins(n.p,true),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();assertNull(n.xa.store().get(DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(2))));
            assertTrue(n.a.active());assertEquals(CorePersistenceCoordinator.State.RUNNING,n.p.ca.state());
            n.p.wallAdvance=86400000;n.a.step();assertTrue(metadata.isEmpty());
            var third=AdminRecords.administrators(n.p.a.groupId,3,n.p.wall.millis(),n.p.a.state.administrators().bindings(),n.p.a.administratorSecret);
            assertTrue(n.p.ca.receiveAdministrators(third,n.p.da.persistenceHooks(n.p.a)));n.a.step();
            assertNotNull(n.xa.store().get(DhtKeys.derive(n.p.a.groupId,DhtKeys.ADMIN_HISTORY,DhtKeys.adminHistorySubject(3))));
            assertTrue(metadata.size()<DhtRecordBudget.MAX_RECORDS);assertTrue(n.a.active());
        }
    }
    ManagedDhtExchange exchange(RosterExchangeTest.Pair p){return new ManagedDhtExchangeTest().exchange(p);}
    @Test public void administratorListReachesDiskBeforeDhtPublication()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var next=new ManagedDhtExchangeTest().nextAdmins(p,true);var current=p.a.state.administrators();
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,p.a.groupId,p.a.administratorSecret,next,1,current.version(),Crypto.blake2s(current.signedBytes()),StorageGroupTest.NOW,null);
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,record,false));
            assertEquals(2,p.a.state.administrators().version());
            try(var loaded=p.da.load(p.wall)){assertEquals(2,loaded.state.administrators().version());assertFalse(loaded.storageBlocked);}
        }
    }
    @Test public void failedAdministratorSaveDoesNotPublishOrStopCommunication()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var next=new ManagedDhtExchangeTest().nextAdmins(p,true);var current=p.a.state.administrators();
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,p.a.groupId,p.a.administratorSecret,next,1,current.version(),Crypto.blake2s(current.signedBytes()),StorageGroupTest.NOW,null);
            p.da.managementFiles.fail=true;
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,record,false));
            assertEquals(1,p.a.state.administrators().version());assertEquals(CorePersistenceCoordinator.State.RUNNING,p.ca.state());assertNull(x.store().get(record.key()));
        }
    }
    @Test public void verifiedAnnouncementAndLocalWrapApplySavedKeyOnTheSameOldSession()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var admins=p.a.state.administrators();var body=p.a.state.revocations();byte[] next=StoredUpdatesTest.key(230),session=p.sa.sessionId(p.b.id());
            var ann=KeyAnnouncement.issue(p.a.groupId,p.a.administratorSecret,1,StorageGroupTest.NOW,body.version(),Crypto.blake2s(body.signedBytes()),KeyAnnouncement.commitment(p.a.groupId,1,next),admins.version(),Crypto.blake2s(admins.signedBytes()));
            var wrap=GroupKeyEnvelope.wrap(p.a.groupId,p.a.id(),Crypto.x25519Public(p.a.handshakeSecret),1,StorageGroupTest.NOW,next,p.a.administratorSecret,Crypto.blake2s(ann.signedBytes()));
            var record=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,p.a.groupId,p.a.administratorSecret,wrap,1,admins.version(),Crypto.blake2s(admins.signedBytes()),StorageGroupTest.NOW,p.a.certificate.encode());
            x.store().accept(null,ManagedDhtRecord.issue(p.a.groupId,p.a.administratorSecret,ann,1,admins.version(),Crypto.blake2s(admins.signedBytes()),StorageGroupTest.NOW),false);
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,record,false));assertEquals(1,p.a.keyVersion);assertArrayEquals(ann.encode(),p.a.state.announcement().encode());
            assertArrayEquals(session,p.sa.sessionId(p.b.id()));
            try(var loaded=p.da.load(p.wall)){assertEquals(1,loaded.keyVersion);assertArrayEquals(ann.encode(),loaded.state.announcement().encode());}
            p.now=179999;assertTrue(p.sa.isEstablished(p.b.id()));p.now=180000;assertFalse(p.sa.isEstablished(p.b.id()));
        }
    }
    void failThree(RosterExchangeTest.Pair p,AdminRecords.Record cert){
        for(int i=0;i<3;i++){
            var request=RosterExchangeTest.request(p);var response=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(cert),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),response.envelope(),p.now);assertTrue(p.frames.isEmpty());
        }
    }
    void delivered(RosterExchangeTest.Pair p,byte[] subject)throws Exception{
        var method=RosterExchange.class.getDeclaredMethod("revocationsDelivered",byte[].class,byte[].class,long.class,byte[].class);method.setAccessible(true);
        method.invoke(p.xa,p.b.id(),p.sa.sessionId(p.b.id()),p.sa.generation(),subject);
    }
    @Test public void savedManagementChangeRecoversStoppedRosterWithoutReplacingSession()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            byte[] broken=p.b.certificate.encode();broken[broken.length-1]^=1;var invalid=AdminRecords.decode(broken);failThree(p,invalid);
            byte[] session=p.sa.sessionId(p.b.id());
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,1,StorageGroupTest.NOW,List.of(),p.a.administratorSecret);
            assertTrue(p.ca.receiveRevocations(body,p.da.persistenceHooks(p.a)));
            var request=RosterExchangeTest.request(p);assertArrayEquals(session,p.sa.sessionId(p.b.id()));
            var response=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),session,response.envelope(),p.now);assertEquals(2,p.xa.directory().size());
        }
    }
    @Test public void completionTriggerAllowsOneRecoveryPerManagementRevisionAcrossDifferentTargets()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            byte[] broken=p.b.certificate.encode();broken[broken.length-1]^=1;var invalid=AdminRecords.decode(broken);failThree(p,invalid);
            delivered(p,StoredUpdatesTest.key(230));failThree(p,invalid);
            delivered(p,StoredUpdatesTest.key(231));p.now+=1000;p.xa.poll(List.of(p.b.id()));p.ra.poll(List.of());assertTrue(p.frames.isEmpty());
        }
    }
    @Test public void revocationDivergenceRecoversAfterSavedStateChangeAndStillValidatesEveryEntry()throws Exception{
        try(var p=new RosterExchangeTest.Pair()){
            var cert=StoredUpdatesTest.peer(p.a,230,231,StorageGroupTest.NOW);byte[] subject=Crypto.blake2s(cert.field(0));
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,1,StorageGroupTest.NOW,List.of(subject),p.a.administratorSecret);
            assertTrue(p.ca.receiveRevocations(body,p.da.persistenceHooks(p.a)));failThree(p,cert);
            assertTrue(p.cb.receiveRevocations(body,p.db.persistenceHooks(p.b)));delivered(p,Crypto.blake2s(body.signedBytes()));
            var request=RosterExchangeTest.request(p);var response=RosterExchangeTest.response(p,request,new RosterMessage.Batch(List.of(p.b.certificate),true));
            p.xa.receive(p.b.id(),p.sa.sessionId(p.b.id()),response.envelope(),p.now);assertEquals(2,p.xa.directory().size());assertTrue(p.ca.isRevoked(subject));
        }
    }
}
