// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagedRoundTwoFixTest {
    @Test public void pendingAdministratorSaveCanRecoverOnTheSameDhtAfterUncommittedFailure()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var second=new ManagedDhtExchangeTest().nextAdmins(n.p,true);
            var third=AdminRecords.administrators(n.p.a.groupId,3,StorageGroupTest.NOW,second.bindings(),n.p.a.administratorSecret);
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,n.p.a.groupId,n.p.a.administratorSecret,third,0,
                    second.version(),Crypto.blake2s(second.signedBytes()),StorageGroupTest.NOW,null);
            assertEquals(DhtWire.StoreStatus.INVALID,n.xa.store().accept(null,record,false));assertEquals(1,n.xa.store().pendingCount());
            assertTrue(n.p.ca.receiveAdministrators(second,n.p.da.persistenceHooks(n.p.a)));
            n.p.da.managementFiles.fail=true;n.a.step();
            assertEquals(CorePersistenceCoordinator.State.RUNNING,n.p.ca.state());assertTrue(n.a.active());
            assertEquals(1,n.xa.store().pendingCount());assertEquals(2,n.p.a.state.administrators().version());
            n.p.da.managementFiles.fail=false;n.p.now+=1000;n.a.step();
            assertTrue(n.a.active());assertEquals(3,n.p.a.state.administrators().version());assertEquals(0,n.xa.store().pendingCount());
            try(var saved=n.p.da.load(n.p.wall)){assertEquals(3,saved.state.administrators().version());}
        }
    }
    @Test public void unexpectedPersistenceInvariantStillFaultsTheDht()throws Exception{
        assertFatalPersistenceFailure(false);
    }
    @Test public void committedAdministratorFailureStillStopsAndFaultsTheDht()throws Exception{
        assertFatalPersistenceFailure(true);
    }
    private void assertFatalPersistenceFailure(boolean committed)throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            var second=new ManagedDhtExchangeTest().nextAdmins(n.p,true);
            var third=AdminRecords.administrators(n.p.a.groupId,3,StorageGroupTest.NOW,second.bindings(),n.p.a.administratorSecret);
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,n.p.a.groupId,n.p.a.administratorSecret,third,0,second.version(),Crypto.blake2s(second.signedBytes()),StorageGroupTest.NOW,null);
            n.xa.store().accept(null,record,false);assertEquals(1,n.xa.store().pendingCount());
            assertTrue(n.p.ca.receiveAdministrators(second,n.p.da.persistenceHooks(n.p.a)));
            var delegate=n.p.da.persistenceHooks(n.p.a);
            var storage=(LanRuntime.Storage)java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),new Class<?>[]{LanRuntime.Storage.class},(proxy,method,args)->{
                if(method.getName().equals("persistenceHooks")){
                    if(!committed)throw new IllegalStateException("Injected invariant failure");
                    return new CorePersistenceCoordinator.PersistenceHooks(){
                        public void save(AdminRecordStore.Snapshot snapshot){delegate.save(snapshot);n.p.sa.close();}
                    };
                }
                try{return method.invoke(n.p.da,args);}catch(java.lang.reflect.InvocationTargetException failure){throw failure.getCause();}
            });
            var field=ManagedDhtExchange.class.getDeclaredField("storage");field.setAccessible(true);field.set(n.xa,storage);
            n.a.step();assertFalse(n.a.active());
            assertEquals(committed?CorePersistenceCoordinator.State.STORAGE_FAILED:CorePersistenceCoordinator.State.RUNNING,n.p.ca.state());
            if(committed)try(var saved=n.p.da.load(n.p.wall)){assertEquals(3,saved.state.administrators().version());}
        }
    }
    @Test public void knownInvalidAnnouncementDoesNotScheduleBodyLookup()throws Exception{
        for(int invalid=0;invalid<3;invalid++)try(var p=new RosterExchangeTest.Pair();var x=new ManagedRoundTwoTest().exchange(p)){
            var admins=p.a.state.administrators();
            var ann=KeyAnnouncement.issue(p.a.groupId,invalid==0?StoredUpdatesTest.key(217):p.a.administratorSecret,2,StorageGroupTest.NOW,
                    8,new byte[32],new byte[32],invalid==2?0:admins.version(),invalid==1?new byte[32]:Crypto.blake2s(admins.signedBytes()));
            var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],p.a.groupId,ann.encode(),0).get(0);
            assertNull(x.receiveAnnouncement(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now));
            var field=ManagedDhtExchange.class.getDeclaredField("lookups");field.setAccessible(true);
            assertEquals(0,((Map<?,?>)field.get(x)).size());
        }
    }
    @Test public void unknownAdministratorVersionStillWaitsAndSchedulesItsDependency()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=new ManagedRoundTwoTest().exchange(p)){
            var ann=KeyAnnouncement.issue(p.a.groupId,StoredUpdatesTest.key(217),2,StorageGroupTest.NOW,8,new byte[32],new byte[32],2,new byte[32]);
            var page=ManagementPage.split(ManagementPage.Kind.ANNOUNCEMENT,new byte[16],p.a.groupId,ann.encode(),0).get(0);
            assertNull(x.receiveAnnouncement(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope(),p.now));
            var field=ManagedDhtExchange.class.getDeclaredField("lookups");field.setAccessible(true);
            assertEquals(1,((Map<?,?>)field.get(x)).size());
        }
    }
    @Test public void closingManagementDhtLeavesTheSharedRecoverySenderUsable()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.xa.transport(n.p.ra);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.a.close();
            assertEquals(ManagementPageSender.Offer.ACCEPTED,n.p.ra.offerRevocations(n.p.b.id()));
            n.p.ra.poll(List.of());assertFalse(n.p.frames.isEmpty());
            for(var frame:n.p.frames)assertEquals(ManagementPage.Kind.REVOCATION,ManagementPage.decodeEnvelope(frame.wire).kind());
        }
    }
    @Test public void productPollOrderCancelsQueuedAnnouncementBeforeTheSenderAdvances()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.xa.transport(n.p.ra);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.p.ra.poll(List.of());
            var rev=ManagementPage.decodeEnvelope(n.p.frames.remove().wire);
            var ack=new ManagementPageAck(n.p.a.groupId,rev.operationId(),rev.objectDigest(),new int[]{0},true);
            n.p.ra.receive(n.p.b.id(),n.p.sa.sessionId(n.p.b.id()),ack.envelope(),n.p.now);
            assertTrue(n.p.ca.receiveAdministrators(new ManagedDhtExchangeTest().nextAdmins(n.p,true),n.p.da.persistenceHooks(n.p.a)));
            n.p.ra.poll(List.of());assertTrue(n.p.frames.isEmpty());n.a.step();
            assertEquals(1,n.p.a.state.announcement().adminVersion());
        }
    }
    @Test public void acceptedRevocationIsNotOfferedAgainWhileAnnouncementSlotIsBusy()throws Exception{
        try(var n=new ManagedDhtWiringTest.Network()){
            n.xa.transport(n.p.ra);
            var old=new ManagedDhtExchangeTest().announcement(n.p,n.p.a.state.revocations(),2,230).announcement();
            assertEquals(ManagementPageSender.Offer.ACCEPTED,n.p.ra.offerAnnouncement(n.p.b.id(),old));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,n.xa.rotation().manual(List.of(),List.of(n.p.b.certificate),n.p.da.persistenceHooks(n.p.a)));
            n.a.step();n.p.ra.poll(List.of());
            var rev=ManagementPage.decodeEnvelope(n.p.frames.remove().wire);assertEquals(ManagementPage.Kind.REVOCATION,rev.kind());
            var ack=new ManagementPageAck(n.p.a.groupId,rev.operationId(),rev.objectDigest(),new int[]{0},true);
            n.p.ra.receive(n.p.b.id(),n.p.sa.sessionId(n.p.b.id()),ack.envelope(),n.p.now);
            n.p.now+=1000;n.a.step();n.p.ra.poll(List.of());
            for(var frame:n.p.frames)assertEquals(ManagementPage.Kind.ANNOUNCEMENT,ManagementPage.decodeEnvelope(frame.wire).kind());
            var senderField=RevocationRecovery.class.getDeclaredField("sender");senderField.setAccessible(true);var sender=senderField.get(n.p.ra);
            for(String list:List.of("pending","active")){
                var f=ManagementPageSender.class.getDeclaredField(list);f.setAccessible(true);
                for(Object out:(List<?>)f.get(sender)){
                    var pages=out.getClass().getDeclaredField("pages");pages.setAccessible(true);
                    assertNotEquals(ManagementPage.Kind.REVOCATION,((ManagementPage)((List<?>)pages.get(out)).get(0)).kind());
                }
            }
        }
    }
}
