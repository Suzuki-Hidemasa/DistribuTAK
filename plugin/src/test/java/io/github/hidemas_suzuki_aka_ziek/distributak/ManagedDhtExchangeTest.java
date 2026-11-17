// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.util.*;
import java.security.SecureRandom;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagedDhtExchangeTest {
    ManagedDhtExchange exchange(RosterExchangeTest.Pair p){return new ManagedDhtExchange(p.a,p.sa,p.ca,p.ua,p.wall,p.deadlines,()->p.now*1000000,new SecureRandom(),p.da);}
    ManagedDhtRecord rev(RosterExchangeTest.Pair p,long v,byte[] subject){
        var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,v,StorageGroupTest.NOW,List.of(subject),p.a.administratorSecret);
        var admins=p.a.state.administrators();
        return ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,p.a.groupId,p.a.administratorSecret,body,1,admins.version(),Crypto.blake2s(admins.signedBytes()),StorageGroupTest.NOW,null);
    }
    ManagedDhtRecord announcement(RosterExchangeTest.Pair p,AdminRecords.Record body,long version,int value){
        var admins=p.a.state.administrators();
        var a=KeyAnnouncement.issue(p.a.groupId,p.a.administratorSecret,version,StorageGroupTest.NOW,body.version(),Crypto.blake2s(body.signedBytes()),StoredUpdatesTest.key(value),admins.version(),Crypto.blake2s(admins.signedBytes()));
        return ManagedDhtRecord.issue(p.a.groupId,p.a.administratorSecret,a,1,admins.version(),Crypto.blake2s(admins.signedBytes()),StorageGroupTest.NOW);
    }
    AdminRecords.Record nextAdmins(RosterExchangeTest.Pair p,boolean retainA){
        var bindings=new ArrayList<AdminBinding>();
        for(var g:retainA?List.of(p.a,p.b):List.of(p.a)){
            var proof=AdminControl.keyProof(p.a.groupId,new byte[16],1,g.identitySecret,g.administratorSecret);
            bindings.add(AdminBinding.bound(proof.administratorKey(),g.id(),proof.encode()));
        }
        return AdminRecords.administrators(p.a.groupId,2,StorageGroupTest.NOW,bindings,p.a.administratorSecret);
    }
    @Test public void pendingOldRevocationRechecksAuthorityAndReachesTheReceiveCoordinator()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var high=rev(p,3,StoredUpdatesTest.key(230));x.store().accept(null,high,false);
            var low=rev(p,2,StoredUpdatesTest.key(231));var next=nextAdmins(p,true);
            var pending=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,p.a.groupId,p.a.administratorSecret,low.inner(),1,2,Crypto.blake2s(next.signedBytes()),StorageGroupTest.NOW,null);
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,pending,false));assertEquals(1,x.store().pendingCount());
            p.a.state.acceptAdministrators(next,v->fail());p.da.save(p.a);x.store().retry();
            assertEquals(0,x.store().pendingCount());assertTrue(p.ca.isRevoked(StoredUpdatesTest.key(231)));assertEquals(3,p.a.state.revocations().version());
            try(var loaded=p.da.load(p.wall)){assertEquals(2,loaded.state.revokedSubjects().size());}
        }
    }
    @Test public void pendingOldRevocationWithLostAuthorityIsDiscardedBeforeReceipt()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var high=rev(p,3,StoredUpdatesTest.key(230));x.store().accept(null,high,false);
            var low=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,2,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(231)),p.b.administratorSecret);var next=nextAdmins(p,false);
            var pending=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,p.a.groupId,p.b.administratorSecret,low,1,2,Crypto.blake2s(next.signedBytes()),StorageGroupTest.NOW,null);
            x.store().accept(null,pending,false);assertEquals(1,x.store().pendingCount());
            p.a.state.acceptAdministrators(next,v->fail());p.da.save(p.a);x.store().retry();
            assertEquals(0,x.store().pendingCount());assertFalse(p.ca.isRevoked(StoredUpdatesTest.key(231)));assertEquals(1,p.a.state.revokedSubjects().size());
        }
    }
    @Test public void oldListsReachDurableUnionWithoutRegressingTheWinner()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var high=rev(p,3,StoredUpdatesTest.key(230));var low=rev(p,2,StoredUpdatesTest.key(231));
            assertEquals(DhtWire.StoreStatus.ACCEPTED,x.store().accept(null,high,false));
            assertEquals(DhtWire.StoreStatus.OLD,x.store().accept(null,low,false));
            assertEquals(3,p.a.state.revocations().version());assertEquals(2,p.a.state.revokedSubjects().size());
            try(var loaded=p.da.load(p.wall)){assertEquals(2,loaded.state.revokedSubjects().size());assertEquals(3,loaded.state.revocations().version());}
        }
    }
    @Test public void competingAnnouncementsWaitForExactBodyThenObserveWithoutApplyingAKey()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var body=rev(p,2,StoredUpdatesTest.key(232));var a=announcement(p,body.inner(),8,210);var b=announcement(p,body.inner(),8,211);
            long key=p.a.keyVersion;assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,a,false));assertEquals(0,x.rotation().reservedKeyVersion());
            x.store().accept(null,body,false);x.store().retry();x.store().accept(null,b,false);
            assertEquals(8,x.rotation().reservedKeyVersion());assertTrue(x.rotation().pending());assertEquals(key,p.a.keyVersion);assertNull(p.a.state.announcement());
        }
    }
    @Test public void savedOldBodyAllowsObservationEvenWhenTheWinningListMissesTheUnion()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var old=rev(p,1,StoredUpdatesTest.key(232));var high=rev(p,2,StoredUpdatesTest.key(233));
            x.store().accept(null,old,false);x.store().accept(null,high,false);
            x.store().accept(null,announcement(p,old.inner(),7,210),false);
            assertEquals(7,x.rotation().reservedKeyVersion());assertTrue(x.rotation().pending());assertEquals(0,p.a.keyVersion);
        }
    }
    @Test public void staleAuthorityAndWrongBodyCannotAdvanceObservation()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var body=rev(p,1,StoredUpdatesTest.key(234));x.store().accept(null,body,false);
            var a=announcement(p,body.inner(),12,210);byte[] bytes=a.encode();bytes[bytes.length-1]^=1;
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().acceptBytes(null,bytes,false));assertEquals(0,x.rotation().reservedKeyVersion());
            var missing=rev(p,2,StoredUpdatesTest.key(235));x.store().accept(null,announcement(p,missing.inner(),13,211),false);
            assertEquals(0,x.rotation().reservedKeyVersion());assertFalse(x.rotation().pending());
        }
    }
    @Test public void unknownAdministratorVersionRemainsPendingAndDoesNotChangeOperationalState()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var admins=p.a.state.administrators();
            var future=AdminRecords.administrators(p.a.groupId,admins.version()+2,StorageGroupTest.NOW,admins.bindings(),p.a.administratorSecret);
            var record=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,p.a.groupId,p.a.administratorSecret,future,1,admins.version()+1,new byte[32],StorageGroupTest.NOW,null);
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,record,false));assertEquals(1,x.store().pendingCount());
            assertEquals(admins.version(),p.a.state.administrators().version());x.store().retry();assertEquals(1,x.store().pendingCount());
            p.now=120000;x.store().retry();assertEquals(0,x.store().pendingCount());assertEquals(admins.version(),p.a.state.administrators().version());
        }
    }
    @Test public void persistenceSuspendsManagementInputAndFailureStopsObservation()throws Exception{
        try(var p=new RosterExchangeTest.Pair();var x=exchange(p)){
            var body=rev(p,1,StoredUpdatesTest.key(234));
            p.ca.saveUnchanged(()->assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,body,false)));
            assertEquals(0,p.a.state.revocations().version());assertEquals(0,x.store().size());
            p.da.managementFiles.fail=true;
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,body,false));
            assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,p.ca.state());assertFalse(x.allowed());
            assertEquals(DhtWire.StoreStatus.INVALID,x.store().accept(null,announcement(p,body.inner(),9,212),false));
            assertEquals(0,x.rotation().reservedKeyVersion());assertEquals(0,x.store().size());
        }
    }
}
