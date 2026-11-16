// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ReviewStorageFixTest {
    final VersionSixStorageTest f=new VersionSixStorageTest();
    AdminRecords.Record revocation(LanGroup g,byte[] subject){
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(subject),g.administratorSecret);
    }
    @Test public void receivedFullDiskKeepsActiveBeforeSpaceCheckAndAfterRestart()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            f.storage().save(g);byte[] before=f.f.state.value.clone();f.files.space=false;
            var c=new CorePersistenceCoordinator(g.state,sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            assertFalse(c.receiveRevocations(revocation(g,StoredUpdatesTest.key(81)),f.storage().persistenceHooks(g)));
            assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,c.state());assertEquals("保存がいっぱい",c.statusText());
            assertArrayEquals(before,f.f.state.value);assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertTrue(loaded.storageBlocked);assertNotNull(loaded.recoveryRequirement);assertEquals(1,loaded.recoveryRequirement.version());
            }
        }
    }
    @Test public void legacyReceivedFullDiskStillWritesActiveBeforeMigrationSpaceCheck()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.f.storage().save(g);f.storage().prepareNetwork(g);f.files.space=false;
            var hooks=f.storage().persistenceHooks(g);var r=f.request(g,revocation(g,StoredUpdatesTest.key(81)),false);
            hooks.active(r);assertThrows(RuntimeException.class,()->hooks.save(r));hooks.stopped();
            assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertTrue(loaded.storageBlocked);assertNotNull(loaded.recoveryRequirement);}
        }
    }
    @Test public void receivedHistoryCountLimitLeavesCandidateLessActiveAfterRestart()throws Exception{limit(0);}
    @Test public void receivedHistoryByteLimitLeavesCandidateLessActiveAfterRestart()throws Exception{limit(1);}
    @Test public void receivedManagementLimitLeavesCandidateLessActiveAfterRestart()throws Exception{limit(2);}
    void limit(int kind)throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);long seq=g.saveSeq;byte[] before=f.f.state.value.clone();
            var body=revocation(g,StoredUpdatesTest.key(81));var r=f.request(g,body,false);var s=r.management();
            if(kind<2){
                var history=kind==0?Collections.nCopies(65_537,new byte[]{1}):List.of(new byte[12*1024*1024]);
                s=new AdminRecordStore.Snapshot(history,s.anchorSignature(),s.revocations(),s.administratorVersion(),s.revocationVersion());
            }else{
                var old=g.management;var labels=new TreeMap<String,String>();for(int n=0;n<513;n++)labels.put("label"+n,"x".repeat(32768));
                g.management=new ManagementState(old.generation,old.snapshot,old.union,old.roster,old.legacyPermissions,labels,old.reservations,old.outgoing,old.legacyAdministratorBasis,old.stopReason,old.checkpoint);
            }
            var request=new CorePersistenceCoordinator.PersistenceRequest(s,body,true,false,null);var hooks=f.storage().persistenceHooks(g);
            assertThrows(RuntimeException.class,()->hooks.active(request));hooks.stopped();
            assertArrayEquals(before,f.f.state.value);var marker=f.marker.marker().inspect();assertEquals(StopMarker.Status.ACTIVE,marker.status());
            assertEquals(seq,marker.target().saveSeq());assertEquals(body.version(),marker.target().requiredVersion());
            assertArrayEquals(new byte[32],marker.target().stateDigest());assertArrayEquals(new byte[32],marker.target().revocationDigest());
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertTrue(loaded.storageBlocked);assertNotNull(loaded.recoveryRequirement);assertEquals(body.version(),loaded.recoveryRequirement.version());
                assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            }
        }
    }
    @Test public void peerRevocationCrashChecksOriginalStateBeforeRemovingPeer()throws Exception{peerCrash(false);}
    @Test public void peerRevocationCrashChecksOriginalPendingRenewalBeforeCleanup()throws Exception{peerCrash(true);}
    void peerCrash(boolean renewal)throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            g.peerCertificate=StoredUpdatesTest.peer(g,71,72,StorageGroupTest.NOW-1);
            g.peerAddress=new InetSocketAddress(InetAddress.getByAddress(new byte[]{(byte)192,0,2,1}),54322);
            byte[] id=Crypto.blake2s(g.peerCertificate.field(0));
            if(renewal)g.rememberRenewal(id,StoredUpdatesTest.peer(g,71,72,StorageGroupTest.NOW).encode());
            f.storage().save(g);var r=f.request(g,revocation(g,id),false);var hooks=f.storage().persistenceHooks(g);
            hooks.active(r);hooks.save(r);assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertFalse(loaded.storageBlocked);assertNull(loaded.recoveryRequirement);assertNull(loaded.peerCertificate);assertNull(loaded.pendingRenewal(id));
                assertEquals(1,loaded.state.revokedSubjects().size());assertEquals(StopMarker.Status.CLEAR,f.marker.marker().inspect().status());
            }
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertFalse(loaded.storageBlocked);assertNull(loaded.peerCertificate);}
        }
    }
    @Test public void legacyMemberBindingTransitionDropsOnlyCandidateBasisAndRestarts()throws Exception{
        var pair=LanProofRenewalTest.legacyPair();
        try(var administrator=pair[0].load(StorageGroupTest.CLOCK);var member=pair[1].load(StorageGroupTest.CLOCK)){
            f.storage().save(member);assertEquals(2,member.management.legacyAdministratorBasis.size());
            var proof=AdminControl.keyProof(member.groupId,new byte[16],0,administrator.identitySecret,administrator.administratorSecret);
            var list=AdminRecords.administrators(member.groupId,1,StorageGroupTest.NOW,List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode())),administrator.administratorSecret);
            try(var administration=new GroupAdministration(member.state,member.certificate,member.identitySecret,member.handshakeSecret,member.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
                var next=administration.received(list,member.state.revocations());
                administration.persist(next,s->{
                    assertFalse(member.state.administrators().hasAdminBindings());
                    f.storage().persistenceHooks(member).save(s);
                    assertFalse(member.state.administrators().hasAdminBindings());assertTrue(member.management.legacyAdministratorBasis.isEmpty());
                },c->{});
            }
            assertTrue(member.state.administrators().hasAdminBindings());
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertTrue(loaded.state.administrators().hasAdminBindings());assertTrue(loaded.management.legacyAdministratorBasis.isEmpty());assertFalse(loaded.storageBlocked);}
        }
    }
    @Test public void candidateLessActiveCannotClearThroughNormalSaveOrRecovery()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);var body=revocation(g,StoredUpdatesTest.key(81));
            f.marker.marker().active(new StopMarker.Target(g.saveSeq,body.version(),new byte[32],new byte[32],StopMarker.RECEIVED));
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertTrue(loaded.storageBlocked);var hooks=f.storage().persistenceHooks(loaded);
                assertThrows(Exception.class,()->f.storage().save(loaded));
                var request=f.request(loaded,body,true);
                assertThrows(RuntimeException.class,()->hooks.clear(request));
                var covers=CorePersistenceCoordinator.RecoveryRequirement.class.getDeclaredMethod("covers",AdminRecords.Record.class);covers.setAccessible(true);
                assertEquals(false,covers.invoke(loaded.recoveryRequirement,body));
                assertThrows(RuntimeException.class,()->hooks.active(request));
                assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            }
        }
    }
    @Test public void candidateLessActiveLayoutUsesZeroDigestsInBothSlots()throws Exception{
        var d=new StopMarkerTest.Disk();var marker=d.marker();marker.initialize(StopMarkerTest.target(1));
        marker.active(new StopMarker.Target(7,9,new byte[32],new byte[32],StopMarker.RECEIVED));
        for(int offset:new int[]{0,128}){
            var bytes=ByteBuffer.wrap(d.bytes,offset,128);assertEquals(0x4454534d,bytes.getInt());assertEquals(1,bytes.get());assertEquals(1,bytes.get());
            assertEquals(StopMarker.RECEIVED,bytes.get());assertEquals(0,bytes.get());assertEquals(offset==0?3:4,bytes.getLong());
            assertEquals(7,bytes.getLong());assertEquals(9,bytes.getLong());
            assertArrayEquals(new byte[64],Arrays.copyOfRange(d.bytes,offset+32,offset+96));
            assertArrayEquals(Crypto.blake2s(Arrays.copyOfRange(d.bytes,offset,offset+96)),Arrays.copyOfRange(d.bytes,offset+96,offset+128));
        }
        assertEquals(StopMarker.Status.ACTIVE,marker.inspect().status());
    }
}
