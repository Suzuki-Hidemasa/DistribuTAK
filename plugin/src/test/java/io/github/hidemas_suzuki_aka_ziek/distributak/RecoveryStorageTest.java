// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RecoveryStorageTest {
    final VersionSixStorageTest f=new VersionSixStorageTest();
    AdminRecords.Record body(LanGroup g,long version,List<byte[]> subjects){
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,version,StorageGroupTest.NOW,subjects,g.administratorSecret);
    }
    void stop(LanGroup g)throws Exception{
        f.marker.marker().active(new StopMarker.Target(g.saveSeq,2,new byte[32],new byte[32],StopMarker.RECEIVED));
    }
    @Test public void candidateLessRequirementCoversSavedUnion()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var id=StoredUpdatesTest.key(81);g.state.acceptRevocations(body(g,1,List.of(id)));f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertNotNull(loaded.recoveryRequirement.subjects());
                assertTrue(ManagementState.sameSubjects(List.of(id),loaded.recoveryRequirement.subjects()));
                assertArrayEquals(new byte[32],loaded.recoveryRequirement.digest());
            }
        }
    }
    @Test public void candidateLessRecoverySavesAndClears()throws Exception{recover(0);}
    @Test public void candidateLessRecoveryCrashBeforeNewActiveRevalidatesProof()throws Exception{recover(1);}
    @Test public void candidateLessRecoveryCrashDuringNewActiveRevalidatesProof()throws Exception{recover(2);}
    void recover(int crash)throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var id=StoredUpdatesTest.key(81);g.state.acceptRevocations(body(g,1,List.of(id)));f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                var request=f.request(loaded,body(g,2,List.of(id,StoredUpdatesTest.key(82))),true);
                byte[] active=f.marker.bytes.clone();var hooks=f.storage().persistenceHooks(loaded);
                hooks.active(request);assertArrayEquals(active,f.marker.bytes);hooks.save(request);assertArrayEquals(active,f.marker.bytes);
                if(crash==0)hooks.clear(request);
                if(crash==2){f.marker.failWrites=3;assertThrows(RuntimeException.class,()->hooks.clear(request));f.marker.failWrites=0;}
                try(var restarted=f.storage().load(StorageGroupTest.CLOCK)){
                    assertFalse(restarted.storageBlocked);assertNull(restarted.recoveryRequirement);
                    assertEquals(2,restarted.state.revocations().version());assertEquals(2,restarted.state.revokedSubjects().size());
                    assertEquals(StopMarker.Status.CLEAR,f.marker.marker().inspect().status());
                }
            }
        }
    }
    @Test public void blockedStageCannotCreateCandidate()throws Exception{
        try(var g=f.group()){
            f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertThrows(Exception.class,()->f.storage().stage(loaded,f.f.temporary,()->f.f.temporary.value,()->{}));
                assertNull(f.f.temporary.value);
            }
        }
    }
    @Test public void blockedSnapshotCannotOverwriteSavedState()throws Exception{
        try(var g=f.group()){
            f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                byte[] before=f.f.state.value.clone();
                assertThrows(RuntimeException.class,()->f.storage().persistenceHooks(loaded).save(loaded.state.snapshot()));
                assertArrayEquals(before,f.f.state.value);
            }
        }
    }
    @Test public void blockedActiveCannotOverwriteCandidateLessRequirement()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                byte[] before=f.marker.bytes.clone();var r=f.request(loaded,body(g,3,List.of()),false);
                assertThrows(RuntimeException.class,()->f.storage().persistenceHooks(loaded).active(r));
                assertArrayEquals(before,f.marker.bytes);
            }
        }
    }
    @Test public void activeCannotOverwriteCandidateLessEvenWithoutMemoryFlag()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);stop(g);byte[] before=f.marker.bytes.clone();
            var r=f.request(g,body(g,3,List.of()),false);
            assertThrows(RuntimeException.class,()->f.storage().persistenceHooks(g).active(r));
            assertArrayEquals(before,f.marker.bytes);
        }
    }
    @Test public void pendingRenewalWithSupersededBaseDoesNotChangeCrashCandidateDigest()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            g.peerCertificate=StoredUpdatesTest.peer(g,71,72,StorageGroupTest.NOW-1);
            g.peerAddress=new java.net.InetSocketAddress(java.net.InetAddress.getByAddress(new byte[]{(byte)192,0,2,1}),54322);
            byte[] id=Crypto.blake2s(g.peerCertificate.field(0));
            var renewal=StoredUpdatesTest.peer(g,71,72,StorageGroupTest.NOW);
            g.rememberRenewal(id,renewal.encode());g.peerCertificate=renewal;
            f.storage().save(g);var request=f.request(g,body(g,1,List.of()),false);var hooks=f.storage().persistenceHooks(g);
            hooks.active(request);hooks.save(request);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                assertFalse(loaded.storageBlocked);assertNull(loaded.pendingRenewal(id));
                assertEquals(UdpEndpoint.CloseReason.INTERNAL_FAILURE,loaded.pendingRenewalReason());
            }
        }
    }
    @Test public void recoveryWithoutPersistedUnionProofIsRejected()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var id=StoredUpdatesTest.key(81);g.state.acceptRevocations(body(g,1,List.of(id)));f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                loaded.recoveryRequirement=CorePersistenceCoordinator.RecoveryRequirement.candidateLess(2,List.of());
                var request=f.request(loaded,body(g,2,List.of(id)),true);
                assertThrows(RuntimeException.class,()->f.storage().persistenceHooks(loaded).active(request));
                assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            }
        }
    }
    @Test public void recoveryWithInsufficientVersionDoesNotWriteCheckpoint()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                byte[] before=f.f.state.value.clone();var request=f.request(loaded,body(g,1,List.of()),true);
                assertThrows(RuntimeException.class,()->f.storage().persistenceHooks(loaded).active(request));assertArrayEquals(before,f.f.state.value);
            }
        }
    }
    @Test public void recoveryFullDiskKeepsOriginalCandidateLessMarker()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                byte[] before=f.marker.bytes.clone();var request=f.request(loaded,body(g,2,List.of()),true);
                var hooks=f.storage().persistenceHooks(loaded);hooks.active(request);f.files.space=false;
                assertThrows(RuntimeException.class,()->hooks.save(request));hooks.stopped();assertArrayEquals(before,f.marker.bytes);
                try(var restarted=f.storage().load(StorageGroupTest.CLOCK)){assertTrue(restarted.storageBlocked);assertNotNull(restarted.recoveryRequirement);}
            }
        }
    }
    @Test public void initialMarkerRequiresDirectorySynchronization()throws Exception{
        var path=java.nio.file.Files.createTempFile("distributak-marker-sync-",".bin");int[] calls={0};
        try{
            var marker=new StopMarker(new StopMarker.FileRegion(path.toFile(),()->{calls[0]++;throw new java.io.IOException("injected directory sync failure");}),millis->{});
            assertThrows(java.io.IOException.class,()->marker.initializeMigration(StopMarkerTest.target(1)));
            assertEquals(3,calls[0]);assertEquals(StopMarker.Status.INVALID,marker.inspect().status());
        }finally{java.nio.file.Files.delete(path);}
    }
    @Test public void formatTwoWithoutPreviousTargetIsRejected()throws Exception{rejectUnrelatedBasis(false);}
    @Test public void formatTwoWithOrdinaryPreviousTargetIsRejected()throws Exception{rejectUnrelatedBasis(true);}
    void rejectUnrelatedBasis(boolean previous)throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            f.storage().save(g);var cp=g.management.checkpoint;
            var changed=new ManagementState.Checkpoint(cp.number,cp.generation,cp.prefix,cp.administratorVersion,cp.revocationVersion,
                    cp.winner,cp.received,cp.target,previous?cp.target:null,List.of()).basis(g.state.snapshot());
            byte[] plain=g.management.checkpoint(changed).encode(false);
            assertEquals(2,java.nio.ByteBuffer.wrap(plain).getInt());
            assertThrows(java.io.IOException.class,()->ManagementState.decode(plain));
        }
    }
    @Test public void candidateLessRecoveryCrashAfterManagementKeepsOriginalStop()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var id=StoredUpdatesTest.key(81);g.state.acceptRevocations(body(g,1,List.of(id)));f.storage().save(g);stop(g);
            byte[] originalState=f.f.state.value.clone(),originalMarker=f.marker.bytes.clone();
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                var request=f.request(loaded,body(g,2,List.of(id,StoredUpdatesTest.key(82))),true);var hooks=f.storage().persistenceHooks(loaded);
                hooks.active(request);f.f.state.fail=true;
                assertThrows(RuntimeException.class,()->hooks.save(request));hooks.stopped();f.f.state.fail=false;
                assertEquals(2,f.files.values.size());assertArrayEquals(originalState,f.f.state.value);assertArrayEquals(originalMarker,f.marker.bytes);
            }
            try(var restarted=f.storage().load(StorageGroupTest.CLOCK)){
                assertTrue(restarted.storageBlocked);assertNotNull(restarted.recoveryRequirement);assertEquals(1,restarted.state.revocations().version());
                assertTrue(f.marker.marker().inspect().target().candidateLess());assertEquals(2,restarted.recoveryRequirement.version());
                assertTrue(ManagementState.sameSubjects(List.of(id),restarted.recoveryRequirement.subjects()));
            }
        }
    }
    @Test public void candidateLessRecoverySettingsFailureRevalidatesSavedProof()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var id=StoredUpdatesTest.key(81);g.state.acceptRevocations(body(g,1,List.of(id)));f.storage().save(g);stop(g);
            byte[] active=f.marker.bytes.clone(),settings=f.f.settings.value.clone();
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                var request=f.request(loaded,body(g,2,List.of(id,StoredUpdatesTest.key(82))),true);var hooks=f.storage().persistenceHooks(loaded);
                hooks.active(request);f.f.settings.fail=true;
                hooks.save(request);hooks.stopped();f.f.settings.fail=false;
                assertArrayEquals(settings,f.f.settings.value);assertTrue(f.f.logs.contains("LAN_SETTINGS_SAVE_FAILED"));
                assertArrayEquals(active,f.marker.bytes);
            }
            try(var restarted=f.storage().load(StorageGroupTest.CLOCK)){
                assertFalse(restarted.storageBlocked);assertNull(restarted.recoveryRequirement);assertEquals(2,restarted.state.revocations().version());
                assertNotNull(restarted.management.checkpoint.basisWinner);
                assertEquals(restarted.saveSeq,StateSettings.decode(f.f.settings.value).saveSeq);
                assertEquals(StopMarker.Status.CLEAR,f.marker.marker().inspect().status());
            }
        }
    }
    @Test public void candidateLessRecoveryCrashDuringClearRevalidatesSavedProof()throws Exception{
        int[] clears={0};
        var region=new StopMarker.Region(){
            public byte[] read(){return f.marker.read();}
            public void allocate()throws java.io.IOException{f.marker.allocate();}
            public void write(int offset,byte[] value)throws java.io.IOException{
                if(value[5]==0&&clears[0]++>0)throw new java.io.IOException("injected partial clear");
                f.marker.write(offset,value);
            }
            public void sync()throws java.io.IOException{f.marker.sync();}
        };
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var id=StoredUpdatesTest.key(81);g.state.acceptRevocations(body(g,1,List.of(id)));f.storage().save(g);stop(g);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){
                var storage=new GroupStateStorage(f.f.envelope,f.f.state,f.f.state,f.f.settings,f.f.settings,f.f.logs::add,f.files,new StopMarker(region,millis->{}));
                var request=f.request(loaded,body(g,2,List.of(id,StoredUpdatesTest.key(82))),true);var hooks=storage.persistenceHooks(loaded);
                hooks.active(request);hooks.save(request);assertThrows(RuntimeException.class,()->hooks.clear(request));hooks.stopped();
                assertTrue(clears[0]>1);assertEquals(StopMarker.Status.ACTIVE,f.marker.marker().inspect().status());
            }
            try(var restarted=f.storage().load(StorageGroupTest.CLOCK)){
                assertFalse(restarted.storageBlocked);assertNull(restarted.recoveryRequirement);assertEquals(2,restarted.state.revocations().version());
                assertNotNull(restarted.management.checkpoint.basisWinner);assertTrue(restarted.management.checkpoint.previous.candidateLess());
                assertEquals(StopMarker.Status.CLEAR,f.marker.marker().inspect().status());
            }
        }
    }
}
