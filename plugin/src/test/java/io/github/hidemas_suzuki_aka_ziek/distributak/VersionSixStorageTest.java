// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class VersionSixStorageTest {
    static final class Files implements ManagementFiles {
        final TreeMap<Long,byte[]> values=new TreeMap<>();
        long next;
        boolean fail,space=true;
        public long nextGeneration(){return ++next;}
        public void write(long generation,byte[] wire)throws IOException{
            if(fail)throw new IOException("injected management failure");
            if(values.putIfAbsent(generation,wire.clone())!=null)throw new IOException("immutable generation");
        }
        public byte[] read(long generation)throws IOException{
            byte[] value=values.get(generation);if(value==null)throw new IOException("missing generation");return value.clone();
        }
        public boolean hasSpace(long bytes){return space;}
        public void cleanup(long retained){values.keySet().removeIf(v->v!=retained);}
    }
    final GroupStateStorageTest f=new GroupStateStorageTest();
    final Files files=new Files();
    final StopMarkerTest.Disk marker=new StopMarkerTest.Disk();
    GroupStateStorage storage(){return new GroupStateStorage(f.envelope,f.state,f.state,f.settings,f.settings,f.logs::add,files,marker.marker());}
    LanGroup group()throws Exception{return LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,true);}
    @Test public void readingVersionFiveDoesNotMigrateUntilNextSuccessfulSave()throws Exception{
        try(var g=group()){
            g.syncInitialized=true;g.renewalCount=4;g.dhtLocalVersion=9;f.storage().save(g);byte[] before=f.state.value.clone();
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertArrayEquals(before,f.state.value);assertTrue(files.values.isEmpty());assertNull(marker.bytes);
                storage().save(loaded);assertEquals(6,ByteBuffer.wrap(f.envelope.open(f.state.value)).getInt());
                assertEquals(3,ByteBuffer.wrap(f.settings.value).getInt(4));
                try(var restored=storage().load(StorageGroupTest.CLOCK)){
                    assertArrayEquals(g.identitySecret,restored.identitySecret);assertArrayEquals(g.handshakeSecret,restored.handshakeSecret);
                    assertArrayEquals(g.administratorSecret,restored.administratorSecret);assertArrayEquals(g.groupKey,restored.groupKey);
                    assertArrayEquals(g.certificate.encode(),restored.certificate.encode());assertEquals(2,restored.saveSeq);
                    assertEquals(9,restored.dhtLocalVersion);assertEquals(4,restored.renewalCount);assertTrue(restored.syncInitialized);
                }
            }
        }
    }
    @Test public void versionsTwoThreeAndFourRemainReadableWithoutWrites()throws Exception{
        for(int v=2;v<=4;v++){
            byte[] fixture;
            if(v<4)fixture=StorageGroupTest.fixture(v,"valid");
            else try(var source=group()){byte[] five=source.encode();fixture=Arrays.copyOf(five,five.length-8);ByteBuffer.wrap(fixture).putInt(4);}
            f.state.value=f.envelope.seal(fixture);f.settings.value=null;byte[] original=f.state.value.clone();
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertArrayEquals(original,f.state.value);assertEquals(0,loaded.dhtLocalVersion);}
        }
        assertTrue(files.values.isEmpty());
    }
    @Test public void failedManagementWritePreservesVersionFiveAndSequence()throws Exception{
        try(var g=group()){
            f.storage().save(g);byte[] old=f.state.value.clone();files.fail=true;
            assertThrows(Exception.class,()->storage().save(g));assertArrayEquals(old,f.state.value);assertEquals(1,g.saveSeq);
        }
    }
    @Test public void failedStateSwitchRetainsPreviouslyReferencedManagementGeneration()throws Exception{
        try(var g=group()){
            storage().save(g);byte[] state=f.state.value.clone(),settings=f.settings.value.clone();long old=g.managementGeneration;
            f.state.fail=true;assertThrows(Exception.class,()->storage().save(g));
            assertArrayEquals(state,f.state.value);assertArrayEquals(settings,f.settings.value);assertTrue(files.values.containsKey(old));
            f.state.fail=false;try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.saveSeq);}
        }
    }
    @Test public void settingsOnlyFailureUsesCommittedStateAndRepairsOnLoad()throws Exception{
        try(var g=group()){
            storage().save(g);f.settings.fail=true;storage().save(g);assertEquals(2,g.saveSeq);f.settings.fail=false;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(2,loaded.saveSeq);}
            assertEquals(2,StateSettings.decode(f.settings.value).saveSeq);
        }
    }
    @Test public void ordinarySaveKeepsCheckpointAndOldClearValid()throws Exception{
        try(var g=group()){
            storage().save(g);byte[] original=marker.bytes.clone();long checkpoint=g.management.checkpoint.number;
            storage().save(g);storage().reserveDhtVersion(g);
            assertArrayEquals(original,marker.bytes);assertEquals(checkpoint,g.management.checkpoint.number);
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertFalse(loaded.storageBlocked);assertNull(loaded.recoveryRequirement);}
        }
    }
    @Test public void missingReferencedGenerationNeverLoadsAnOrphan()throws Exception{
        try(var g=group()){
            storage().save(g);long old=g.managementGeneration;storage().save(g);files.values.remove(g.managementGeneration);
            assertThrows(Exception.class,()->storage().load(StorageGroupTest.CLOCK));assertFalse(files.values.containsKey(old));
        }
    }
    @Test public void corruptedManagementEnvelopeIsRejected()throws Exception{
        try(var g=group()){
            storage().save(g);byte[] bytes=files.values.get(g.managementGeneration);bytes[bytes.length-1]^=1;
            assertThrows(Exception.class,()->storage().load(StorageGroupTest.CLOCK));
        }
    }
    @Test public void stateRollbackIsDetectedBySettings()throws Exception{
        try(var g=group()){
            storage().save(g);byte[] old=f.state.value.clone();byte[] oldManagement=files.values.get(g.managementGeneration).clone();long oldGen=g.managementGeneration;
            storage().save(g);files.values.put(oldGen,oldManagement);f.state.value=old;
            assertThrows(StateSettings.Rollback.class,()->storage().load(StorageGroupTest.CLOCK));
        }
    }
    @Test public void sameSequenceWithDifferentManagementDigestIsRejected()throws Exception{
        try(var g=group()){
            storage().save(g);byte[] config=f.settings.value.clone();config[config.length-1]^=1;f.settings.value=config;
            assertThrows(StateSettings.Rollback.class,()->storage().load(StorageGroupTest.CLOCK));
        }
    }
    @Test public void unavailableSpaceAbortsWithoutChangingState()throws Exception{
        try(var g=group()){
            storage().save(g);byte[] old=f.state.value.clone();files.space=false;
            assertThrows(Exception.class,()->storage().save(g));assertArrayEquals(old,f.state.value);assertEquals(1,g.saveSeq);
        }
    }
    @Test public void markerAllocationFailureDoesNotCommitVersionSix()throws Exception{
        try(var g=group()){
            f.storage().save(g);byte[] old=f.state.value.clone();marker.failAllocation=true;
            assertThrows(Exception.class,()->storage().save(g));assertArrayEquals(old,f.state.value);
        }
    }
    @Test public void signedUnionHistorySurvivesRestartWithoutShrinkingToWinner()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var high=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,2,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret);
            var low=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(82)),g.administratorSecret);
            g.state.acceptRevocations(high);g.state.acceptRevocations(low);storage().save(g);
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertEquals(2,loaded.state.revokedSubjects().size());assertEquals(2,loaded.state.revocations().version());
                assertEquals(g.state.snapshot().records().size(),loaded.state.snapshot().records().size());
            }
        }
    }
    @Test public void receivedRevocationUsesActiveSaveClearAndSurvivesRestart()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            storage().save(g);var union=new RevocationUnion(g.groupId,new AdminStateTrust(g.state));
            var coordinator=new CorePersistenceCoordinator(g.state,sessions,union,StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret);
            assertTrue(coordinator.receiveRevocations(body,storage().persistenceHooks(g)));
            assertEquals(StopMarker.Status.CLEAR,marker.marker().inspect().status());
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.state.revocations().version());assertFalse(loaded.storageBlocked);}
        }
    }
    @Test public void committedRevocationsBeforeClearAreVerifiedAndClearedAtStartup()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            storage().save(g);var union=new RevocationUnion(g.groupId,new AdminStateTrust(g.state));
            var c=new CorePersistenceCoordinator(g.state,sessions,union,StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            var delegate=storage().persistenceHooks(g);var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(),g.administratorSecret);
            assertFalse(c.receiveRevocations(body,new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail();}
                public void active(CorePersistenceCoordinator.PersistenceRequest r){delegate.active(r);}
                public void save(CorePersistenceCoordinator.PersistenceRequest r){delegate.save(r);}
                public void clear(CorePersistenceCoordinator.PersistenceRequest r){throw new IllegalStateException("injected crash before clear");}
            }));
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.state.revocations().version());assertFalse(loaded.storageBlocked);}
            assertEquals(StopMarker.Status.CLEAR,marker.marker().inspect().status());
        }
    }
    @Test public void activeWithUncommittedRevocationsKeepsOldStateInLimitedRecovery()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            storage().save(g);var union=new RevocationUnion(g.groupId,new AdminStateTrust(g.state));
            var c=new CorePersistenceCoordinator(g.state,sessions,union,StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            files.fail=true;var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret);
            assertFalse(c.receiveRevocations(body,storage().persistenceHooks(g)));files.fail=false;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertEquals(0,loaded.state.revocations().version());assertNotNull(loaded.recoveryRequirement);assertEquals(1,loaded.recoveryRequirement.version());
            }
            assertEquals(StopMarker.Status.ACTIVE,marker.marker().inspect().status());
        }
    }
    @Test public void invalidMarkerStopsWithoutInferringRecoveryRequirements()throws Exception{
        try(var g=group()){
            storage().save(g);marker.bytes[0]^=1;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertTrue(loaded.storageBlocked);assertNull(loaded.recoveryRequirement);}
        }
    }
    @Test public void historyCountAndByteLimitsRejectWithoutPruning()throws Exception{
        var snapshot=new AdminRecordStore.Snapshot(Collections.nCopies(65_537,new byte[]{1}),new byte[64],new byte[]{1},0,0);
        assertThrows(IOException.class,()->ManagementState.checkHistory(snapshot));
        var oversized=new AdminRecordStore.Snapshot(List.of(new byte[12*1024*1024]),new byte[64],new byte[]{1},0,0);
        assertThrows(IOException.class,()->ManagementState.checkHistory(oversized));
    }
    @Test public void managementEnvelopeBudgetIncludesHeaderIvAndTag(){
        assertEquals(16*1024*1024+38,ManagementState.MAX_ENVELOPE_BYTES);
    }
    CorePersistenceCoordinator.PersistenceRequest request(LanGroup g,AdminRecords.Record body,boolean recovery)throws Exception{
        var prepared=LanGroup.restore(g.groupId,g.urlAdmin,g.state.snapshot(),StorageGroupTest.CLOCK);
        try{prepared.acceptRevocations(body);return new CorePersistenceCoordinator.PersistenceRequest(prepared.snapshot(),body,true,recovery,g.recoveryRequirement);}
        finally{prepared.clear();}
    }
    @Test public void migrationCanRetryAfterManagementFailureWithoutDeletingInitialRegion()throws Exception{
        try(var g=group()){
            f.storage().save(g);files.fail=true;assertThrows(Exception.class,()->storage().save(g));
            byte[] region=marker.bytes;files.fail=false;storage().save(g);assertSame(region,marker.bytes);
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertFalse(loaded.storageBlocked);}
        }
    }
    @Test public void abortedVersionSixStageCanBeRetriedAndCommitted()throws Exception{
        try(var g=group()){
            var source=storage();var pending=source.stage(g,f.temporary,()->f.temporary.value.clone(),()->f.temporary.value=null);
            assertNull(f.state.value);pending.abort();assertEquals(0,g.saveSeq);
            var next=source.stage(g,f.temporary,()->f.temporary.value.clone(),()->f.temporary.value=null);next.commit();
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(6,ByteBuffer.wrap(f.envelope.open(f.state.value)).getInt());assertFalse(loaded.storageBlocked);}
        }
    }
    @Test public void recoverySaveThenCrashBeforeNewActiveUsesOriginalRequirement()throws Exception{
        recoveryCrash(false,false);
    }
    @Test public void recoveryCrashDuringNewActiveUsesSavedRecoveryProof()throws Exception{
        recoveryCrash(true,false);
    }
    @Test public void recoveryAcceptsProvenSupersetWithoutPretendingOldStateDigestMatches()throws Exception{
        recoveryCrash(false,true);
    }
    void recoveryCrash(boolean activeFailure,boolean superset)throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            if(superset)g.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret));
            storage().save(g);
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,2,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret);
            var hooks=storage().persistenceHooks(g);var original=request(g,body,false);hooks.active(original);
            files.fail=true;assertThrows(RuntimeException.class,()->hooks.save(original));hooks.stopped();files.fail=false;
            byte[] active=marker.bytes.clone();
            try(var recovering=storage().load(StorageGroupTest.CLOCK)){
                assertNotNull(recovering.recoveryRequirement);
                var fresh=superset?AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,3,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81),StoredUpdatesTest.key(82)),g.administratorSecret):body;
                var r=request(recovering,fresh,true);var recovery=storage().persistenceHooks(recovering);
                recovery.active(r);assertArrayEquals(active,marker.bytes);recovery.save(r);assertArrayEquals(active,marker.bytes);
                if(activeFailure){marker.failWrites=3;assertThrows(RuntimeException.class,()->recovery.clear(r));}
            }
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertFalse(loaded.storageBlocked);assertNull(loaded.recoveryRequirement);assertEquals(superset?3:2,loaded.state.revocations().version());
            }
            assertEquals(StopMarker.Status.CLEAR,marker.marker().inspect().status());
        }
    }
    @Test public void stateAndSettingsRollbackAfterReceivedCheckpointCannotUseNewClear()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            storage().save(g);byte[] state=f.state.value.clone(),settings=f.settings.value.clone();long generation=g.managementGeneration;
            byte[] management=files.values.get(generation).clone();
            var c=new CorePersistenceCoordinator(g.state,sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(),g.administratorSecret);
            assertTrue(c.receiveRevocations(body,storage().persistenceHooks(g)));f.state.value=state;f.settings.value=settings;files.values.put(generation,management);
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertTrue(loaded.storageBlocked);assertNull(loaded.recoveryRequirement);}
        }
    }

    @Test public void rotationPersistsKeyAnnouncementQueueAndReservationsTogether()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0);
            var administration=new GroupAdministration(g.state,g.certificate,g.identitySecret,g.handshakeSecret,g.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
            var rotation=administration.rotations(sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),new MonotonicClock(()->0));
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(List.of(),List.of(g.certificate),storage().persistenceHooks(g)));
            assertEquals(1,g.keyVersion);byte[] key=g.groupKey.clone(),announcement=g.state.snapshot().announcement();
            try(var loaded=storage().load(StorageGroupTest.CLOCK);var restoredSessions=loaded.sessions(StorageGroupTest.CLOCK,()->0);
                var restored=new GroupAdministration(loaded.state,loaded.certificate,loaded.identitySecret,loaded.handshakeSecret,loaded.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
                assertArrayEquals(key,loaded.groupKey);assertArrayEquals(announcement,loaded.state.snapshot().announcement());
                var result=restored.rotations(restoredSessions,new RevocationUnion(loaded.groupId,new AdminStateTrust(loaded.state)),new MonotonicClock(()->0));
                loaded.management.restoreRotation(loaded,result);assertEquals(1,result.reservedKeyVersion());assertNotNull(result.publication());
                assertEquals(1,result.publication().envelopes().size());
            }finally{Crypto.wipe(key);}
        }
    }
    @Test public void reservationSurvivesRestartEvenWithoutSignedPublication()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            storage().persistenceHooks(g).reserveRotationVersions(7,9);
            try(var loaded=storage().load(StorageGroupTest.CLOCK);var sessions=loaded.sessions(StorageGroupTest.CLOCK,()->0);
                var administration=new GroupAdministration(loaded.state,loaded.certificate,loaded.identitySecret,loaded.handshakeSecret,loaded.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
                var rotation=administration.rotations(sessions,new RevocationUnion(loaded.groupId,new AdminStateTrust(loaded.state)),new MonotonicClock(()->0));
                loaded.management.restoreRotation(loaded,rotation);assertEquals(7,rotation.reservedKeyVersion());assertEquals(9,rotation.reservedRevocationVersion());assertNull(rotation.publication());
            }
        }
    }

    @Test public void savedRosterAndLocalLabelsSurviveRestartWithoutInventingMembers()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            var directory=new MemberDirectory(g.state);directory.saved(g.certificate);var peer=StoredUpdatesTest.peer(g,71,72,StorageGroupTest.NOW);
            directory.saved(peer);String identity=Base64.getEncoder().encodeToString(peer.field(0));
            storage().saveDirectory(g,directory,Map.of(identity,"local label"));
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertEquals(2,loaded.management.roster.size());assertEquals("local label",loaded.management.aliases.get(identity));
            }
        }
    }
    @Test public void rosterRejectsLabelsForUnknownMembersWithoutChangingState()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            storage().save(g);byte[] old=f.state.value.clone();var directory=new MemberDirectory(g.state);directory.saved(g.certificate);
            assertThrows(Exception.class,()->storage().saveDirectory(g,directory,Map.of("unknown","local label")));assertArrayEquals(old,f.state.value);
        }
    }

    @Test public void bothLegacyVersionFivePeersRetainAllFieldsAndSeparateCotBytes()throws Exception{
        var pair=LanProofRenewalTest.legacyPair();
        for(var disk:pair)try(var original=disk.load(StorageGroupTest.CLOCK)){
            byte[] sync=disk.sync.value.clone();f.state.value=disk.state.value.clone();f.settings.value=disk.settings.value.clone();
            try(var migrating=storage().load(StorageGroupTest.CLOCK)){
                assertEquals(0,migrating.managementGeneration);storage().save(migrating);
                try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                    original.saveSeq=loaded.saveSeq;assertArrayEquals(original.encode(),loaded.encode());
                    assertArrayEquals(sync,disk.sync.value);
                    if(!loaded.isAdministrator())assertEquals(2,loaded.management.legacyAdministratorBasis.size());
                }
            }
        }
    }
    @Test public void ordinarySelfRenewalKeepsLegacyAdministratorBasisAndExactPermissions()throws Exception{
        var pair=LanProofRenewalTest.legacyPair();
        try(var administrator=pair[0].load(StorageGroupTest.CLOCK);var member=pair[1].load(StorageGroupTest.CLOCK)){
            storage().save(member);var basis=member.management.legacyAdministratorBasis;var permissions=member.management.legacyPermissions;
            var certificate=AdminRecords.certificate(member.groupId,member.certificate.field(0),member.certificate.field(1),
                    SignaturePurpose.identityProof(member.identitySecret,member.groupId,member.certificate.field(1)),StorageGroupTest.NOW+1,administrator.administratorSecret);
            storage().saveLocalRenewal(member,certificate);
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertEquals(2,loaded.certificate.format());assertEquals(2,loaded.management.legacyAdministratorBasis.size());
                assertArrayEquals(basis.get(0),loaded.management.legacyAdministratorBasis.get(0));assertArrayEquals(basis.get(1),loaded.management.legacyAdministratorBasis.get(1));
                for(byte[] exact:permissions)assertTrue(loaded.management.legacyPermissions.stream().anyMatch(value->Arrays.equals(exact,value)));
                try(var administration=new GroupAdministration(loaded.state,loaded.certificate,loaded.identitySecret,loaded.handshakeSecret,
                        loaded.administratorSecret,StorageGroupTest.CLOCK,()->0,new java.security.SecureRandom())){
                    administration.restoreLegacyAdministratorBasis(loaded.management.legacyAdministratorBasis);assertEquals(2,administration.legacyAdministratorBasis().size());
                }
            }
        }
    }

    @Test public void settingsVersionThreeComparesEveryAddedFieldAtEqualSequence()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom())){
            storage().save(g);byte[] valid=f.settings.value.clone();
            for(int offset:new int[]{45,53,85,117,125}){
                f.settings.value=valid.clone();f.settings.value[offset+7]^=2;
                assertThrows(StateSettings.Rollback.class,()->storage().load(StorageGroupTest.CLOCK));
            }
            f.settings.value=valid;
        }
    }
    @Test public void candidateDigestUsesFixedLabelAndBigEndianLengthFraming()throws Exception{
        byte[] label="DistribuTAK/state-candidate/v6".getBytes(java.nio.charset.StandardCharsets.US_ASCII),state={1,2},management={3,4,5};
        byte[] expected=ByteBuffer.allocate(12+label.length+5).putInt(label.length).put(label).putInt(2).put(state).putInt(3).put(management).array();
        assertArrayEquals(Crypto.blake2s(expected),VersionSixStorage.candidateDigest(state,management));
    }

    @Test public void legacyNetworkStartRequiresMarkerAllocationButDoesNotMigrateState()throws Exception{
        try(var g=group()){
            f.storage().save(g);byte[] original=f.state.value.clone();marker.failAllocation=true;
            assertThrows(Exception.class,()->storage().prepareNetwork(g));assertArrayEquals(original,f.state.value);assertEquals(0,g.managementGeneration);
            marker.failAllocation=false;storage().prepareNetwork(g);assertEquals(256,marker.bytes.length);assertArrayEquals(original,f.state.value);
        }
    }
    @Test public void partialInitialRegionCanBeReallocatedUsingVerifiedLegacyState()throws Exception{
        try(var g=group()){
            f.storage().save(g);byte[] original=f.state.value.clone();marker.bytes=new byte[256];marker.bytes[0]=68;
            storage().prepareNetwork(g);assertEquals(StopMarker.Status.CLEAR,marker.marker().inspect().status());assertArrayEquals(original,f.state.value);
            storage().save(g);try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertFalse(loaded.storageBlocked);}
        }
    }
    @Test public void receivingRevocationAfterFailedInitialAllocationStopsAllSessions()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            f.storage().save(g);marker.failAllocation=true;assertThrows(Exception.class,()->storage().save(g));
            var coordinator=new CorePersistenceCoordinator(g.state,sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret);
            assertFalse(coordinator.receiveRevocations(body,storage().persistenceHooks(g)));assertTrue(sessions.isClosed());
            assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,coordinator.state());assertEquals("保存がいっぱい",coordinator.statusText());
            assertEquals(5,ByteBuffer.wrap(f.envelope.open(f.state.value)).getInt());
        }
    }

    @Test public void firstRevocationDuringLegacyMigrationMarksActiveBeforeAnyManagementWrite()throws Exception{
        try(var g=LanGroup.create(54321,StorageGroupTest.CLOCK,new java.security.SecureRandom());var sessions=g.sessions(StorageGroupTest.CLOCK,()->0)){
            f.storage().save(g);byte[] legacy=f.state.value.clone();storage().prepareNetwork(g);files.fail=true;
            var coordinator=new CorePersistenceCoordinator(g.state,sessions,new RevocationUnion(g.groupId,new AdminStateTrust(g.state)),StorageGroupTest.CLOCK,new MonotonicClock(()->0));
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,g.groupId,1,StorageGroupTest.NOW,List.of(StoredUpdatesTest.key(81)),g.administratorSecret);
            assertFalse(coordinator.receiveRevocations(body,storage().persistenceHooks(g)));assertArrayEquals(legacy,f.state.value);
            assertEquals(StopMarker.Status.ACTIVE,marker.marker().inspect().status());files.fail=false;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){
                assertTrue(loaded.storageBlocked);assertNotNull(loaded.recoveryRequirement);assertEquals(1,loaded.recoveryRequirement.version());
                var recovery=storage().persistenceHooks(loaded);var request=request(loaded,body,true);
                recovery.active(request);recovery.save(request);recovery.clear(request);
            }
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.state.revocations().version());assertFalse(loaded.storageBlocked);}
        }
    }

}
