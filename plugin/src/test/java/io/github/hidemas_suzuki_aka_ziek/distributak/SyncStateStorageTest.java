// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class SyncStateStorageTest {
    final Clock clock=Clock.fixed(Instant.ofEpochMilli(10_000_000_000L),ZoneOffset.UTC);
    static final class Disk extends StateEnvelopeTest.MemoryTarget implements SyncStateStorage.Source {
        final ExternalStateStorageTest.Disk external=new ExternalStateStorageTest.Disk();
        final List<String> steps=new ArrayList<>();
        public boolean exists(){return value!=null;}
        public byte[] read(){return value.clone();}
        @Override public void commit(){super.commit();steps.add("sync");}
    }
    static SyncStateStorage storage(Disk disk) {var envelope=new StateEnvelope(new StateEnvelopeTest.TestCipher());return new SyncStateStorage(envelope,disk,disk,new ExternalStateStorage(envelope,disk.external,disk.external));}
    @Test public void initializesSyncBeforeMarkingTheGroupAndDoesNotRepeatInitialization()throws Exception {
        var disk=new Disk();
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            assertFalse(group.syncInitialized);
            var state=storage(disk).load(group,()->{assertTrue(disk.exists());assertTrue(disk.external.exists());assertTrue(group.syncInitialized);disk.steps.add("group");});
            assertEquals(List.of("sync","group"),disk.steps);assertEquals(0,state.uidCount());
            storage(disk).load(group,()->fail("already initialized"));assertEquals(2,disk.steps.size());
        }
    }
    @Test public void failedFlagCommitRestoresTheFlagAndRestartAdoptsTheValidInitialFile()throws Exception {
        var disk=new Disk();
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            assertThrows(IOException.class,()->storage(disk).load(group,()->{throw new IOException();}));
            assertFalse(group.syncInitialized);assertTrue(disk.exists());
            storage(disk).load(group,()->{});assertTrue(group.syncInitialized);assertEquals(List.of("sync"),disk.steps);
        }
    }
    @Test public void initializedButMissingOrCorruptSyncFailsClosedWithoutCreatingAnEmptyFile()throws Exception {
        var disk=new Disk();
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            group.syncInitialized=true;
            assertThrows(Exception.class,()->storage(disk).load(group,()->fail("flag")));assertNull(disk.value);
            disk.value=new byte[]{1,2,3};
            assertThrows(Exception.class,()->storage(disk).load(group,()->fail("flag")));assertArrayEquals(new byte[]{1,2,3},disk.value);
        }
    }
    @Test public void eitherInitializationFailureCanResumeButCommittedPairsCannotLoseEitherFile()throws Exception {
        for(boolean externalFailure:new boolean[]{true,false}){
            var disk=new Disk();try(var group=LanGroup.create(54321,clock,new SecureRandom())){
                if(externalFailure)disk.external.fail=true;else disk.fail=true;
                assertThrows(Exception.class,()->storage(disk).load(group,()->fail("must not mark incomplete pair")));assertFalse(group.syncInitialized);
                disk.external.fail=false;disk.fail=false;storage(disk).load(group,()->{});assertTrue(group.syncInitialized);assertTrue(disk.exists());assertTrue(disk.external.exists());
                byte[] sync=disk.value,external=disk.external.value;
                disk.external.value=null;assertThrows(Exception.class,()->storage(disk).load(group,()->fail("cannot replace missing external")));assertArrayEquals(sync,disk.value);
                disk.external.value=external;disk.value=null;assertThrows(Exception.class,()->storage(disk).load(group,()->fail("cannot replace missing sync")));assertArrayEquals(external,disk.external.value);
            }
        }
    }
    @Test public void oldExternalOriginRowsFailWithoutMigration()throws Exception {
        var disk=new Disk();try(var group=LanGroup.create(54321,clock,new SecureRandom())){
            var state=storage(disk).load(group,()->{});state.origin("legacy",SyncState.Origin.LOCAL_CREATED);
            byte[] plain=state.encode();assertEquals(2,plain[plain.length-1]);plain[plain.length-1]=4;
            disk.value=new StateEnvelope(new StateEnvelopeTest.TestCipher()).seal(plain);
            assertThrows(Exception.class,()->storage(disk).load(group,()->fail("cannot migrate")));
        }
    }
    @Test public void failedSaveLeavesThePreviousCommittedSnapshotReadable()throws Exception {
        var disk=new Disk();
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            var store=storage(disk);var state=store.load(group,()->{});
            byte[] previous=disk.value.clone();state.put(CotRecord.tombstone("test",clock.millis(),group.id(),0),clock.millis());
            disk.fail=true;assertThrows(Exception.class,()->store.save(group,state));assertArrayEquals(previous,disk.value);
            disk.fail=false;assertNull(store.load(group,()->fail("flag")).get("test"));
            store.save(group,state);assertNotNull(store.load(group,()->fail("flag")).get("test"));
        }
    }
    @Test public void anotherGroupCannotLoadOrSaveTheFirstGroupsSnapshot()throws Exception {
        var disk=new Disk();
        try(var a=LanGroup.create(54321,clock,new SecureRandom());var b=LanGroup.create(54322,clock,new SecureRandom())) {
            var store=storage(disk);var state=store.load(a,()->{});
            assertThrows(Exception.class,()->store.load(b,()->fail("flag")));
            assertThrows(Exception.class,()->store.save(b,state));assertFalse(b.syncInitialized);
        }
    }
    @Test public void versionTwoGroupsMigrateWithoutLosingKeysAndNewGroupsPersistTheFlag()throws Exception {
        try(var group=LanGroup.create(54321,clock,new SecureRandom())) {
            group.syncInitialized=true;byte[] current=group.encode();
            try(var restored=LanGroup.decode(current,clock)){assertTrue(restored.syncInitialized);}
            // v2には初期化済みの印・更新回数・保存番号・更新のMap・DHTの版がない（17+8バイト）。
            byte[] legacy=Arrays.copyOf(current,current.length-25);ByteBuffer.wrap(legacy).putInt(2);
            try(var restored=LanGroup.decode(legacy,clock)){
                assertFalse(restored.syncInitialized);assertArrayEquals(group.groupId,restored.groupId);assertArrayEquals(group.identitySecret,restored.identitySecret);
            }
            Crypto.wipe(current);Crypto.wipe(legacy);
        }
    }
}
