// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.nio.ByteBuffer;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class GroupStateStorageTest {
    final StateEnvelope envelope=new StateEnvelope(new StateEnvelopeTest.TestCipher());
    static class File extends StateEnvelopeTest.MemoryTarget implements SyncStateStorage.Source {
        public boolean exists(){return value!=null;}
        public byte[] read(){return value.clone();}
    }
    final File state=new File(),settings=new File(),temporary=new File();
    final List<String> logs=new ArrayList<>();
    GroupStateStorage storage(){return new GroupStateStorage(envelope,state,state,settings,settings,logs::add);}
    @Test public void legacyFirstSaveFailureLeavesVersionThreeBytesUntilSuccessfulMigration()throws Exception {
        state.value=envelope.seal(StorageGroupTest.fixture(3,"valid"));byte[] old=state.value.clone();
        try(var group=storage().load(StorageGroupTest.CLOCK)) {
            state.fail=true;assertThrows(Exception.class,()->storage().save(group));assertEquals(0,group.saveSeq);assertArrayEquals(old,state.value);
            assertEquals(3,ByteBuffer.wrap(envelope.open(state.value)).getInt());state.fail=false;storage().save(group);
            assertEquals(5,ByteBuffer.wrap(envelope.open(state.value)).getInt());
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.saveSeq);}
        }
    }
    @Test public void settingsVersionOneReadsWithZeroWatermarks()throws Exception {
        byte[] old=ByteBuffer.allocate(13).putInt(0x44544346).putInt(1).putInt(54321).put((byte)0).array();
        var decoded=StateSettings.decode(old);assertEquals(54321,decoded.port);assertEquals(0,decoded.saveSeq);
        assertEquals(0,decoded.administratorVersion);assertEquals(0,decoded.revocationVersion);assertEquals(0,decoded.issuedAt);
        assertEquals(2,ByteBuffer.wrap(decoded.encode()).getInt(4));
    }
    @Test public void settingsMissingIsRepairedFromState()throws Exception {missingOrLegacy(false);}
    @Test public void settingsVersionOneIsRepairedFromState()throws Exception {missingOrLegacy(true);}
    void missingOrLegacy(boolean legacy)throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] original=state.value.clone();
            settings.value=legacy?ByteBuffer.allocate(13).putInt(0x44544346).putInt(1).putInt(group.port).put((byte)0).array():null;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)) {
                assertEquals(group.saveSeq,loaded.saveSeq);assertArrayEquals(original,state.value);
                assertEquals(group.saveSeq,StateSettings.decode(settings.value).saveSeq);
            }
        }
    }
    @Test public void malformedSettingsAreRebuiltWithoutChangingStateBytes()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] original=state.value.clone(),valid=settings.value.clone();
            var malformed=new ArrayList<byte[]>();
            malformed.add(new byte[0]);malformed.add(Arrays.copyOf(valid,12));malformed.add(Arrays.copyOf(valid,46));
            byte[] magic=valid.clone();magic[0]^=1;malformed.add(magic);
            byte[] version=valid.clone();ByteBuffer.wrap(version).putInt(4,3);malformed.add(version);
            byte[] flag=valid.clone();flag[12]=1;malformed.add(flag);
            byte[] port=valid.clone();ByteBuffer.wrap(port).putInt(8,0);malformed.add(port);
            byte[] sequence=valid.clone();ByteBuffer.wrap(sequence).putLong(13,-1);malformed.add(sequence);
            for(byte[] damaged:malformed) {
                settings.value=damaged;
                try(var loaded=storage().load(StorageGroupTest.CLOCK)) {
                    assertArrayEquals(group.certificate.encode(),loaded.certificate.encode());assertEquals(group.saveSeq,loaded.saveSeq);
                    assertArrayEquals(valid,settings.value);assertArrayEquals(original,state.value);
                }
            }
            assertTrue(logs.isEmpty());
        }
    }
    @Test public void malformedSettingsRepairFailureLogsAndContinuesThenRetries()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] original=state.value.clone(),valid=settings.value.clone(),damaged=new byte[]{1,2};
            settings.value=damaged.clone();settings.fail=true;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(group.saveSeq,loaded.saveSeq);}
            assertEquals(List.of("LAN_SETTINGS_SAVE_FAILED"),logs);assertArrayEquals(original,state.value);assertArrayEquals(damaged,settings.value);
            settings.fail=false;
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(group.saveSeq,loaded.saveSeq);}
            assertArrayEquals(valid,settings.value);assertArrayEquals(original,state.value);
        }
    }
    @Test public void settingsReadFailureIsAlsoRepairedFromAuthenticatedState()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] original=state.value.clone(),valid=settings.value.clone();settings.value=new byte[]{1};
            SyncStateStorage.Source unreadable=new SyncStateStorage.Source(){
                public boolean exists(){return true;}
                public byte[] read()throws Exception{throw new java.io.IOException("設定を読めません");}
            };
            var store=new GroupStateStorage(envelope,state,state,settings,unreadable,logs::add);
            try(var loaded=store.load(StorageGroupTest.CLOCK)){assertEquals(group.saveSeq,loaded.saveSeq);}
            assertArrayEquals(valid,settings.value);assertArrayEquals(original,state.value);
        }
    }
    @Test public void versionThreeValidStateAndVersionOneSettingsMigrateTogether()throws Exception {legacyStateAndSettings("valid");}
    @Test public void versionThreeExpiredStateAndVersionOneSettingsMigrateTogether()throws Exception {legacyStateAndSettings("expired");}
    void legacyStateAndSettings(String status)throws Exception {
        byte[] plain=StorageGroupTest.fixture(3,status);state.value=envelope.seal(plain);byte[] original=state.value.clone();
        settings.value=ByteBuffer.allocate(13).putInt(0x44544346).putInt(1).putInt(54321).put((byte)0).array();
        try(var expected=LanGroup.decode(plain,StorageGroupTest.CLOCK,true);var loaded=storage().load(StorageGroupTest.CLOCK)) {
            assertArrayEquals(expected.groupId,loaded.groupId);assertArrayEquals(expected.id(),loaded.id());
            assertArrayEquals(expected.certificate.encode(),loaded.certificate.encode());assertEquals(0,loaded.saveSeq);
            assertArrayEquals(original,state.value);assertEquals(1,ByteBuffer.wrap(settings.value).getInt(4));
            storage().save(loaded);
            assertEquals(5,ByteBuffer.wrap(envelope.open(state.value)).getInt());assertEquals(2,ByteBuffer.wrap(settings.value).getInt(4));
            assertEquals(1,StateSettings.decode(settings.value).saveSeq);
            try(var restored=storage().load(StorageGroupTest.CLOCK)) {
                assertArrayEquals(expected.certificate.encode(),restored.certificate.encode());assertEquals(1,restored.saveSeq);
            }
        }
    }
    @Test public void restoringOnlyStateIsRejectedWithoutDeletingIt()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] old=state.value.clone();storage().save(group);state.value=old;
            var failure=assertThrows(SecurityException.class,()->storage().load(StorageGroupTest.CLOCK));
            assertEquals("保存が古い状態に戻っています",failure.getMessage());assertArrayEquals(old,state.value);
        }
    }
    @Test public void restoringStateAndSettingsTogetherCannotBeDetected()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] old=state.value.clone(),config=settings.value.clone();storage().save(group);
            state.value=old;settings.value=config;try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.saveSeq);}
        }
    }
    @Test public void settingsFailureAfterCommittedStateKeepsSequenceAndRepairsOnLoad()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);settings.fail=true;storage().save(group);assertEquals(2,group.saveSeq);
            assertTrue(logs.contains("LAN_SETTINGS_SAVE_FAILED"));assertEquals(1,StateSettings.decode(settings.value).saveSeq);
            settings.fail=false;try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(2,loaded.saveSeq);}
            assertEquals(2,StateSettings.decode(settings.value).saveSeq);
        }
    }
    @Test public void equalSequenceRejectsEachLowerListVersionAndCertificateTime()throws Exception {
        for(int field=0;field<3;field++)try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] config=settings.value.clone();
            ByteBuffer b=ByteBuffer.wrap(config);int offset=21+8*field;b.putLong(offset,b.getLong(offset)+1);settings.value=config;
            assertEquals("保存が古い状態に戻っています",assertThrows(SecurityException.class,()->storage().load(StorageGroupTest.CLOCK)).getMessage());
        }
    }
    @Test public void newerStateRepairsSettingsEvenWhenCertificateTimeWentBack()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] config=settings.value.clone();ByteBuffer.wrap(config).putLong(37,group.certificate.issuedAt()+1);settings.value=config;
            group.saveSeq++;state.value=envelope.seal(group.encode());
            try(var loaded=storage().load(StorageGroupTest.CLOCK)){assertEquals(group.saveSeq,loaded.saveSeq);}
            assertEquals(group.certificate.issuedAt(),StateSettings.decode(settings.value).issuedAt);
        }
    }
    @Test public void stateFailureRestoresSequenceAndLeavesBothFilesIdentical()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            storage().save(group);byte[] old=state.value.clone(),config=settings.value.clone();state.fail=true;
            assertThrows(Exception.class,()->storage().save(group));assertEquals(1,group.saveSeq);
            assertArrayEquals(old,state.value);assertArrayEquals(config,settings.value);
        }
    }
    @Test public void largeAuthenticatedHistoryIsSavedWithoutTruncationAndWarns()throws Exception {
        try(var group=LanGroup.decode(StorageGroupTest.fixture(3,"valid"),StorageGroupTest.CLOCK,false)) {
            var administrators=AdministratorFixtures.bindings(group,12);
            for(int version=1;version<=130;version++)group.state.acceptAdministrators(AdminRecords.administrators(group.groupId,version,StorageGroupTest.NOW,administrators,group.administratorSecret),v->fail());
            var store=storage();store.save(group);assertTrue(state.value.length>512*1024);assertTrue(state.value.length<=StateEnvelope.MAX_BYTES);
            assertTrue(store.largeState());assertEquals(List.of("LAN_STATE_LARGE"),logs);
            try(var restored=storage().load(StorageGroupTest.CLOCK)){assertEquals(group.state.snapshot().records().size(),restored.state.snapshot().records().size());}
        }
    }
    @Test public void warningUsesEnvelopeSizeAndOnlyExceeds512KiB()throws Exception {
        var store=storage();assertFalse(store.largeState());
        store.observeSize(512*1024);assertFalse(store.largeState());assertTrue(logs.isEmpty());
        store.observeSize(512*1024+1);assertTrue(store.largeState());assertEquals(List.of("LAN_STATE_LARGE"),logs);
    }
}
