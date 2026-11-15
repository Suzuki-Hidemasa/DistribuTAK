// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import org.junit.Test;
import static org.junit.Assert.*;
/** 保存の版5（dhtLocalVersion）と、版の予約口の試験（04 の 8.3）。 */
public class DhtLocalVersionTest {
    final GroupStateStorageTest f=new GroupStateStorageTest();
    /** 版5の平文から、末尾の8バイトを外して版4の並びを作る。 */
    static byte[] asVersionFour(byte[] five) {
        byte[] four=Arrays.copyOf(five,five.length-8);ByteBuffer.wrap(four).putInt(0,4);return four;
    }
    static int versionOf(byte[] plain){return ByteBuffer.wrap(plain).getInt();}
    static long trailingLong(byte[] plain){return ByteBuffer.wrap(plain).getLong(plain.length-8);}
    @Test public void versionTwoThreeAndFourReadAsZeroWithoutRewriting()throws Exception {
        for(int version:new int[]{2,3,4}) {
            byte[] plain=version==4?asVersionFour(newGroupPlain(0)):StorageGroupTest.fixture(version,"valid");
            assertEquals(version,versionOf(plain));
            f.state.value=f.envelope.seal(plain);byte[] old=f.state.value.clone();f.settings.value=null;
            try(var group=f.storage().load(StorageGroupTest.CLOCK)) {
                assertEquals(0,group.dhtLocalVersion);
                assertArrayEquals("読むだけでは書き換えない",old,f.state.value);
                f.storage().save(group);
                byte[] saved=f.envelope.open(f.state.value);assertEquals(5,versionOf(saved));assertEquals(0,trailingLong(saved));
                try(var again=f.storage().load(StorageGroupTest.CLOCK)){assertEquals(0,again.dhtLocalVersion);}
            }
        }
    }
    @Test public void versionFourKeepsOtherFieldsAndIgnoresNothingElse()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.saveSeq=7;group.renewalCount=3;group.syncInitialized=true;group.dhtLocalVersion=99;
            byte[] four=asVersionFour(group.encode());
            try(var restored=LanGroup.decode(four,StorageGroupTest.CLOCK,false)) {
                assertEquals(0,restored.dhtLocalVersion);assertEquals(7,restored.saveSeq);assertEquals(3,restored.renewalCount);
                assertTrue(restored.syncInitialized);assertArrayEquals(group.groupId,restored.groupId);
            }
        }
    }
    @Test public void versionFiveRoundTripsZeroOneAndLargeValues()throws Exception {
        for(long value:new long[]{0,1,123_456_789_012L,Long.MAX_VALUE-1}) {
            try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
                group.dhtLocalVersion=value;byte[] plain=group.encode();
                assertEquals(5,versionOf(plain));assertEquals(value,trailingLong(plain));
                try(var restored=LanGroup.decode(plain,StorageGroupTest.CLOCK,false)){assertEquals(value,restored.dhtLocalVersion);}
            }
        }
    }
    @Test public void versionFiveRefusesBadValuesTruncationAndFutureVersion()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.dhtLocalVersion=-1;assertThrows(Exception.class,group::encode);
            group.dhtLocalVersion=Long.MAX_VALUE;assertThrows(Exception.class,group::encode);
            group.dhtLocalVersion=5;byte[] plain=group.encode();
            byte[] negative=plain.clone();ByteBuffer.wrap(negative).putLong(negative.length-8,-1);
            assertThrows(IOException.class,()->LanGroup.decode(negative,StorageGroupTest.CLOCK,false));
            byte[] top=plain.clone();ByteBuffer.wrap(top).putLong(top.length-8,Long.MAX_VALUE);
            assertThrows(IOException.class,()->LanGroup.decode(top,StorageGroupTest.CLOCK,false));
            byte[] cut=Arrays.copyOf(plain,plain.length-1);
            assertThrows(IOException.class,()->LanGroup.decode(cut,StorageGroupTest.CLOCK,false));
            byte[] extra=Arrays.copyOf(plain,plain.length+1);
            assertThrows(IOException.class,()->LanGroup.decode(extra,StorageGroupTest.CLOCK,false));
            byte[] six=plain.clone();ByteBuffer.wrap(six).putInt(0,6);
            assertThrows(IOException.class,()->LanGroup.decode(six,StorageGroupTest.CLOCK,false));
        }
    }
    static byte[] newGroupPlain(long value)throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {group.dhtLocalVersion=value;return group.encode();}
    }
    @Test public void reserveRaisesVersionAndSaveSeqByOneAndSurvivesReload()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            long seq=group.saveSeq;
            assertEquals(1,f.storage().reserveDhtVersion(group));
            assertEquals(1,group.dhtLocalVersion);assertEquals(seq+1,group.saveSeq);
            assertEquals(seq+1,StateSettings.decode(f.settings.value).saveSeq);
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertEquals(1,loaded.dhtLocalVersion);assertEquals(seq+1,loaded.saveSeq);}
            assertEquals(2,f.storage().reserveDhtVersion(group));assertEquals(seq+2,group.saveSeq);
        }
    }
    @Test public void stateSaveFailureRestoresVersionAndSaveSeqAndKeepsOldBytes()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            f.storage().reserveDhtVersion(group);byte[] old=f.state.value.clone();
            byte[] oldSettings=f.settings.value.clone();
            long seq=group.saveSeq;
            long version=group.dhtLocalVersion;
            f.state.fail=true;assertThrows(Exception.class,()->f.storage().reserveDhtVersion(group));
            assertEquals(version,group.dhtLocalVersion);assertEquals(seq,group.saveSeq);
            assertArrayEquals(old,f.state.value);assertArrayEquals(oldSettings,f.settings.value);
            f.state.fail=false;assertEquals(version+1,f.storage().reserveDhtVersion(group));
        }
    }
    @Test public void settingsOnlyFailureStillCountsAsSavedBecauseStateIsSourceOfTruth()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            f.storage().reserveDhtVersion(group);long seq=group.saveSeq;
            f.settings.fail=true;
            assertEquals(2,f.storage().reserveDhtVersion(group));
            assertEquals(2,group.dhtLocalVersion);assertEquals(seq+1,group.saveSeq);
            assertTrue(f.logs.contains("LAN_SETTINGS_SAVE_FAILED"));
            assertEquals(2,ByteBuffer.wrap(f.envelope.open(f.state.value)).getLong(f.envelope.open(f.state.value).length-8));
            f.settings.fail=false;
            try(var loaded=f.storage().load(StorageGroupTest.CLOCK)){assertEquals(2,loaded.dhtLocalVersion);assertEquals(seq+1,loaded.saveSeq);}
            assertEquals(seq+1,StateSettings.decode(f.settings.value).saveSeq);
        }
    }
    @Test public void reserveStopsAtTheLimitWithoutAdvancing()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            f.storage().reserveDhtVersion(group);
            group.dhtLocalVersion=Long.MAX_VALUE-2;assertEquals(Long.MAX_VALUE-1,f.storage().reserveDhtVersion(group));
            byte[] old=f.state.value.clone();long seq=group.saveSeq;
            assertThrows(IllegalStateException.class,()->f.storage().reserveDhtVersion(group));
            assertEquals(Long.MAX_VALUE-1,group.dhtLocalVersion);assertEquals(seq,group.saveSeq);assertArrayEquals(old,f.state.value);
        }
    }
    @Test public void reservedVersionAfterRestartIsLargerThanBefore()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            long first=f.storage().reserveDhtVersion(group);
            try(var restarted=f.storage().load(StorageGroupTest.CLOCK)){assertTrue(f.storage().reserveDhtVersion(restarted)>first);}
        }
    }
    @Test public void rollbackOfStateFileIsStillDetectedWithVersionFive()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            f.storage().reserveDhtVersion(group);byte[] older=f.state.value.clone();
            f.storage().reserveDhtVersion(group);f.storage().reserveDhtVersion(group);
            f.state.value=older;
            assertThrows(StateSettings.Rollback.class,()->f.storage().load(StorageGroupTest.CLOCK));
        }
    }
    @Test public void settingsVersionStaysTwoAndHasNoDhtVersion()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())) {
            group.dhtLocalVersion=1000;f.storage().save(group);
            assertEquals(2,ByteBuffer.wrap(f.settings.value).getInt(4));assertTrue(f.settings.value.length<=StateSettings.MAX_BYTES);
        }
    }
    @Test public void rejoinedAndAcceptRejoinedCarryTheVersionOver()throws Exception {
        try(var pair=new RejoinedStorageTest.Fixture()) {
            pair.member.dhtLocalVersion=41;f.storage().save(pair.member);
            var later=java.time.Clock.offset(StorageGroupTest.CLOCK,java.time.Duration.ofSeconds(1));
            try(var candidate=pair.rejoin(later)) {
                assertEquals(41,candidate.dhtLocalVersion);
                var staged=f.storage().stage(candidate,f.temporary,()->f.temporary.value.clone(),()->f.temporary.value=null);
                f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged);
                try(var loaded=f.storage().load(later)){assertEquals(41,loaded.dhtLocalVersion);}
            }
        }
    }
    @Test public void acceptRejoinedRefusesACandidateWithADifferentVersion()throws Exception {
        try(var pair=new RejoinedStorageTest.Fixture()) {
            pair.member.dhtLocalVersion=41;f.storage().save(pair.member);byte[] old=f.state.value.clone();
            var later=java.time.Clock.offset(StorageGroupTest.CLOCK,java.time.Duration.ofSeconds(1));
            for(long other:new long[]{40,42}) {
                try(var candidate=pair.rejoin(later)) {
                    var staged=f.storage().stage(candidate,f.temporary,()->f.temporary.value.clone(),()->f.temporary.value=null);
                    candidate.dhtLocalVersion=other;
                    assertThrows(SecurityException.class,()->f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged));
                    assertArrayEquals(old,f.state.value);staged.abort();
                }
            }
        }
    }
    @Test public void newGroupsStartAtZero()throws Exception {
        try(var group=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom())){assertEquals(0,group.dhtLocalVersion);}
        try(var pair=new RejoinedStorageTest.Fixture()){assertEquals(0,pair.member.dhtLocalVersion);}
    }
}
