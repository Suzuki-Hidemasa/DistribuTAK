// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.time.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExternalExpiryTest {
    static final long BASE=CotRecordTest.NOW;
    static final byte[] LOCAL=CotRecordTest.id(1),PEER=CotRecordTest.id(2),SESSION=SyncFragmentsTest.token(1);
    static final class Wall extends Clock {
        final AtomicLong now=new AtomicLong(BASE);
        public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}
        public Instant instant(){return Instant.ofEpochMilli(now.get());}
    }
    static final class Node implements AutoCloseable {
        final Wall wall;final CotSync sync;SyncState saved;ExternalMarks marks;
        final List<CotRecord> imported=new ArrayList<>();final List<byte[]> sent=new ArrayList<>();
        boolean failSync,failExternal;
        Node(Wall wall,SyncState saved,ExternalMarks marks){
            this.wall=wall;this.saved=saved;this.marks=marks;
            sync=new CotSync(LOCAL,saved,wall,()->0,s->{if(failSync)throw new IllegalStateException();this.saved=s.copy();},
                (p,se,w)->{sent.add(w.clone());return true;},imported::add,new SecureRandom(),0,marks,
                m->{if(failExternal)throw new IllegalStateException();this.marks=ExternalMarks.decode(m.encode(),new byte[32],LOCAL);});
            sync.connected(PEER,SESSION);
        }
        Node(){this(new Wall(),new SyncState(new byte[32],LOCAL),marked());}
        static ExternalMarks marked(){var marks=new ExternalMarks(new byte[32],LOCAL);marks.add("incoming");return marks;}
        CotRecord record(long version){return CotRecord.record("incoming",version,PEER,wall.millis()+60_000,CotRecordTest.xml("incoming",wall.millis()+60_000),1);}
        void receive(CotRecord record){sync.receive(PEER,SESSION,SyncWire.encode(record));sync.flush();}
        public void close(){sync.close();}
    }
    @Test void noDistribuTakRecordLeavesMarkIndefinitelyIncludingLegacyMigration(){
        var old=ByteBuffer.allocate(ExternalMarks.HEADER_BYTES+16);
        var fingerprint=ExternalMarks.fingerprint("incoming");
        old.putInt(0x44544558).putInt(1).put("distributak-external-uids-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        old.put(new byte[32]).put(LOCAL).putInt(1).putLong(fingerprint.high()).putLong(fingerprint.low());
        var marks=ExternalMarks.decode(old.array(),new byte[32],LOCAL);assertTrue(marks.migrateLegacy());assertFalse(marks.migrateLegacy());
        var restored=ExternalMarks.decode(marks.encode(),new byte[32],LOCAL);assertFalse(restored.migrateLegacy());
        assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),restored.startedAt(fingerprint));assertEquals(0,restored.expire(Long.MAX_VALUE));
        try(var node=new Node(new Wall(),new SyncState(new byte[32],LOCAL),restored)){
            node.wall.now.addAndGet(365L*86400_000);node.sync.poll();assertEquals(1,node.sync.externalSnapshot().size());assertTrue(node.imported.isEmpty());
        }
    }
    @Test void firstDurableReceiptStartsTimerAndMoreReceiptsDoNotExtendItThenLatestStaleRecordImports(){
        try(var node=new Node()){
            var first=node.record(BASE);node.receive(first);
            assertEquals(Long.valueOf(BASE),node.marks.startedAt(ExternalMarks.fingerprint("incoming")));assertTrue(node.imported.isEmpty());
            node.wall.now.set(BASE+300_000);var latest=node.record(BASE+300_000);node.receive(latest);
            assertEquals(Long.valueOf(BASE),node.marks.startedAt(ExternalMarks.fingerprint("incoming")));
            node.wall.now.set(BASE+599_999);assertEquals(0,node.sync.expireExternal());assertTrue(node.imported.isEmpty());
            node.wall.now.incrementAndGet();assertEquals(1,node.sync.expireExternal());assertEquals(1,node.imported.size());
            assertTrue(latest.sameRecord(node.imported.get(0)));assertEquals(0,node.marks.size());assertEquals(1,node.sync.externalExpired());
            assertEquals(0,node.sync.expireExternal());assertEquals(1,node.imported.size());
        }
    }
    @Test void newExternalObservationCancelsTimerAndSameOrOlderReceiptRestartsItWithoutChangingPrimary(){
        for(boolean older:new boolean[]{false,true})try(var node=new Node()){
            var first=CotRecord.record("incoming",BASE,PEER,BASE+2_000_000,CotRecordTest.xml("incoming",BASE+2_000_000),1);node.receive(first);
            node.wall.now.set(BASE+300_000);node.sync.external("incoming");node.sync.flush();
            assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),node.marks.startedAt(ExternalMarks.fingerprint("incoming")));
            node.wall.now.set(BASE+700_000);assertEquals(0,node.sync.expireExternal());
            var repeat=older?node.record(BASE-1):first;node.receive(repeat);
            assertEquals(Long.valueOf(BASE+700_000),node.marks.startedAt(ExternalMarks.fingerprint("incoming")));assertTrue(first.sameRecord(node.saved.get("incoming")));
            node.wall.now.set(BASE+1_300_000);assertEquals(1,node.sync.expireExternal());assertEquals(1,node.imported.size());assertTrue(first.sameRecord(node.imported.get(0)));
        }
    }
    @Test void restartKeepsStartAndClockRollbackWaitsThenLatestDeletionImports(){
        var wall=new Wall();SyncState state;ExternalMarks marks;
        try(var node=new Node(wall,new SyncState(new byte[32],LOCAL),Node.marked())){
            node.receive(node.record(BASE));wall.now.set(BASE+1000);node.receive(CotRecord.tombstone("incoming",BASE+1000,PEER,1));state=node.saved;marks=node.marks;
        }
        try(var node=new Node(wall,SyncState.decode(state.encode(),new byte[32],LOCAL),ExternalMarks.decode(marks.encode(),new byte[32],LOCAL))){
            wall.now.set(BASE-1000);assertEquals(0,node.sync.expireExternal());wall.now.set(BASE+599_999);assertEquals(0,node.sync.expireExternal());
            wall.now.incrementAndGet();assertEquals(1,node.sync.expireExternal());assertEquals(1,node.imported.size());assertTrue(node.imported.get(0).deleted());
        }
    }
    @Test void failedExpirySaveStopsWithoutPublishingRemovalOrImport(){
        try(var node=new Node()){
            node.receive(node.record(BASE));node.wall.now.addAndGet(600_000);node.failExternal=true;
            assertThrows(IllegalStateException.class,node.sync::expireExternal);assertTrue(node.sync.isClosed());assertTrue(node.marks.contains("incoming"));assertTrue(node.imported.isEmpty());assertEquals(0,node.sync.externalExpired());
        }
    }
    @Test void failedPrimarySaveDoesNotStartTimerOrAck(){
        try(var node=new Node()){
            node.sent.clear();node.failSync=true;
            assertThrows(IllegalStateException.class,()->node.receive(node.record(BASE)));assertTrue(node.sync.isClosed());
            assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),node.marks.startedAt(ExternalMarks.fingerprint("incoming")));
            assertTrue(node.sent.stream().noneMatch(w->SyncWire.parse(w).hasAck()));assertTrue(node.imported.isEmpty());
        }
    }
    @Test void rejectedRecordDoesNotStartTimer(){
        try(var node=new Node()){
            node.sync.receive(PEER,SESSION,SyncWire.encode(node.record(BASE+300_001)));node.sync.flush();
            assertEquals(1,node.sync.statistics().rejected());assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),node.sync.externalSnapshot().startedAt(ExternalMarks.fingerprint("incoming")));
        }
    }
    @Test void failedTimerSaveForSameVersionDoesNotAckOrChangePrimary(){
        try(var node=new Node()){
            var first=node.record(BASE);node.receive(first);node.sync.external("incoming");node.sync.flush();
            node.sent.clear();node.failExternal=true;
            assertThrows(IllegalStateException.class,()->node.receive(first));assertTrue(node.sync.isClosed());
            assertTrue(first.sameRecord(node.saved.get("incoming")));
            assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),node.marks.startedAt(ExternalMarks.fingerprint("incoming")));
            assertTrue(node.sent.stream().noneMatch(w->SyncWire.parse(w).hasAck()));assertTrue(node.imported.isEmpty());
        }
    }
    @Test void expiryFreesFullRegistryBeforeCapacityCheckAndCopyKeepsStart(){
        var marks=new ExternalMarks(new byte[32],LOCAL);for(int n=0;n<ExternalMarks.MAX_ENTRIES;n++)marks.add("outside-"+n,BASE-600_000);
        var copied=marks.copy();assertEquals(ExternalMarks.MAX_ENTRIES,copied.expire(BASE));assertTrue(marks.full());
        try(var node=new Node(new Wall(),new SyncState(new byte[32],LOCAL),marks)){
            node.sync.external("incoming");node.sync.flush();assertEquals(1,node.marks.size());assertTrue(node.marks.contains("incoming"));assertEquals(ExternalMarks.MAX_ENTRIES,node.sync.externalExpired());
        }
    }
    @Test void stalePruneRemovesPrimaryBeforeExpirySoOnlyTheMarkAndCounterChange(){
        try(var node=new Node()){
            var first=node.record(BASE);node.receive(first);
            node.wall.now.set(first.stale());node.sync.poll();node.sync.flush();
            assertNull(node.saved.get(first.uid()));assertTrue(node.marks.contains(first.uid()));
            assertTrue(node.imported.isEmpty());assertEquals(0,node.sync.externalExpired());
            node.wall.now.set(BASE+600_000);node.sync.poll();
            assertFalse(node.marks.contains(first.uid()));assertNull(node.saved.get(first.uid()));
            assertEquals(1,node.sync.externalExpired());assertTrue(node.imported.isEmpty());
        }
    }
    @Test void recordCapacityCheckExpiresDurablyThenImportsSavedLatestBeforeSavingNewReceipt(){
        try(var node=new Node()){
            var first=CotRecord.record("incoming",BASE,PEER,BASE+2_000_000,CotRecordTest.xml("incoming",BASE+2_000_000),1);node.receive(first);
            node.wall.now.set(BASE+600_000);
            var other=CotRecord.record("another",node.wall.millis(),PEER,node.wall.millis()+60_000,CotRecordTest.xml("another",node.wall.millis()+60_000),1);
            node.sync.receive(PEER,SESSION,SyncWire.encode(other));
            assertEquals(1,node.sync.externalExpired());assertFalse(node.marks.contains(first.uid()));
            assertEquals(1,node.imported.size());assertTrue(first.sameRecord(node.imported.get(0)));
            assertNull(node.saved.get(other.uid()));
            node.sync.flush();assertTrue(other.sameRecord(node.saved.get(other.uid())));assertEquals(2,node.imported.size());
        }
    }
    @Test void publishCapacityCheckExpiresDurablyWithoutPrematurelySavingTheLocalUpdate(){
        try(var node=new Node()){
            var first=CotRecord.record("incoming",BASE,PEER,BASE+2_000_000,CotRecordTest.xml("incoming",BASE+2_000_000),1);node.receive(first);
            node.wall.now.set(BASE+600_000);
            assertTrue(node.sync.publish("local-created",CotRecordTest.xml("local-created",node.wall.millis()+60_000),SyncState.Origin.LOCAL_CREATED));
            assertEquals(1,node.sync.externalExpired());assertFalse(node.marks.contains(first.uid()));
            assertEquals(1,node.imported.size());assertTrue(first.sameRecord(node.imported.get(0)));
            assertNull(node.saved.get("local-created"));node.sync.flush();assertNotNull(node.saved.get("local-created"));
            assertEquals(1,node.imported.size());
        }
    }
    @Test void expirySaveFailureFromRecordOrPublishCapacityCheckStopsBeforeNewWorkIsSavedOrAcked(){
        for(boolean publish:new boolean[]{false,true})try(var node=new Node()){
            node.receive(node.record(BASE));node.wall.now.set(BASE+600_000);node.failExternal=true;node.sent.clear();
            if(publish)assertThrows(IllegalStateException.class,()->node.sync.publish("local-created",CotRecordTest.xml("local-created",node.wall.millis()+60_000),SyncState.Origin.LOCAL_CREATED));
            else{
                var other=CotRecord.record("another",node.wall.millis(),PEER,node.wall.millis()+60_000,CotRecordTest.xml("another",node.wall.millis()+60_000),1);
                assertThrows(IllegalStateException.class,()->node.sync.receive(PEER,SESSION,SyncWire.encode(other)));
            }
            assertTrue(node.sync.isClosed());assertTrue(node.marks.contains("incoming"));
            assertEquals(0,node.sync.externalExpired());assertTrue(node.imported.isEmpty());
            assertNull(node.saved.get("another"));assertNull(node.saved.get("local-created"));
            assertTrue(node.sent.stream().noneMatch(w->SyncWire.parse(w).hasAck()));
        }
    }
}
