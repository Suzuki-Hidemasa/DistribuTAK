// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class SyncStateTest {
    @Test void receivedUidSnapshotIncludesExpiredAndDebugOnlyOriginsAndIsImmutable() {
        var state=state();state.origin("expired",SyncState.Origin.DISTRIBUTAK);state.origin("debug",SyncState.Origin.DISTRIBUTAK);
        state.origin("outside",SyncState.Origin.LOCAL_CREATED);
        var received=state.receivedUids();assertEquals(java.util.Set.of("expired","debug"),received);
        assertThrows(UnsupportedOperationException.class,()->received.add("new"));
        state.origin("later",SyncState.Origin.DISTRIBUTAK);assertEquals(2,received.size());
    }
    static SyncState state() { return new SyncState(new byte[32],CotRecordTest.id(1)); }
    @Test void snapshotBindsGroupAndLocalIdentityAndPreservesMaximumAndOrigins() {
        var state=state();state.maximum(1234);
        state.origin("test",SyncState.Origin.LOCAL_CREATED);
        state.put(CotRecordTest.record(CotRecordTest.NOW,1,0),CotRecordTest.NOW);
        var restored=SyncState.decode(state.encode(),new byte[32],CotRecordTest.id(1));
        assertEquals(1234,restored.maximum());assertEquals(SyncState.Origin.LOCAL_CREATED,restored.origin("test"));
        assertTrue(restored.get("test").sameRecord(state.get("test")));
        assertThrows(IllegalArgumentException.class,()->SyncState.decode(state.encode(),new byte[]{1},CotRecordTest.id(1)));
        assertThrows(IllegalArgumentException.class,()->SyncState.decode(state.encode(),new byte[32],CotRecordTest.id(2)));
    }
    @Test void tombstoneSurvivesRestartForThirtyDaysAndDuplicateDoesNotExtendIt() {
        var state=state();var tombstone=CotRecord.tombstone("deleted",CotRecordTest.NOW,CotRecordTest.id(1),1);
        state.put(tombstone,CotRecordTest.NOW);
        state.put(tombstone,CotRecordTest.NOW+10000);
        var restored=SyncState.decode(state.encode(),new byte[32],CotRecordTest.id(1));
        restored.prune(CotRecordTest.NOW+CotXml.MAX_STALE_MILLIS-1);assertNotNull(restored.get("deleted"));
        restored.prune(CotRecordTest.NOW+CotXml.MAX_STALE_MILLIS);assertNull(restored.get("deleted"));
    }
    @Test void pruningAnExpiredRecordDoesNotForgetThatItCameFromAnotherDevice() {
        var state=state();state.origin("test",SyncState.Origin.DISTRIBUTAK);
        state.put(CotRecordTest.record(CotRecordTest.NOW,1,1),CotRecordTest.NOW);
        state.prune(CotRecordTest.NOW+60000);assertNull(state.get("test"));
        assertEquals(SyncState.Origin.DISTRIBUTAK,state.origin("test"));
    }
    @Test void provenanceAndRecordsShareThe4096UidLimitAndFailedInsertIsAtomic() {
        var state=state();for(int n=0;n<4096;n++)state.origin("source-"+n,SyncState.Origin.DISTRIBUTAK);
        var item=CotRecord.tombstone("source-0",CotRecordTest.NOW,CotRecordTest.id(1),1);
        state.put(item,CotRecordTest.NOW);assertEquals(4096,state.uidCount());
        byte[] before=state.encode();
        assertThrows(IllegalArgumentException.class,()->state.origin("overflow",SyncState.Origin.DISTRIBUTAK));
        assertArrayEquals(before,state.encode());
        assertThrows(IllegalArgumentException.class,()->state.put(CotRecord.tombstone("overflow",CotRecordTest.NOW,CotRecordTest.id(1),1),CotRecordTest.NOW));
        assertArrayEquals(before,state.encode());
    }
    @Test void plaintextBudgetIncludesEveryXmlAndFailedInsertLeavesTheSnapshotUnchanged() {
        var state=state();int n=0;
        for(;n<100;n++) {
            String uid="large-"+n;long stale=CotRecordTest.NOW+60000;
            String xml=new String(CotRecordTest.xml(uid,stale),StandardCharsets.UTF_8).replace("<detail/>","<detail><remarks>"+"x".repeat(60000)+"</remarks></detail>");
            var item=CotRecord.record(uid,CotRecordTest.NOW,CotRecordTest.id(1),stale,xml.getBytes(StandardCharsets.UTF_8),1);
            byte[] before=state.encode();
            try { state.put(item,CotRecordTest.NOW); }
            catch(IllegalArgumentException e) { assertArrayEquals(before,state.encode());break; }
        }
        assertTrue(n>1&&n<100);assertTrue(state.encode().length<=4194266);
        assertThrows(IllegalArgumentException.class,()->SyncState.decode(new byte[4194267],new byte[32],CotRecordTest.id(1)));
    }
    @Test void aWorkingCopyCannotMutateTheLastCommittedSnapshot() {
        var committed=state();var working=committed.copy();
        working.origin("test",SyncState.Origin.DISTRIBUTAK);
        working.put(CotRecordTest.record(CotRecordTest.NOW,1,1),CotRecordTest.NOW);
        assertNull(committed.get("test"));assertEquals(SyncState.Origin.UNKNOWN,committed.origin("test"));
        assertNotNull(working.get("test"));
    }
    @Test void malformedSnapshotIsRejectedInsteadOfBeingTreatedAsEmpty() {
        assertThrows(IllegalArgumentException.class,()->SyncState.decode(new byte[]{10,(byte)255},new byte[32],CotRecordTest.id(1)));
        var state=state();state.put(CotRecordTest.record(CotRecordTest.NOW,1,1),CotRecordTest.NOW);
        byte[] bytes=state.encode();bytes[bytes.length-3]^=1;
        assertThrows(IllegalArgumentException.class,()->SyncState.decode(bytes,new byte[32],CotRecordTest.id(1)));
    }
}
