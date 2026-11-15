// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncStateReuseTest {
    @Test void unchangedEncodedRecordsAreCopiedWithoutOpeningColdXmlAndWireIsIdentical(){
        var state=SyncStateTest.state();state.put(CotRecordTest.record(CotRecordTest.NOW,1,0),CotRecordTest.NOW);state.origin("marker",SyncState.Origin.LOCAL_CREATED);state.maximum(CotRecordTest.NOW);
        byte[] original=state.encode();var committed=state.copy();var disk=new SyncCacheTest.Disk();var cache=new SyncCache(disk,1,32,()->0);
        var item=state.records().get(0);state.replaceBody(item.offload(cache,()->{throw new AssertionError("must not restore XML");}));disk.reads=0;
        assertArrayEquals(original,state.encodeUsing(committed,original));assertEquals(0,disk.reads);
        state.origin("received",SyncState.Origin.DISTRIBUTAK);var expected=committed.copy();expected.origin("received",SyncState.Origin.DISTRIBUTAK);
        assertArrayEquals(expected.encode(),state.encodeUsing(committed,original));assertEquals(0,disk.reads);
        state.put(CotRecord.tombstone("changed",CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);expected.put(CotRecord.tombstone("changed",CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        assertArrayEquals(expected.encode(),state.encodeUsing(committed,original));
        var changed=CotRecord.record(item.uid(),item.time()+1,item.author(),item.stale(),item.xml(),item.hop());state.put(changed,CotRecordTest.NOW);expected.put(changed,CotRecordTest.NOW);
        assertArrayEquals(expected.encode(),state.encodeUsing(committed,original));assertEquals(0,disk.reads);cache.close();
    }
    @Test void primaryRecordLengthsAndHashesMustMatchCommittedStateBeforeReuse()throws Exception{
        var state=SyncStateTest.state();state.put(CotRecordTest.record(CotRecordTest.NOW,1,0),CotRecordTest.NOW);byte[] plain=state.encode();
        var snapshot=SyncSchema.SyncSnapshot.parseFrom(plain);var stored=snapshot.getRecords(0);var record=stored.getEnvelope().getRecord();
        byte[] xml=record.getXmlUtf8().toByteArray();xml[xml.length-3]^=1;
        byte[] damaged=snapshot.toBuilder().setRecords(0,stored.toBuilder().setEnvelope(stored.getEnvelope().toBuilder().setRecord(record.toBuilder().setXmlUtf8(SyncWire.bytes(xml))))).build().toByteArray();
        assertEquals(plain.length,damaged.length);assertThrows(IllegalArgumentException.class,()->state.encodeUsing(state.copy(),damaged));
        assertThrows(IllegalArgumentException.class,()->state.encodeUsing(state.copy(),new byte[0]));assertArrayEquals(plain,state.encodeUsing(state.copy(),plain));
    }
    @Test void applyIsAtomicAndUidUnionCountsRecordsOriginsAndPruningWithoutTemporarySets(){
        var state=SyncStateTest.state();var item=CotRecordTest.record(CotRecordTest.NOW,1,0);state.apply(item,CotRecordTest.NOW,SyncState.Origin.LOCAL_CREATED,CotRecordTest.NOW);assertEquals(1,state.uidCount());
        state.origin(item.uid(),SyncState.Origin.UNKNOWN);assertEquals(1,state.uidCount());state.prune(item.stale());assertEquals(0,state.uidCount());
        state.origin("only-origin",SyncState.Origin.DISTRIBUTAK);assertEquals(1,state.uidCount());byte[] before=state.encode();
        assertThrows(IllegalArgumentException.class,()->state.apply(CotRecord.tombstone("rollback",CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW,SyncState.Origin.DISTRIBUTAK,CotRecordTest.NOW-1));
        assertArrayEquals(before,state.encode());assertEquals(1,state.uidCount());
    }
}
