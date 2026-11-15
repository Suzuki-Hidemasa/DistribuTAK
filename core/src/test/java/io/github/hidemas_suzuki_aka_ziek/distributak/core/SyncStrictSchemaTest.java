// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.io.ByteArrayOutputStream;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncStrictSchemaTest {
    @Test void snapshotsAndAllStorageMessagesRejectUnknownFieldsAndGroups()throws Exception {
        var state=SyncStateTest.state();state.origin("test",SyncState.Origin.LOCAL_CREATED);state.put(CotRecordTest.record(CotRecordTest.NOW,1,1),CotRecordTest.NOW);
        var base=SyncSchema.SyncSnapshot.parseFrom(state.encode());
        assertNotNull(SyncState.decode(base.toByteArray(),new byte[32],CotRecordTest.id(1)));
        for(boolean group:new boolean[]{false,true}){
            var stored=base.getRecords(0);
            for(byte[] bad:new byte[][]{extra(base.toByteArray(),group),
                base.toBuilder().setRecords(0,SyncSchema.SyncStoredRecord.parseFrom(extra(stored.toByteArray(),group))).build().toByteArray(),
                base.toBuilder().setOrigins(0,SyncSchema.SyncOrigin.parseFrom(extra(base.getOrigins(0).toByteArray(),group))).build().toByteArray(),
                base.toBuilder().setRecords(0,stored.toBuilder().setEnvelope(SyncSchema.SyncEnvelope.parseFrom(extra(stored.getEnvelope().toByteArray(),group)))).build().toByteArray()})
                assertThrows(IllegalArgumentException.class,()->SyncState.decode(bad,new byte[32],CotRecordTest.id(1)));
        }
        byte[] legacy=base.toBuilder().setOrigins(0,base.getOrigins(0).toBuilder().setKind(SyncState.Origin.EXTERNAL.ordinal())).build().toByteArray();
        assertThrows(IllegalArgumentException.class,()->SyncState.decode(legacy,new byte[32],CotRecordTest.id(1)));
    }
    static byte[] extra(byte[] known,boolean group)throws Exception {
        var bytes=new ByteArrayOutputStream();bytes.write(known);var out=CodedOutputStream.newInstance(bytes);
        if(group){out.writeTag(99,3);out.writeTag(99,4);}else out.writeByteArray(99,new byte[100]);
        out.flush();return bytes.toByteArray();
    }
    static byte[] envelope(int body,byte[] value)throws Exception {
        var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);out.writeUInt32(1,1);out.writeByteArray(body,value);out.flush();return bytes.toByteArray();
    }
    static List<byte[]> known(){
        var record=CotRecordTest.record(CotRecordTest.NOW,1,1);var entry=SyncWire.entry(record);
        return List.of(SyncWire.encode(record),SyncWire.encode(CotRecord.tombstone("test",CotRecordTest.NOW,CotRecordTest.id(1),1)),SyncWire.ack(record),
            SyncWire.envelope().setInventory(SyncSchema.SyncInventory.newBuilder().setSnapshotId(SyncWire.bytes(new byte[16])).setLast(true).addEntries(entry)).build().toByteArray(),
            SyncWire.envelope().setRequest(SyncSchema.SyncRequest.newBuilder().setSnapshotId(SyncWire.bytes(new byte[16])).addWanted(entry)).build().toByteArray(),
            SyncWire.envelope().setFragment(SyncSchema.SyncFragment.newBuilder().setTransferId(SyncWire.bytes(new byte[16])).setDigest(SyncWire.bytes(new byte[32])).setTotalBytes(2048).setCount(2).setPayload(SyncWire.bytes(new byte[1024]))).build().toByteArray());
    }
    @Test void unknownAndGroupFieldsAreRejectedAtEnvelopeAndEveryBodyLevel()throws Exception {
        for(byte[] wire:known()) {
            var value=SyncWire.parse(wire);int body=value.getBodyCase().getNumber();
            byte[] inner=switch(body){case 2->value.getRecord().toByteArray();case 3->value.getTombstone().toByteArray();case 4->value.getAck().toByteArray();case 5->value.getInventory().toByteArray();case 6->value.getRequest().toByteArray();default->value.getFragment().toByteArray();};
            for(boolean group:new boolean[]{false,true}){
                assertThrows(IllegalArgumentException.class,()->SyncWire.parse(extra(wire,group)),"envelope body="+body);
                assertThrows(IllegalArgumentException.class,()->SyncWire.parse(envelope(body,extra(inner,group))),"nested body="+body);
            }
        }
    }
    @Test void versionAndEntryUnknownFieldsAreRejectedInEveryContainer()throws Exception {
        var record=CotRecordTest.record(CotRecordTest.NOW,1,1);var entry=SyncWire.entry(record);
        for(boolean group:new boolean[]{false,true}) {
            var version=SyncSchema.SyncVersion.parseFrom(extra(SyncWire.version(record).toByteArray(),group));
            var badEntry=SyncSchema.SyncInventoryEntry.parseFrom(extra(entry.toByteArray(),group));
            var versionEntry=entry.toBuilder().setVersion(version).build();
            for(var item:new SyncSchema.SyncInventoryEntry[]{badEntry,versionEntry}) {
                var inventory=SyncWire.envelope().setInventory(SyncSchema.SyncInventory.newBuilder().setSnapshotId(SyncWire.bytes(new byte[16])).setLast(true).addEntries(item)).build().toByteArray();
                var request=SyncWire.envelope().setRequest(SyncSchema.SyncRequest.newBuilder().setSnapshotId(SyncWire.bytes(new byte[16])).addWanted(item)).build().toByteArray();
                assertThrows(IllegalArgumentException.class,()->SyncWire.parse(inventory));assertThrows(IllegalArgumentException.class,()->SyncWire.parse(request));
            }
            var value=SyncWire.parse(SyncWire.encode(record));
            for(byte[] wire:new byte[][]{
                value.toBuilder().setRecord(value.getRecord().toBuilder().setVersion(version)).build().toByteArray(),
                SyncWire.envelope().setTombstone(SyncSchema.SyncTombstone.newBuilder().setUid("test").setVersion(version)).build().toByteArray(),
                SyncWire.envelope().setAck(SyncSchema.SyncAck.newBuilder().setUid("test").setVersion(version)).build().toByteArray()})assertThrows(IllegalArgumentException.class,()->SyncWire.parse(wire));
        }
    }
    @Test void knownFieldsRemainAcceptedInAllMessageKinds(){for(byte[] wire:known())assertArrayEquals(wire,SyncWire.parse(wire).toByteArray());}
}
