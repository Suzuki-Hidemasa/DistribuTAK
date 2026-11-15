// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncWireTest {
    @Test void protobufGroupsAreRejectedBeforeRecursiveUnknownFieldSkipping() {
        byte[] ordinary=SyncWire.ack(CotRecordTest.record(CotRecordTest.NOW,1,1));
        byte[] group=java.util.Arrays.copyOf(ordinary,ordinary.length+4);
        group[ordinary.length]=(byte)0x9b;group[ordinary.length+1]=6;
        group[ordinary.length+2]=(byte)0x9c;group[ordinary.length+3]=6;
        assertThrows(IllegalArgumentException.class,()->SyncWire.parse(group));
    }
    @Test void recordsAndTombstonesRoundTripWithoutChangingXmlOrHash() {
        for(var item:new CotRecord[]{CotRecordTest.record(CotRecordTest.NOW,1,1),
                CotRecord.tombstone("test",CotRecordTest.NOW,CotRecordTest.id(1),1)}) {
            var decoded=SyncWire.decodeRecord(SyncWire.encode(item));
            assertTrue(item.sameRecord(decoded));assertEquals(item.deleted(),decoded.deleted());
            assertEquals(item.hop(),decoded.hop());assertArrayEquals(item.xml(),decoded.xml());
        }
    }
    @Test void rejectsChangedHashAndUnknownSchema() {
        var envelope=SyncWire.parse(SyncWire.encode(CotRecordTest.record(CotRecordTest.NOW,1,1)));
        var badHash=envelope.toBuilder().setRecord(envelope.getRecord().toBuilder().setHash(ByteString.copyFrom(new byte[32]))).build();
        assertThrows(IllegalArgumentException.class,()->SyncWire.decodeRecord(badHash.toByteArray()));
        assertThrows(IllegalArgumentException.class,()->SyncWire.parse(envelope.toBuilder().setSchema(2).build().toByteArray()));
    }
    @Test void rejectsMalformedOversizeAndMissingBody() {
        assertThrows(IllegalArgumentException.class,()->SyncWire.parse(new byte[73729]));
        assertThrows(IllegalArgumentException.class,()->SyncWire.parse(new byte[]{10,(byte)255}));
        assertThrows(IllegalArgumentException.class,()->SyncWire.parse(SyncSchema.SyncEnvelope.newBuilder().setSchema(1).build().toByteArray()));
    }
    @Test void ackCarriesTheExactVersionHashAndDeletedFlag() {
        var deleted=CotRecord.tombstone("test",CotRecordTest.NOW,CotRecordTest.id(1),1);
        var ack=SyncWire.parse(SyncWire.ack(deleted)).getAck();
        assertEquals(deleted.uid(),ack.getUid());assertEquals(deleted.time(),ack.getVersion().getWallMillis());
        assertArrayEquals(deleted.author(),ack.getVersion().getEudId().toByteArray());
        assertArrayEquals(deleted.hash(),ack.getHash().toByteArray());assertTrue(ack.getDeleted());
    }
}
