// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ManagedDhtWireTest {
    static byte[] managed(byte[] legacy)throws Exception{
        var outer=SyncSchema.SyncEnvelope.parseFrom(legacy);
        return outer.toBuilder().setSchema(3).setDht(outer.getDht().toBuilder().setSchema(2)).build().toByteArray();
    }
    @Test void managedStoreUsesTheExistingDhtBodyWithItsOwnSchemas()throws Exception{
        byte[] wire=managed(DhtWire.store(new byte[32],new byte[16],new DhtId(new byte[32]),new byte[]{1}));
        assertTrue(DhtWire.isDht(wire));
        assertEquals(DhtWire.Op.STORE,DhtWire.parse(wire).op());
    }
    @Test void managedValueIsRecognizedWithoutOpeningRecordContents()throws Exception{
        byte[] wire=managed(DhtWire.value(new byte[32],new byte[16],new DhtId(new byte[32]),new byte[]{1}));
        assertEquals(DhtWire.Op.VALUE,DhtWire.parse(wire).op());
    }
    @Test void mixedSchemasAndUnknownFieldsRemainRejected()throws Exception{
        var legacy=SyncSchema.SyncEnvelope.parseFrom(DhtWire.findValue(new byte[32],new byte[16],new DhtId(new byte[32])));
        assertThrows(IllegalArgumentException.class,()->DhtWire.parse(legacy.toBuilder().setSchema(3).build().toByteArray()));
        assertThrows(IllegalArgumentException.class,()->DhtWire.parse(legacy.toBuilder().setDht(legacy.getDht().toBuilder().setSchema(2)).build().toByteArray()));
        byte[] valid=managed(legacy.toByteArray());byte[] unknown=java.util.Arrays.copyOf(valid,valid.length+2);unknown[valid.length]=120;
        assertThrows(IllegalArgumentException.class,()->DhtWire.parse(unknown));
    }
}
