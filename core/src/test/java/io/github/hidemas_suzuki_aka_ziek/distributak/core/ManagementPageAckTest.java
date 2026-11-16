// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementWire.*;

class ManagementPageAckTest {
    ManagementPageAck ack(boolean complete){
        return new ManagementPageAck(new byte[32],new byte[16],new byte[32],new int[]{3068,3069,3070,3071},complete);
    }
    @Test void completionZeroAndOneRoundTripExplicitlyWithinOneHundredTwentyEightBytes()throws Exception{
        for(boolean complete:new boolean[]{false,true}){
            var ack=ack(complete);var wire=ack.encode();
            assertEquals(complete,ManagementPageAck.decode(wire).complete());
            assertEquals(complete,ManagementPageAck.decodeEnvelope(ack.envelope()).complete());
            assertArrayEquals(wire,ManagementPageAck.decode(wire).encode());
            assertEquals(48,wire[wire.length-2]);assertEquals(complete?1:0,wire[wire.length-1]);
            assertTrue(wire.length<=128);assertTrue(ack.envelope().length<=128);
            assertEquals(complete?1:0,SyncSchema.ManagementPageAck.parseFrom(wire).getComplete());
        }
    }
    @Test void missingUnknownOutOfOrderDuplicateAndOutOfRangeCompletionAreRejected(){
        byte[] wire=ack(false).encode(),prefix=Arrays.copyOf(wire,wire.length-2);
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(prefix));
        for(int value:new int[]{2,127,255}){
            byte[] bad=wire.clone();bad[bad.length-1]=(byte)value;
            assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(bad));
        }
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(Crypto.concat(wire,new byte[]{56,0})));
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(Crypto.concat(wire,new byte[]{48,0})));
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(Crypto.concat(wire,new byte[]{0})));
        byte[] reordered=write(out->{out.writeUInt32(1,1);out.writeByteArray(2,new byte[32]);
            out.writeByteArray(3,new byte[16]);out.writeByteArray(4,new byte[32]);out.writeUInt32(6,0);out.writeByteArray(5,new byte[]{0});});
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(reordered));
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(Crypto.concat(prefix,new byte[]{48,(byte)128,0})));
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(Crypto.concat(prefix,new byte[]{48,(byte)128,(byte)128,(byte)128,(byte)128,16})));
    }
}
