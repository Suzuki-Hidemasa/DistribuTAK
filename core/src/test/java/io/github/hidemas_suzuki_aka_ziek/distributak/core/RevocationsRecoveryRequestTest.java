// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RevocationsRecoveryRequestTest {
    RevocationsRecoveryRequest request(long version){return new RevocationsRecoveryRequest(new byte[32],new byte[16],version,new byte[32]);}
    @Test void roundTripsAllRequiredFieldsAndEnvelope10(){
        var r=request(0);assertEquals(10,RevocationsRecoveryRequest.ENVELOPE_FIELD);
        assertArrayEquals(r.encode(),RevocationsRecoveryRequest.decode(r.encode()).encode());
        assertArrayEquals(r.envelope(),RevocationsRecoveryRequest.decodeEnvelope(r.envelope()).envelope());
    }
    @Test void uint64PreservesFullUnsignedRange(){
        for(long n:new long[]{0,Long.MAX_VALUE,Long.MIN_VALUE,-1})assertEquals(n,RevocationsRecoveryRequest.decode(request(n).encode()).requiredVersion());
    }
    @Test void missingUnknownDuplicateAndNonCanonicalFieldsAreRejected(){
        byte[] r=request(1).encode();
        for(byte[] bad:List.of(Arrays.copyOf(r,r.length-1),Crypto.concat(r,new byte[]{48,1}),Crypto.concat(r,new byte[]{8,1}),
                Crypto.concat(new byte[]{8,(byte)129,0},Arrays.copyOfRange(r,2,r.length))))
            assertThrows(IllegalArgumentException.class,()->RevocationsRecoveryRequest.decode(bad));
    }
    @Test void fixedLengthsAndSchemaAreStrict(){
        assertThrows(IllegalArgumentException.class,()->new RevocationsRecoveryRequest(new byte[31],new byte[16],0,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->new RevocationsRecoveryRequest(new byte[32],new byte[15],0,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->new RevocationsRecoveryRequest(new byte[32],new byte[16],0,new byte[31]));
        byte[] r=request(0).encode();r[1]=2;assertThrows(IllegalArgumentException.class,()->RevocationsRecoveryRequest.decode(r));
    }
    @Test void managementEnvelopeNumbersAreCentralAndUnique(){
        var numbers=ManagementEnvelopeFields.supported();assertEquals(numbers.length,Arrays.stream(numbers).distinct().count());
        assertFalse(Arrays.stream(numbers).anyMatch(n->n==6));
        assertEquals(ManagementEnvelopeFields.PAGE_ACK,ManagementPageAck.ENVELOPE_FIELD);
        assertEquals(ManagementEnvelopeFields.REVOCATIONS_RECOVERY_REQUEST,RevocationsRecoveryRequest.ENVELOPE_FIELD);
        for(var kind:ManagementPage.Kind.values())assertTrue(Arrays.stream(numbers).anyMatch(n->n==kind.envelopeField()));
    }
}
