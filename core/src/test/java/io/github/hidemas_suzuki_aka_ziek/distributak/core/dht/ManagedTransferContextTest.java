// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ManagedTransferContextTest {
    @Test void contextKeepsRequestKeyPeerSessionAndGenerationWithoutSharingMutableArrays() {
        byte[] request=new byte[16],session=new byte[16];
        request[0]=1;session[0]=2;
        var context=new ManagedTransferContext(DhtIdTest.id(1),session,17,request,DhtIdTest.id(2),DhtWire.TransferKind.STORE);
        request[0]=3;session[0]=4;
        assertEquals(DhtIdTest.id(1),context.peer());
        assertEquals(DhtIdTest.id(2),context.key());
        assertEquals(17,context.generation());
        assertEquals(1,context.requestId()[0]);assertEquals(2,context.sessionId()[0]);
        context.requestId()[0]=5;context.sessionId()[0]=6;
        assertEquals(1,context.requestId()[0]);assertEquals(2,context.sessionId()[0]);
        assertEquals("Managed transfer context",context.toString());
    }
}
