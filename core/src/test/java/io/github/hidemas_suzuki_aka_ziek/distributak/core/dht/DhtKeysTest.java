// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DhtKeysTest {
    @Test void discoveryKeyIncludesTheDomainGroupKindAndWholeSubject() {
        byte[] group=new byte[32],subject=DhtIdTest.id(4).bytes();
        byte[] expected=Crypto.blake2s(Crypto.concat("DistribuTAK/dht-key/v1".getBytes(StandardCharsets.US_ASCII),group,new byte[]{1},subject));
        assertArrayEquals(expected,DhtKeys.derive(group,DhtKeys.MEMBER_DISCOVERY,subject).bytes());
        assertEquals(DhtKeys.derive(group,1,subject),DhtKeys.derive(group,1,subject));
        byte[] other=group.clone();other[31]=1;
        assertNotEquals(DhtKeys.derive(group,1,subject),DhtKeys.derive(other,1,subject));
        assertNotEquals(DhtKeys.derive(group,1,subject),DhtKeys.derive(group,1,DhtIdTest.id(5).bytes()));
        assertNotEquals(DhtKeys.hash(group,(byte)1,subject),DhtKeys.hash(group,(byte)2,subject));
    }
    @Test void unknownKindsAndWrongLengthsAreRejectedBeforeHashing() {
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],2,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[31],1,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],1,new byte[31]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(null,1,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],1,null));
    }
}
