// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.nio.charset.StandardCharsets;
import java.util.Set;
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
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],0,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],7,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],257,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[31],1,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],1,new byte[31]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(null,1,new byte[32]));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(new byte[32],1,null));
    }
    /** 管理の種類 2〜6 は同じ式で鍵を作る。種類 2・3・6 の宛先は 32 バイトの 0 だけ。 */
    @Test void managementKindsUseTheSameFormulaAndKinds236AcceptOnlyTheZeroSubject() {
        byte[] group=DhtIdTest.id(9).bytes(),zero=new byte[32];
        for(int kind:new int[]{2,3,6}) {
            byte[] expected=Crypto.blake2s(Crypto.concat("DistribuTAK/dht-key/v1".getBytes(StandardCharsets.US_ASCII),group,new byte[]{(byte)kind},zero));
            assertArrayEquals(expected,DhtKeys.derive(group,kind,zero).bytes());
            byte[] other=zero.clone();other[31]=1;
            assertThrows(IllegalArgumentException.class,()->DhtKeys.derive(group,kind,other));
        }
        assertEquals(2,DhtKeys.LATEST_ADMINS);assertEquals(3,DhtKeys.LATEST_REVOCATIONS);assertEquals(4,DhtKeys.WRAPPED_KEY);
        assertEquals(5,DhtKeys.ADMIN_HISTORY);assertEquals(6,DhtKeys.KEY_ANNOUNCEMENT);
        assertEquals(6,Set.of(DhtKeys.derive(group,1,zero),DhtKeys.derive(group,2,zero),DhtKeys.derive(group,3,zero),
                DhtKeys.derive(group,4,zero),DhtKeys.derive(group,5,zero),DhtKeys.derive(group,6,zero)).size());
    }
    /** 種類 5 の宛先は、固定の前置きと、版を 8 バイトの大きい順で並べた値の BLAKE2s。 */
    @Test void adminHistorySubjectHashesThePrefixAndTheBigEndianVersion() {
        byte[] expected=Crypto.blake2s(Crypto.concat("DistribuTAK/admin-history/v1".getBytes(StandardCharsets.US_ASCII),
                new byte[]{0,0,0,0,0,0,1,2}));
        assertArrayEquals(expected,DhtKeys.adminHistorySubject(258));
        assertFalse(java.util.Arrays.equals(DhtKeys.adminHistorySubject(1),DhtKeys.adminHistorySubject(2)));
        assertThrows(IllegalArgumentException.class,()->DhtKeys.adminHistorySubject(-1));
        byte[] group=DhtIdTest.id(9).bytes();
        assertEquals(DhtKeys.hash(group,(byte)5,expected),DhtKeys.derive(group,5,expected));
    }
    /** 種類 4 の宛先は端末の識別子 32 バイト。 */
    @Test void wrappedKeySubjectIsAnyThirtyTwoByteMemberIdentifier() {
        byte[] group=DhtIdTest.id(9).bytes();
        assertNotEquals(DhtKeys.derive(group,4,DhtIdTest.id(1).bytes()),DhtKeys.derive(group,4,DhtIdTest.id(2).bytes()));
        assertNotEquals(DhtKeys.derive(group,4,DhtIdTest.id(1).bytes()),DhtKeys.derive(group,1,DhtIdTest.id(1).bytes()));
    }
}
