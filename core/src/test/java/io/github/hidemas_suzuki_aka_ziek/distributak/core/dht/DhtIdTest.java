// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DhtIdTest {
    static DhtId id(int value) {
        byte[] bytes=new byte[32];bytes[30]=(byte)(value>>>8);bytes[31]=(byte)value;return new DhtId(bytes);
    }
    @Test void identityUsesAllThirtyTwoPublicKeyBytes() {
        byte[] publicKey=Crypto.ed25519Public(new byte[32]);
        assertArrayEquals(Crypto.blake2s(publicKey),DhtId.fromIdentityPublicKey(publicKey).bytes());
        assertThrows(IllegalArgumentException.class,()->DhtId.fromIdentityPublicKey(new byte[31]));
        assertThrows(IllegalArgumentException.class,()->new DhtId(new byte[16]));
        assertThrows(IllegalArgumentException.class,()->new DhtId(null));
    }
    @Test void equalIdsHaveZeroDistanceAndNoBucket() {
        assertEquals(id(7),id(7));assertEquals(id(7).hashCode(),id(7).hashCode());
        assertEquals(-1,id(7).bucketIndex(id(7)));assertArrayEquals(new byte[32],id(7).distance(id(7)));
    }
    @Test void lowAndHighBitsChooseBucketsZeroAndTwoHundredFiftyFive() {
        byte[] high=new byte[32];high[0]=(byte)0x80;
        assertEquals(0,id(0).bucketIndex(id(1)));assertEquals(255,id(0).bucketIndex(new DhtId(high)));
        for(int bit=0;bit<256;bit++) {
            byte[] bytes=new byte[32];bytes[31-bit/8]=(byte)(1<<(bit%8));
            assertEquals(bit,id(0).bucketIndex(new DhtId(bytes)));
        }
    }
    @Test void distanceOrderingIsUnsignedAndUsesTheTarget() {
        byte[] high=new byte[32];high[0]=(byte)0x80;
        assertTrue(id(0).compareDistance(id(1),new DhtId(high))<0);
        assertTrue(id(15).compareDistance(id(14),id(1))<0);
        assertEquals(0,id(15).compareDistance(id(14),id(14)));
    }
    @Test void orderingAgreesWithIndependentUnsignedIntegerOracle() {
        var random=new Random(1712);
        for(int n=0;n<200;n++) {
            byte[] target=new byte[32],left=new byte[32],right=new byte[32];
            random.nextBytes(target);random.nextBytes(left);random.nextBytes(right);
            var t=new DhtId(target);var l=new DhtId(left);var r=new DhtId(right);
            int expected=new BigInteger(1,target).xor(new BigInteger(1,left))
                    .compareTo(new BigInteger(1,target).xor(new BigInteger(1,right)));
            assertEquals(Integer.signum(expected),Integer.signum(t.compareDistance(l,r)));
            assertEquals(new BigInteger(1,target).xor(new BigInteger(1,left)).bitLength()-1,t.bucketIndex(l));
        }
    }
    @Test void publicArraysCannotChangeAnIdAndTextDoesNotExposeIt() {
        byte[] bytes=new byte[32];bytes[0]=42;var value=new DhtId(bytes);bytes[0]=7;
        byte[] copy=value.bytes();copy[0]=8;
        assertEquals(42,value.bytes()[0]);assertEquals("DHT identifier",value.toString());
    }
}
