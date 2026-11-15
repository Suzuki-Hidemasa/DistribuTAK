// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C1: 使ってよい番地は、自分と同じサブネットの別の端末だけ（答え 181 の 8）。 */
class LocalNetworkTest {
    static byte[] ip(int a,int b,int c,int d){return new byte[]{(byte)a,(byte)b,(byte)c,(byte)d};}
    private final LocalNetwork net=new LocalNetwork(ip(192,168,10,5),24);
    @Test void onlyOtherHostsInTheSameSubnetAreAllowed() {
        assertTrue(net.allows(ip(192,168,10,6),4000));assertTrue(net.allows(ip(192,168,10,254),65535));
        assertFalse(net.allows(ip(192,168,11,6),4000));assertFalse(net.allows(ip(10,0,0,6),4000));
    }
    @Test void selfNetworkAndBroadcastAreRefused() {
        assertFalse(net.allows(ip(192,168,10,5),4000));
        assertFalse(net.allows(ip(192,168,10,0),4000));assertFalse(net.allows(ip(192,168,10,255),4000));
    }
    @Test void anyLoopbackAndMulticastAreRefusedEvenInsideTheSubnetMask() {
        var wide=new LocalNetwork(ip(10,0,0,5),8);
        assertFalse(wide.allows(ip(0,0,0,0),4000));assertFalse(wide.allows(ip(127,0,0,1),4000));assertFalse(wide.allows(ip(224,0,0,1),4000));
        var loopback=new LocalNetwork(ip(127,0,0,1),8);assertFalse(loopback.allows(ip(127,0,0,2),4000));
        var multicast=new LocalNetwork(ip(224,0,0,5),4);assertFalse(multicast.allows(ip(224,0,0,6),4000));
        assertTrue(wide.allows(ip(10,9,8,7),4000));
    }
    @Test void thePortMustBeBetween1And65535() {
        assertFalse(net.allows(ip(192,168,10,6),0));assertFalse(net.allows(ip(192,168,10,6),65536));assertFalse(net.allows(ip(192,168,10,6),-1));
        assertTrue(net.allows(ip(192,168,10,6),1));
    }
    @Test void unknownSlash31Slash32AndSlash0AreNotUsed() {
        for(int prefix:new int[]{LocalNetwork.UNKNOWN_PREFIX,0,31,32}) {
            var closed=new LocalNetwork(ip(192,168,10,5),prefix);assertFalse(closed.usable());
            assertFalse(closed.allows(ip(192,168,10,6),4000));
        }
        assertTrue(new LocalNetwork(ip(192,168,10,5),30).usable());assertTrue(new LocalNetwork(ip(192,168,10,5),1).usable());
        assertTrue(new LocalNetwork(ip(192,168,10,5),30).allows(ip(192,168,10,6),4000));
        assertFalse(new LocalNetwork(ip(192,168,10,5),30).allows(ip(192,168,10,7),4000));
    }
    @Test void badInputsAreRefusedWithoutShowingValues() {
        assertThrows(IllegalArgumentException.class,()->new LocalNetwork(null,24));
        assertThrows(IllegalArgumentException.class,()->new LocalNetwork(new byte[3],24));
        assertThrows(IllegalArgumentException.class,()->new LocalNetwork(ip(1,2,3,4),33));
        assertThrows(IllegalArgumentException.class,()->new LocalNetwork(ip(1,2,3,4),-2));
        assertFalse(net.allows(null,4000));assertFalse(net.allows(new byte[5],4000));
        assertEquals("Local network",net.toString());
    }
    @Test void equalityFollowsTheAddressAndThePrefix() {
        assertEquals(net,new LocalNetwork(ip(192,168,10,5),24));assertEquals(net.hashCode(),new LocalNetwork(ip(192,168,10,5),24).hashCode());
        assertNotEquals(net,new LocalNetwork(ip(192,168,10,5),25));assertNotEquals(net,new LocalNetwork(ip(192,168,10,6),24));
    }
}
