// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.net.*;import java.util.*;
import org.junit.Test;import static org.junit.Assert.*;
public class WifiStateTest {
    static LanRuntime.Link link(String key,Inet4Address ip){return new LanRuntime.Link(){
        public Inet4Address address(){return ip;}
        public boolean same(LanRuntime.Link other){return other!=null&&toString().equals(other.toString());}
        public io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.DatagramIo open(int port){throw new AssertionError("no sockets");}
        public String toString(){return key+ip.getHostAddress();}
    };}
    final InetAddress a,b;
    public WifiStateTest()throws Exception{a=InetAddress.getByName("192.0.2.1");b=InetAddress.getByName("192.0.2.2");}
    @Test public void lossIpv4AndCountTransitionsAreRetainedEvenWhenSelectionReturns() {
        var state=new WifiState<String>(WifiStateTest::link);state.available("A");state.addresses("A",List.of(a));
        var initial=state.snapshot();state.lost("A");state.available("A");state.addresses("A",List.of(a));
        assertTrue(state.snapshot().revision>initial.revision);assertTrue(initial.link.same(state.snapshot().link));
        long revision=state.snapshot().revision;state.addresses("A",List.of(b));state.addresses("A",List.of(a));
        assertTrue(state.snapshot().revision>revision);assertTrue(initial.link.same(state.snapshot().link));
        revision=state.snapshot().revision;state.available("B");assertNull(state.snapshot().link);state.lost("B");
        assertTrue(state.snapshot().revision>revision);assertTrue(initial.link.same(state.snapshot().link));
    }
    @Test public void identicalCapabilitiesAndIpv4NotificationsDoNotAdvanceRevision() {
        var state=new WifiState<String>(WifiStateTest::link);state.available("A");state.addresses("A",List.of(a));
        long before=state.snapshot().revision;state.available("A");state.capabilities("A",true);state.addresses("A",List.of(a));
        assertEquals(before,state.snapshot().revision);assertNotNull(state.snapshot().link);
        state.capabilities("A",false);assertNull(state.snapshot().link);assertTrue(state.snapshot().revision>before);
    }
}
