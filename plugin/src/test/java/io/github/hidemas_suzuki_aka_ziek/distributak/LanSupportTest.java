// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class LanSupportTest {
    @Test public void onlyUsableWifiIpv4IsSelectedInNetworkOrder() throws Exception {
        var good=InetAddress.getByName("192.168.20.2");
        assertEquals(good,LanSupport.selectIpv4(Arrays.asList(InetAddress.getByName("::1"),InetAddress.getByName("fe80::1"),
                InetAddress.getByName("2001:db8::1"),InetAddress.getByName("127.0.0.1"),InetAddress.getByName("169.254.1.1"),
                InetAddress.getByName("0.0.0.0"),InetAddress.getByName("224.0.0.1"),InetAddress.getByName("192.168.20.3"),good)));
        assertNull(LanSupport.selectIpv4(Arrays.asList(InetAddress.getByName("::1"),InetAddress.getByName("169.254.1.1"))));
        assertNull(LanSupport.selectIpv4(Collections.emptyList()));
    }
    @Test public void portsStayInRangeAndSavedValueWins() {
        assertEquals(49152,LanSupport.port(null,new Random(){@Override public int nextInt(int bound){return 0;}}));
        assertEquals(65535,LanSupport.port(null,new Random(){@Override public int nextInt(int bound){return bound-1;}}));
        assertEquals(54321,LanSupport.port(54321,new Random(){@Override public int nextInt(int b){throw new AssertionError();}}));
        for(int n:new int[]{0,49151,65536}) assertThrows(IllegalArgumentException.class,()->LanSupport.port(n,new Random()));
    }
    @Test public void testPayloadAndReceiptNeverContainInput() {
        byte[] good=LanSupport.testData();assertTrue(LanSupport.isTestData(good));
        byte[] bad=good.clone();bad[0]^=1;
        assertFalse(LanSupport.isTestData(bad));assertFalse(LanSupport.isTestData(new byte[0]));
        assertFalse(LanSupport.isTestData(Arrays.copyOf(good,good.length-1)));
        assertEquals("LAN_TEST_RX count=1",LanSupport.receipt(1));
        assertFalse(LanSupport.receipt(1).contains("DT-LAN-TEST"));
    }
}
