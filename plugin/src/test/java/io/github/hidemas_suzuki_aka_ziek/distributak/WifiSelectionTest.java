// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.Inet4Address;
import java.net.InetAddress;
import org.junit.Test;

/** 選んだ Wi-Fi が前と同じ LAN かの比べ。違うなら DHT は止めて作り直す。 */
public class WifiSelectionTest {
    private static Inet4Address ip(int last) throws Exception {
        return (Inet4Address)InetAddress.getByAddress(new byte[]{(byte)192,0,2,(byte)last});
    }

    @Test public void sameNetworkAddressAndPrefixIsTheSameLan() throws Exception {
        Object network=new Object();
        assertTrue(WifiLan.Selection.sameLan(network,ip(5),24,network,ip(5),24));
    }

    @Test public void differentPrefixIsAnotherLan() throws Exception {
        Object network=new Object();
        assertFalse(WifiLan.Selection.sameLan(network,ip(5),24,network,ip(5),26));
    }

    @Test public void differentAddressIsAnotherLan() throws Exception {
        Object network=new Object();
        assertFalse(WifiLan.Selection.sameLan(network,ip(5),24,network,ip(6),24));
    }

    @Test public void differentNetworkIsAnotherLan() throws Exception {
        assertFalse(WifiLan.Selection.sameLan(new Object(),ip(5),24,new Object(),ip(5),24));
    }
}
