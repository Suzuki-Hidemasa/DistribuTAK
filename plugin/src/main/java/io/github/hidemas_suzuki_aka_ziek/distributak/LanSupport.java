// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

/** Androidに依存しない番地・ポート・秘密を含まない試験の印。 */
final class LanSupport {
    private LanSupport() {}
    static Inet4Address selectIpv4(Collection<InetAddress> candidates) {
        Inet4Address selected=null;
        for(InetAddress candidate:candidates) {
            if(!(candidate instanceof Inet4Address) || candidate.isAnyLocalAddress() || candidate.isLoopbackAddress()
                    || candidate.isLinkLocalAddress() || candidate.isMulticastAddress()) continue;
            if(selected==null || compare(candidate.getAddress(),selected.getAddress())<0) selected=(Inet4Address)candidate;
        }
        return selected;
    }
    private static int compare(byte[] a,byte[] b) {
        for(int i=0;i<a.length;i++){int n=(a[i]&255)-(b[i]&255);if(n!=0)return n;}return 0;
    }
    static int port(Integer saved,Random random) {
        if(saved==null)return 49152+random.nextInt(16384);
        if(saved<49152 || saved>65535)throw new IllegalArgumentException("ポートの範囲が違います");
        return saved;
    }
    static byte[] testData(){return "DT-LAN-TEST\u0001".getBytes(StandardCharsets.US_ASCII);}
    static boolean isTestData(byte[] bytes){return Crypto.equal(testData(),bytes);}
    static String shortId(byte[] id) {
        if(id.length!=32)throw new IllegalArgumentException("IDの長さが違います");
        char[] out=new char[8];String alphabet="0123456789abcdef";
        for(int i=0;i<4;i++){out[i*2]=alphabet.charAt((id[i]&255)>>>4);out[i*2+1]=alphabet.charAt(id[i]&15);}return new String(out);
    }
    static String receipt(long count,byte[] id){return "LAN_TEST_RX count="+count+" peer="+shortId(id);}
}
