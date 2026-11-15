// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** しきい値を置かないPC上の参考値。ソケットは開かない。 */
class CookiePerformanceTest {
    @Test void cookieAndIncomingHandshakeCost() {
        byte[] first=AddressCookiesTest.first(433);
        try(var cookies=new AddressCookies(System::nanoTime)) {
            byte[] cookie=cookies.issue(first,AddressCookiesTest.SOURCE);
            for(int i=0;i<100;i++)assertTrue(cookies.verify(cookie,first,AddressCookiesTest.SOURCE));
            long[] issue=new long[5000],verify=new long[5000];
            for(int i=0;i<issue.length;i++) {
                long began=System.nanoTime();byte[] made=cookies.issue(first,AddressCookiesTest.SOURCE);issue[i]=System.nanoTime()-began;
                began=System.nanoTime();assertTrue(cookies.verify(made,first,AddressCookiesTest.SOURCE));verify[i]=System.nanoTime()-began;Crypto.wipe(made);
            }
            print("cookie-issue",issue);print("cookie-verify",verify);Crypto.wipe(cookie);
        }
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)) {
            a.remember(b);b.remember(a);long[] values=new long[50];
            for(int i=-10;i<50;i++) {
                byte[] request=a.sessions.start(b.id).packet();b.sessions.refresh();long began=System.nanoTime();
                var reply=b.sessions.receive(request);long took=System.nanoTime()-began;
                if(i>=0)values[i]=took;
                b.sessions.receive(a.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());f.time.advance(5);
            }
            print("incoming-handshake",values);
        }
    }
    static void print(String name,long[] values) {
        Arrays.sort(values);System.out.printf(Locale.ROOT,"%s samples=%d mean_us=%.3f median_us=%.3f p95_us=%.3f max_us=%.3f%n",
            name,values.length,Arrays.stream(values).average().orElseThrow()/1000,values[values.length/2]/1000.0,values[(int)(values.length*.95)-1]/1000.0,values[values.length-1]/1000.0);
    }
}
