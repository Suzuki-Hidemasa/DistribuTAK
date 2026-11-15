// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** PC 上の参考値。性能の合否のしきい値は置かない。通信は行わない。 */
class SessionPerformanceTest {
    @Test void fiftyEstablishedPeers() {
        var fixture=new SessionManagerTest();var nodes=new ArrayList<SessionManagerTest.Node>();
        try(var center=fixture.new Node(1)) {
            try {
                for(int n=2;n<=51;n++) {
                    var peer=fixture.new Node(n);nodes.add(peer);fixture.connect(center,peer);
                }
                var remote=nodes.get(0);
                for(int n=0;n<10;n++) {
                    center.sessions.refresh();
                    remote.sessions.receive(center.sessions.send(remote.id,new byte[]{1}).get(0).packet());
                    center.sessions.receive(remote.sessions.send(center.id,new byte[]{2}).get(0).packet());
                }
                long[] refresh=new long[50],send=new long[50],receive=new long[50];
                for(int n=0;n<50;n++) {
                    long began=System.nanoTime();center.sessions.refresh();refresh[n]=System.nanoTime()-began;
                    began=System.nanoTime();var out=center.sessions.send(remote.id,new byte[]{1});send[n]=System.nanoTime()-began;
                    assertArrayEquals(new byte[]{1},remote.sessions.receive(out.get(0).packet()).plaintext());
                    byte[] packet=remote.sessions.send(center.id,new byte[]{2}).get(0).packet();
                    began=System.nanoTime();var result=center.sessions.receive(packet);receive[n]=System.nanoTime()-began;
                    assertArrayEquals(new byte[]{2},result.plaintext());
                }
                print("refresh",refresh);print("send",send);print("receive",receive);
                System.out.println("benchmark java="+System.getProperty("java.version")+" os="+System.getProperty("os.name")+" arch="+System.getProperty("os.arch"));
            } finally { nodes.forEach(SessionManagerTest.Node::close); }
        }
    }
    private static void print(String name,long[] values) {
        Arrays.sort(values);
        System.out.printf(Locale.ROOT,"50 peers %s samples=50 mean_ms=%.3f median_ms=%.3f p95_ms=%.3f max_ms=%.3f%n",
                name,Arrays.stream(values).average().orElseThrow()/1e6,values[25]/1e6,values[47]/1e6,values[49]/1e6);
    }
}
