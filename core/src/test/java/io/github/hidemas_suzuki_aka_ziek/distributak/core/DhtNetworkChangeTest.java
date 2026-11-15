// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.AuthenticatedPeer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtNode;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.LocalNetwork;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C1 直し: ネットワークが変わったら、世代とサブネットを 1 回の呼び出しでそろえる。 */
class DhtNetworkChangeTest {
    private final SessionManagerTest t=new SessionManagerTest();
    private static DhtNode<Integer> node(byte[] local) {
        return new DhtNode<>(new DhtId(local),Clock.systemUTC(),System::nanoTime,(destination,request)->true,
            (key,bytes,clock)->1,Integer::compare);
    }
    @Test void oneCallTakesTheSessionGenerationAndTheSubnetTogether() {
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            t.connect(a,b);
            var node=node(a.id);
            var before=AuthenticatedPeer.fromVerifiedSession(a.sessions.verifiedSession(b.id));
            node.observe(before);assertEquals(1,node.routing().size());
            a.sessions.forgetAllVolatile();
            node.networkChanged(a.sessions.generation(),new LocalNetwork(new byte[]{(byte)192,(byte)168,10,5},24));
            assertEquals(a.sessions.generation(),node.generation());
            assertEquals(0,node.routing().size());
            // 古い世代から作った相手の受信は通らず、新しい VerifiedSession から作った相手は通る。
            node.observe(before);assertEquals(0,node.routing().size());
            var after=AuthenticatedPeer.fromVerifiedSession(a.sessions.verifiedSession(b.id));
            node.observe(after);assertEquals(1,node.routing().size());
        }
    }
    @Test void aCallWhoseGenerationHasNotAdvancedIsRefusedAndChangesNothing() {
        try(var a=t.new Node(1);var b=t.new Node(2)) {
            t.connect(a,b);
            var node=node(a.id);
            var peer=AuthenticatedPeer.fromVerifiedSession(a.sessions.verifiedSession(b.id));
            node.observe(peer);
            var network=new LocalNetwork(new byte[]{(byte)192,(byte)168,10,5},24);
            // セッション側の世代がまだ 0 のまま（ノードも 0）。
            assertThrows(IllegalArgumentException.class,()->node.networkChanged(a.sessions.generation(),network));
            assertEquals(0,node.generation());assertEquals(1,node.routing().size());
            assertThrows(NullPointerException.class,()->node.networkChanged(5,null));
            assertEquals(0,node.generation());assertEquals(1,node.routing().size());
        }
    }
}
