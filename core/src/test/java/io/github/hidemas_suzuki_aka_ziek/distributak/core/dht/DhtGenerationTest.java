// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C1: ネットワークが変わったあとの古い世代の受信を、核の口で止める。 */
class DhtGenerationTest {
    private static AuthenticatedPeer peer(int number,long generation) {
        return AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(DhtIdTest.id(number)),generation);
    }
    @Test void generationStartsAtZeroAndGrowsOnlyWhenTheNetworkChanges() {
        var f=new DhtNodeTest.Fixture();assertEquals(0,f.node.generation());
        f.node.poll();assertEquals(0,f.node.generation());
        f.node.networkChanged();assertEquals(1,f.node.generation());
        f.node.networkChanged();assertEquals(2,f.node.generation());
    }
    @Test void theNodeTakesTheSessionGenerationAndNeverGoesBack() {
        var f=new DhtNodeTest.Fixture();f.node.observe(peer(1,0));
        f.node.networkChanged(5);assertEquals(5,f.node.generation());assertEquals(0,f.node.routing().size());
        f.node.observe(peer(1,4));assertEquals(0,f.node.routing().size());
        f.node.observe(peer(1,5));assertEquals(1,f.node.routing().size());
        assertThrows(IllegalArgumentException.class,()->f.node.networkChanged(5));
        assertThrows(IllegalArgumentException.class,()->f.node.networkChanged(3));
        assertEquals(5,f.node.generation());
    }
    @Test void observeFromAnOldGenerationIsDroppedAndTheNewGenerationIsAccepted() {
        var f=new DhtNodeTest.Fixture();f.node.observe(peer(1,0));assertEquals(1,f.node.routing().size());
        f.node.networkChanged();assertEquals(0,f.node.routing().size());
        f.node.observe(peer(1,0));assertEquals(0,f.node.routing().size());
        f.node.observe(peer(1,1));assertEquals(1,f.node.routing().size());
    }
    @Test void aReplyFromAnOldGenerationIsDroppedEvenWithANewRequestNumber() {
        var f=new DhtNodeTest.Fixture();f.node.networkChanged();
        f.delivery.known.add(DhtIdTest.id(1));f.node.observe(peer(1,1));
        var lookup=f.node.findNode(DhtIdTest.id(0));f.node.poll();var sent=f.delivery.take();
        // 要求の番号は新しいので境目の比べは通る。世代だけで止まる。
        f.delivery.known.add(DhtIdTest.id(2));
        f.node.receive(peer(1,0),sent.request().id(),List.of(new Contact(DhtIdTest.id(2))),null);
        f.node.poll();assertTrue(f.delivery.waiting.isEmpty());assertFalse(lookup.done());
        f.node.receive(peer(1,1),sent.request().id(),List.of(new Contact(DhtIdTest.id(2))),null);
        f.node.poll();assertEquals(DhtIdTest.id(2),f.delivery.take().destination().id());
    }
    @Test void aPeerWithoutAGenerationKeepsTheCoreTestsWorking() {
        var f=new DhtNodeTest.Fixture();f.node.networkChanged();
        f.node.observe(AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(DhtIdTest.id(1))));
        assertEquals(1,f.node.routing().size());
    }
    @Test void aMissingSessionIsRefused() {
        assertThrows(NullPointerException.class,()->AuthenticatedPeer.fromVerifiedSession(null));
    }
    @Test void aNetworkChangeAlsoDropsTheCandidatesAndTheNewNetworkIsKept() {
        var f=new DhtNodeTest.Fixture();var candidates=f.node.candidates();
        candidates.setNetwork(new LocalNetwork(LocalNetworkTest.ip(192,168,10,5),24));
        assertTrue(candidates.offer(DhtIdTest.id(1),DhtCandidatesTest.candidate(100,10,4000)));assertEquals(1,candidates.size());
        f.node.networkChanged();assertEquals(0,candidates.size());
        // 世代だけ進めても、候補は使える状態に戻らない（新しいネットワークの値が渡るまで何も入らない）。
        assertFalse(candidates.offer(DhtIdTest.id(1),DhtCandidatesTest.candidate(101,11,4000)));
        f.node.networkChanged(new LocalNetwork(LocalNetworkTest.ip(172,16,0,9),16));assertEquals(2,f.node.generation());
        assertFalse(candidates.offer(DhtIdTest.id(1),DhtCandidatesTest.candidate(101,11,4000)));
        assertTrue(candidates.offer(DhtIdTest.id(1),new DhtCandidates.Candidate(DhtIdTest.id(101),LocalNetworkTest.ip(172,16,0,10),4000,new byte[32])));
    }
}
