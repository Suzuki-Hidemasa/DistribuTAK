// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.lang.reflect.Modifier;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DhtRoutingTableTest {
    static Contact contact(int n){return new Contact(DhtIdTest.id(n));}
    static AuthenticatedPeer peer(int n){return AuthenticatedPeer.fromVerifiedDhtResponse(contact(n));}
    static DhtRoutingTable full() {
        var table=new DhtRoutingTable(DhtIdTest.id(0));
        for(int i=128;i<148;i++)table.observe(peer(i));return table;
    }
    @Test void selfDuplicatesAndBucketBoundariesDoNotInflateTheTable() {
        var table=new DhtRoutingTable(DhtIdTest.id(0));table.observe(peer(0));assertEquals(0,table.size());
        table.observe(peer(1));table.observe(peer(1));table.observe(peer(2));table.observe(peer(3));
        assertEquals(3,table.size());assertEquals(2,table.allocatedBuckets());
        assertEquals(List.of(DhtIdTest.id(2),DhtIdTest.id(3)),table.bucket(1).stream().map(AuthenticatedPeer::id).toList());
    }
    @Test void authenticatedDhtTrafficMovesAnExistingPeerToTheLruTail() {
        var table=full();table.observe(peer(128));
        assertEquals(DhtIdTest.id(129),table.bucket(7).get(0).id());
        assertEquals(DhtIdTest.id(128),table.bucket(7).get(19).id());
    }
    @Test void overflowKeepsOnlyOneReplacementAndAnAliveIncumbentWins() {
        var table=full();table.observe(peer(148));table.observe(peer(149));
        assertEquals(20,table.size());assertEquals(1,table.pendingCount());
        var probe=table.probes().get(0);assertEquals(DhtIdTest.id(128),probe.incumbent().id());
        table.resolve(probe,true);assertEquals(0,table.pendingCount());
        assertEquals(DhtIdTest.id(128),table.bucket(7).get(19).id());
        assertFalse(table.nearest(DhtIdTest.id(148),20).stream().anyMatch(p->p.id().equals(DhtIdTest.id(148))));
    }
    @Test void timedOutIncumbentIsReplacedByTheFirstWaitingPeer() {
        var table=full();table.observe(peer(148));table.observe(peer(149));
        table.resolve(table.probes().get(0),false);
        assertEquals(20,table.size());assertEquals(DhtIdTest.id(129),table.bucket(7).get(0).id());
        assertEquals(DhtIdTest.id(148),table.bucket(7).get(19).id());
    }
    @Test void otherAuthenticatedDhtTrafficCancelsTheProbeAndStaleTimeoutCannotEvictIt() {
        var table=full();table.observe(peer(148));var probe=table.probes().get(0);
        table.observe(peer(128));assertEquals(0,table.pendingCount());table.resolve(probe,false);
        assertEquals(DhtIdTest.id(128),table.bucket(7).get(19).id());
    }
    @Test void unverifiedContactsCannotBePassedToTheAdmissionMethod() throws Exception {
        assertEquals(0,AuthenticatedPeer.class.getConstructors().length);
        assertFalse(Modifier.isPublic(AuthenticatedPeer.class.getDeclaredMethod("fromVerifiedDhtResponse",Contact.class).getModifiers()));
        assertThrows(NoSuchMethodException.class,()->DhtRoutingTable.class.getMethod("observe",Contact.class));
        assertFalse(AuthenticatedPeer.class.isAssignableFrom(Contact.class));
    }
    @Test void nearestPeersUseXorDistanceAndReturnAnImmutableSnapshot() {
        var table=new DhtRoutingTable(DhtIdTest.id(0));for(int i=1;i<=32;i++)table.observe(peer(i));
        var nearest=table.nearest(DhtIdTest.id(31),3);
        assertEquals(List.of(DhtIdTest.id(31),DhtIdTest.id(30),DhtIdTest.id(29)),nearest.stream().map(AuthenticatedPeer::id).toList());
        assertThrows(UnsupportedOperationException.class,nearest::clear);
        table.clear();assertEquals(3,nearest.size());assertEquals(0,table.size());assertEquals(0,table.allocatedBuckets());
    }
    @Test void clearingTheNetworkAlsoDiscardsReplacementsAndPendingProbes() {
        var table=full();table.observe(peer(148));var probe=table.probes().get(0);table.clear();
        assertEquals(0,table.pendingCount());table.resolve(probe,false);assertEquals(0,table.size());
    }
    @Test void removeDropsOnlyThatPeerAndReportsWhetherItWasThere() {
        var table=full();assertTrue(table.remove(DhtIdTest.id(130)));assertEquals(19,table.size());
        assertFalse(table.remove(DhtIdTest.id(130)));assertFalse(table.remove(DhtIdTest.id(5)));assertFalse(table.remove(DhtIdTest.id(0)));
        assertEquals(19,table.size());
        assertTrue(table.bucket(7).stream().noneMatch(p->p.id().equals(DhtIdTest.id(130))));
        assertTrue(table.nearest(DhtIdTest.id(130),20).stream().noneMatch(p->p.id().equals(DhtIdTest.id(130))));
    }
    @Test void removingAnIncumbentOrAWaitingReplacementAlsoClearsThePendingProbe() {
        var table=full();table.observe(peer(148));var probe=table.probes().get(0);
        assertTrue(table.remove(DhtIdTest.id(128)));assertEquals(0,table.pendingCount());assertEquals(19,table.size());
        table.resolve(probe,false);assertEquals(19,table.size());
        var again=full();again.observe(peer(148));var second=again.probes().get(0);
        assertFalse(again.remove(DhtIdTest.id(148)));assertEquals(0,again.pendingCount());
        again.resolve(second,false);assertEquals(20,again.size());
        assertTrue(again.nearest(DhtIdTest.id(148),20).stream().noneMatch(p->p.id().equals(DhtIdTest.id(148))));
    }
    @Test void aRemovedPeerCanBeObservedAgainAndTheTableKeepsWorking() {
        var table=full();table.remove(DhtIdTest.id(129));table.observe(peer(129));assertEquals(20,table.size());
        assertEquals(DhtIdTest.id(129),table.bucket(7).get(19).id());
    }
}
