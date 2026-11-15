// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.Set;
import org.junit.Test;
import static org.junit.Assert.*;

public class CotFenceTest {
    @Test public void delayedSuccessCannotBeatTimeoutByArrivingBeforePoll(){
        var late=new CotFence();late.begin(0);late.registered(true,5_000_000_001L);assertFalse(late.ready());assertTrue(late.failed());
        var edge=new CotFence();edge.begin(0);edge.registered(true,5_000_000_000L);assertFalse(edge.ready());assertTrue(edge.failed());
        var timely=new CotFence();timely.begin(0);timely.registered(true,4_900_000_000L);timely.poll(6_000_000_000L);assertTrue(timely.ready());assertFalse(timely.failed());
    }
    @Test public void blocksReceivedUidAndDeletionTargetsOnlyAfterSavedRegistry() {
        var gate=new CotFence();gate.begin(0);gate.registered(true,0);
        assertFalse(gate.consume("received",false,Set.of()));
        gate.saved(Set.of("received"));
        assertTrue(gate.consume("received",false,Set.of()));
        assertTrue(gate.consume("delete-event",true,Set.of("received")));
        assertFalse(gate.consume("local",false,Set.of("received")));
        assertFalse(gate.consume("local",false,Set.of()));
        assertFalse(gate.consume(null,false,Set.of()));assertFalse(gate.contains(null));
        assertEquals(2,gate.consumed());
    }
    @Test public void timeoutAndLostRegistrationPreventImportWithoutRetry() {
        var gate=new CotFence();gate.begin(1);assertFalse(gate.ready());gate.poll(5_000_000_000L);assertFalse(gate.failed());
        gate.poll(5_000_000_001L);assertTrue(gate.failed());gate.registered(true,0);assertFalse(gate.ready());
        var active=new CotFence();active.begin(0);active.registered(true,0);assertTrue(active.ready());
        active.registered(false,0);assertTrue(active.failed());assertFalse(active.ready());active.registered(true,0);assertFalse(active.ready());
    }
    @Test public void stopRemovesRegistryAndLateRegistrationCannotRevive() {
        var gate=new CotFence();gate.begin(0);gate.saved(Set.of("received"));gate.registered(true,0);gate.stop();gate.registered(true,0);
        assertFalse(gate.ready());assertFalse(gate.consume("received",false,Set.of()));
    }
}
