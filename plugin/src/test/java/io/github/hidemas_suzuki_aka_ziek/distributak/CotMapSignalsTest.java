// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class CotMapSignalsTest {
    @Test public void coalescesByUidKeepsImportAndSchedulesOneBoundedDrain(){
        var q=new CotMapSignals();assertTrue(q.offer("a",1,0));assertFalse(q.offer("a",1,1));assertFalse(q.offer("a",1,4));
        var b=q.drain(1);assertEquals(1,b.kinds().size());assertEquals(Integer.valueOf(19),b.kinds().get("a"));assertFalse(b.overflow());
        assertTrue(q.offer("new",1,0));assertTrue(q.drain(2).kinds().isEmpty());
    }
    @Test public void capacityCannotKeepUnboundedNotificationsAndDrainClearsOverflow(){
        var q=new CotMapSignals();for(int i=0;i<4097;i++)q.offer("a"+i,1,0);
        var b=q.drain(1);assertEquals(4096,b.kinds().size());assertTrue(b.overflow());assertFalse(q.drain(1).overflow());
    }
}
