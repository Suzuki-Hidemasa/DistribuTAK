// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

class ManagedPendingTest {
    private final AtomicLong time=new AtomicLong(NOW);
    private final Clock clock=new Clock(){
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(time.get());}
    };
    @Test void eightEntriesAreKeptAndTheNinthIsRefusedWithoutEviction() {
        var pending=new ManagedPending(clock);
        for(int i=0;i<8;i++)assertTrue(pending.offer(revocationRecord(i,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(i/2)));
        assertFalse(pending.offer(revocationRecord(9,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(9)));
        assertEquals(8,pending.size());
        assertTrue(pending.offer(revocationRecord(0,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(0)));
        assertEquals(8,pending.size());
    }
    @Test void totalBytesAreBoundedAndOldEntriesAreNotDiscarded() {
        var pending=new ManagedPending(clock);
        var a=revocationRecord(1,1,0,NOW,60000);var b=revocationRecord(2,1,0,NOW,60000);
        assertTrue(pending.offer(a,ManagedVerdict.needsVersion(1)));
        assertTrue(pending.offer(b,ManagedVerdict.needsVersion(1)));
        int bytes=a.encode().length+b.encode().length;
        assertEquals(bytes,pending.bytes());assertTrue(bytes<=ManagedPending.MAX_BYTES);
        assertFalse(pending.offer(revocationRecord(3,1,0,NOW,10000),ManagedVerdict.needsVersion(1)));
        assertEquals(bytes,pending.bytes());assertEquals(2,pending.size());
    }
    @Test void retriesDoNotExtendTheOriginalOneHundredTwentySecondDeadline() {
        var pending=new ManagedPending(clock);var record=revocationRecord(1,1,0,NOW,0);
        assertTrue(pending.offer(record,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        time.addAndGet(119999);assertTrue(pending.offer(record,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        assertEquals(1,pending.size());time.incrementAndGet();assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }
    @Test void onlyPendingVerdictsCanEnterTheQueue() {
        var pending=new ManagedPending(clock);var record=revocationRecord(1,1,0,NOW,0);
        for(var verdict:new ManagedVerdict[]{ManagedVerdict.ACCEPTED,ManagedVerdict.INVALID,ManagedVerdict.DUPLICATE,ManagedVerdict.OLD})
            assertFalse(pending.offer(record,verdict));
        assertEquals(0,pending.size());
    }
    @Test void aBackwardClockDiscardsPendingEntriesAndReleasesTheirBytes() {
        var pending=new ManagedPending(clock);
        assertTrue(pending.offer(revocationRecord(1,1,0,NOW,0),ManagedVerdict.NEEDS_ANNOUNCEMENT));
        time.decrementAndGet();assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }
    @Test void findAndStoreIdentitiesHaveIndependentLimitsAndDeadlines() {
        var pending=new ManagedPending(clock);var r=revocationRecord(1,1,0,NOW,0);
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        for(int i=1;i<8;i++)assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(i)));
        assertEquals(8,pending.size());assertEquals(8*r.encode().length,pending.bytes());
        assertFalse(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(9)));
        time.addAndGet(120000);assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }

    @Test void identicalBytesWithDifferentIdentitiesStillRespectTheByteLimit() {
        var pending=new ManagedPending(clock);var r=revocationRecord(1,1,0,NOW,60000);
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(1)));
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(2)));
        assertFalse(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(3)));
        assertEquals(2,pending.size());assertEquals(2*r.encode().length,pending.bytes());
    }
    @Test void eachIdentityHasItsOwnFirstArrivalDeadline() {
        var pending=new ManagedPending(clock);var r=revocationRecord(1,1,0,NOW,0);
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(1)));
        time.addAndGet(60000);
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(2)));
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,digest(1)));
        time.addAndGet(60000);assertEquals(1,pending.size());
        time.addAndGet(60000);assertEquals(0,pending.size());
    }

}
