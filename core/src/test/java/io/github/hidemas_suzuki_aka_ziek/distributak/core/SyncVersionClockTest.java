// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncVersionClockTest {
    @Test void sameMillisecondUpdatesIncreaseAcrossAllUids() {
        var clock=new SyncVersionClock(-1);
        assertEquals(1000,clock.next(1000).orElseThrow());
        assertEquals(1001,clock.next(1000).orElseThrow());
        assertEquals(1002,clock.next(1001).orElseThrow());
    }
    @Test void runtimeRollbackWaitsUntilBeyondTheMaximumEvenWithinFiveMinutes() {
        var clock=new SyncVersionClock(-1);clock.next(1000);clock.next(1100);
        assertTrue(clock.next(1099).isEmpty());assertTrue(clock.next(1100).isEmpty());
        assertEquals(1101,clock.next(1101).orElseThrow());
    }
    @Test void restartBeforeSavedMaximumIsTreatedAsRollback() {
        var clock=new SyncVersionClock(1000);
        assertTrue(clock.next(999).isEmpty());assertTrue(clock.next(1000).isEmpty());
        assertEquals(1001,clock.next(1001).orElseThrow());
    }
    @Test void equalityAtStartupMayAdvanceByOne() {
        assertEquals(1001,new SyncVersionClock(1000).next(1000).orElseThrow());
    }
    @Test void aFixedClockCannotGenerateMoreThanFiveMinutesIntoTheFuture() {
        var clock=new SyncVersionClock(-1);
        for(int n=0;n<=300000;n++)assertEquals(1000L+n,clock.next(1000).orElseThrow());
        assertTrue(clock.next(1000).isEmpty());
        assertEquals(301001,clock.next(1001).orElseThrow());
    }
    @Test void overflowDoesNotWrapToAnOldVersion() {
        var clock=new SyncVersionClock(Long.MAX_VALUE);
        assertTrue(clock.next(Long.MAX_VALUE).isEmpty());assertEquals(Long.MAX_VALUE,clock.maximum());
        assertThrows(IllegalArgumentException.class,()->new SyncVersionClock(-2));
    }
}
