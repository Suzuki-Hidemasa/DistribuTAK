// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class AnnouncementConsistencyTest {
    final RejoinConflictTest fixture=new RejoinConflictTest();
    @Test void sharedCheckRejectsSameVersionDifferentKeyWithoutChangingState(){
        var state=fixture.t.saved();var current=fixture.announcement(state,fixture.f.groupKey,fixture.f.f.now);
        state.recordGroupKey(current,fixture.f.groupKey,0);var before=state.snapshot();
        assertThrows(SecurityException.class,()->state.checkGroupKeyCandidate(fixture.announcement(state,key(89),fixture.f.f.now),key(89),0));
        assertTrue(AdminState.sameSnapshot(before,state.snapshot()));
    }
    @Test void sharedCheckRejectsLowerRankAndAllowsSameKeyResignature(){
        var state=fixture.t.saved();state.recordGroupKey(fixture.announcement(state,fixture.f.groupKey,fixture.f.f.now),fixture.f.groupKey,0);
        assertThrows(SecurityException.class,()->state.checkGroupKeyCandidate(fixture.announcement(state,fixture.f.groupKey,fixture.f.f.now-1),fixture.f.groupKey,0));
        assertDoesNotThrow(()->state.checkGroupKeyCandidate(fixture.announcement(state,fixture.f.groupKey,fixture.f.f.now+1),fixture.f.groupKey,0));
    }
    @Test void initialLocalKeyComparisonDoesNotInitializeAnnouncement(){
        var state=fixture.t.saved();var before=state.snapshot();
        state.checkGroupKeyCandidate(fixture.announcement(state,fixture.f.groupKey,fixture.f.f.now),fixture.f.groupKey,0);
        assertNull(state.announcement());assertTrue(AdminState.sameSnapshot(before,state.snapshot()));
    }
}
