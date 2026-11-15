// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class CotImportInputTest {
    @Test public void onlyParseArgumentFailureNullAndInvalidEventAreSkippable(){
        assertThrows(CotImportInput.Invalid.class,()->CotImportInput.parse(()->{throw new IllegalArgumentException("private input");},e->true));
        assertThrows(CotImportInput.Invalid.class,()->CotImportInput.parse(()->null,e->true));
        assertThrows(CotImportInput.Invalid.class,()->CotImportInput.parse(()->"event",e->false));
        assertEquals("event",CotImportInput.parse(()->"event",e->true));
    }
    @Test public void unexpectedParserAndValidationFailuresStillEscape(){
        var failure=new IllegalStateException("private failure");
        assertSame(failure,assertThrows(IllegalStateException.class,()->CotImportInput.parse(()->{throw failure;},e->true)));
        var validation=new IllegalArgumentException("private validation");
        assertSame(validation,assertThrows(IllegalArgumentException.class,()->CotImportInput.parse(()->"event",e->{throw validation;})));
    }
    @Test public void gateCountsInvalidInputAndContinuesWithNextRecordButPropagatesDispatchFailure(){
        var queue=new java.util.ArrayDeque<Runnable>();var source=new CotSourceBuffer();
        var marks=new io.github.hidemas_suzuki_aka_ziek.distributak.core.ExternalMarks(new byte[32],new byte[32]);
        int[] attempts={0},skipped={0};
        var gate=new CotImportGate(queue::add,()->true,()->marks,source,true,r->{if(++attempts[0]==1)throw new CotImportInput.Invalid();},()->{},()->skipped[0]++);
        var record=io.github.hidemas_suzuki_aka_ziek.distributak.core.CotRecord.tombstone("incoming",1,new byte[32],1);
        gate.notice(record);gate.notice(record);while(!queue.isEmpty())queue.remove().run();
        assertEquals(2,attempts[0]);assertEquals(1,skipped[0]);
        var failed=new CotImportGate(Runnable::run,()->true,()->marks,source,true,r->{throw new IllegalStateException("dispatch");},()->{},()->skipped[0]++);
        assertThrows(IllegalStateException.class,()->failed.notice(record));assertEquals(1,skipped[0]);
    }
}
