// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class CotImportStatusTest {
    private static CotRecord item(){return CotRecord.tombstone("incoming",1,new byte[32],1);}
    @Test public void pendingInFlightAndDurableMatchesAreCountedButUnmarkedRecordsAreAccepted(){
        var source=new CotSourceBuffer();var marks=new ExternalMarks(new byte[32],new byte[32]);
        var queue=new ArrayDeque<Runnable>();int[] skipped={0},accepted={0};
        var gate=new CotImportGate(queue::add,()->true,()->marks,source,CotPort.REAL_IMPORT_ENABLED,r->accepted[0]++,()->skipped[0]++);
        source.external("incoming");gate.notice(item());assertEquals(1,skipped[0]);assertTrue(queue.isEmpty());
        try(var batch=source.take()){
            gate.notice(item());assertEquals(2,skipped[0]);marks.add("incoming");batch.committed();
        }
        gate.notice(item());assertEquals(3,skipped[0]);assertEquals(0,accepted[0]);
        gate.notice(CotRecord.tombstone("other",1,new byte[32],1));queue.remove().run();
        assertEquals(3,skipped[0]);assertEquals(1,accepted[0]);
    }
    @Test public void mainRecheckCountsOneLateExternalButOldGenerationCountsNothing(){
        var source=new CotSourceBuffer();var marks=new ExternalMarks(new byte[32],new byte[32]);
        var queue=new ArrayDeque<Runnable>();int[] skipped={0},accepted={0};boolean[] active={true};
        var gate=new CotImportGate(queue::add,()->active[0],()->marks,source,CotPort.REAL_IMPORT_ENABLED,r->accepted[0]++,()->skipped[0]++);
        gate.notice(item());source.external("incoming");queue.remove().run();assertEquals(1,skipped[0]);assertEquals(0,accepted[0]);
        active[0]=false;gate.notice(item());assertEquals(1,skipped[0]);assertTrue(queue.isEmpty());
    }
    @Test public void unreadMarksAndBothOverflowStatesDoNotCountAsAnExternalMatch(){
        var source=new CotSourceBuffer();int[] skipped={0};
        assertFalse(source.permitsImport("incoming",()->null,()->skipped[0]++));assertEquals(0,skipped[0]);
        for(int i=0;i<ExternalMarks.MAX_ENTRIES;i++)assertTrue(source.external("outside-"+i));
        assertFalse(source.external("overflow"));var marks=new ExternalMarks(new byte[32],new byte[32]);
        assertFalse(source.permitsImport("outside-0",()->marks,()->skipped[0]++));assertEquals(0,skipped[0]);
        try(var batch=source.take()){
            assertTrue(batch.overflow);assertFalse(source.permitsImport("outside-0",()->marks,()->skipped[0]++));assertEquals(0,skipped[0]);
        }
        source.clear();
    }
    @Test public void fixedCountDisplayDistinguishesUnreadZeroAndSavedCountWithoutDebugDependency(){
        var d=new CotImportStatus();
        assertTrue(d.text(-1).contains("外来の印（external.bin・保存済み）件数: 未読"));
        d.start(0);d.gateSkipped();assertTrue(d.text(2).contains("核で外来と一致して見送った件数: 2"));
        assertTrue(d.text(2).contains("取り込みの直前に外来と一致して見送った件数: 1"));
        assertTrue(d.text(2).contains("外来の印（external.bin・保存済み）件数: 0"));
        d.savedMarks(3);assertTrue(d.text(2).contains("件数: 3"));d.clear();assertTrue(d.text(-1).contains("件数: 未読"));
        var ordinary=new CotImportStatus();ordinary.start(3);ordinary.gateSkipped();ordinary.savedMarks(4);assertTrue(ordinary.text(5).contains("件数: 4"));
    }
}
