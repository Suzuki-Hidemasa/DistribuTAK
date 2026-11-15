// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class CotImportGateTest {
    @Test public void queuedNotificationRechecksAtMainAndOffModeStillExcludesMarkedRecords(){
        for(boolean enabled:new boolean[]{false,true})for(boolean lateExternal:new boolean[]{false,true}){
            var queue=new java.util.ArrayDeque<Runnable>();var source=new CotSourceBuffer();var marks=new ExternalMarks(new byte[32],new byte[32]);int[] calls={0};
            var gate=new CotImportGate(queue::add,()->true,()->marks,source,enabled,r->calls[0]++);
            var record=CotRecord.tombstone("incoming",1,new byte[32],1);gate.notice(record);assertEquals(1,queue.size());
            if(lateExternal)source.external("incoming");queue.remove().run();assertEquals(enabled&&!lateExternal?1:0,calls[0]);
            source.external("incoming");gate.notice(record);assertTrue(queue.isEmpty());
        }
    }
    @Test public void handoffCannotUseAStaleSavedSnapshotAfterPendingWasCleared(){
        var source=new CotSourceBuffer();var queue=new java.util.ArrayDeque<Runnable>();var current=new java.util.concurrent.atomic.AtomicReference<>(new ExternalMarks(new byte[32],new byte[32]));
        int[] reads={0},calls={0};CotSourceBuffer.Batch[] batch={null};
        java.util.function.Supplier<ExternalMarks> saved=()->{
            var captured=current.get();if(++reads[0]==2){var marked=new ExternalMarks(new byte[32],new byte[32]);marked.add("incoming");current.set(marked);batch[0].committed();batch[0].close();}return captured;
        };
        var gate=new CotImportGate(queue::add,()->true,saved,source,true,r->calls[0]++);gate.notice(CotRecord.tombstone("incoming",1,new byte[32],1));
        source.external("incoming");batch[0]=source.take();queue.remove().run();assertEquals(0,calls[0]);batch[0].committed();batch[0].close();
    }
    @Test public void gateRejectsExternalObservedBetweenWorkerAndMainIncludingTombstonesAndRestart(){
        for(boolean deleted:new boolean[]{false,true})for(boolean restart:new boolean[]{false,true}){
            var source=new CotSourceBuffer();var marks=new ExternalMarks(new byte[32],new byte[32]);
            var record=deleted?CotRecord.tombstone("incoming",1,new byte[32],1):CotRecord.record("incoming",1,new byte[32],1000,"<event uid=\"incoming\" stale=\"1970-01-01T00:00:01Z\"/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),1);
            assertTrue(CotPort.REAL_IMPORT_ENABLED);assertTrue(CotImportGate.allowed(record,marks,source));
            source.external("incoming");assertFalse(CotImportGate.allowed(record,marks,source));
            assertBlockedByEnabledGate(record,marks,source);
            try(var batch=source.take()){assertFalse(CotImportGate.allowed(record,marks,source));marks.addFingerprint(batch.external.iterator().next());batch.committed();}
            if(restart)marks=ExternalMarks.decode(marks.encode(),new byte[32],new byte[32]);
            assertFalse(CotImportGate.allowed(record,marks,source));assertBlockedByEnabledGate(record,marks,source);
            assertTrue(CotImportGate.allowed(record,new ExternalMarks(new byte[32],new byte[32]),source));
        }
    }
    private static void assertBlockedByEnabledGate(CotRecord record,ExternalMarks marks,CotSourceBuffer source){
        var queue=new java.util.ArrayDeque<Runnable>();int[] accepted={0};
        var gate=new CotImportGate(queue::add,()->true,()->marks,source,CotPort.REAL_IMPORT_ENABLED,r->accepted[0]++);
        gate.notice(record);while(!queue.isEmpty())queue.remove().run();assertEquals(0,accepted[0]);
    }
    @Test public void enabledGateRejectsOldGenerationBeforeQueueAndAgainAtMainForRecordsAndDeletions(){
        assertTrue(CotPort.REAL_IMPORT_ENABLED);
        for(boolean deletion:new boolean[]{false,true}){
            var queue=new java.util.ArrayDeque<Runnable>();var source=new CotSourceBuffer();var marks=new ExternalMarks(new byte[32],new byte[32]);
            long[] generation={7};boolean[] active={true};int[] accepted={0};long epoch=generation[0];
            var gate=new CotImportGate(queue::add,()->active[0]&&epoch==generation[0],()->marks,source,CotPort.REAL_IMPORT_ENABLED,r->accepted[0]++);
            var record=deletion?CotRecord.tombstone("incoming",1,new byte[32],1):CotRecord.record("incoming",1,new byte[32],1000,"<event uid=\"incoming\" stale=\"1970-01-01T00:00:01Z\"/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),1);
            gate.notice(record);assertEquals(1,queue.size());generation[0]++;queue.remove().run();assertEquals(0,accepted[0]);
            gate.notice(record);assertTrue(queue.isEmpty());
            long current=generation[0];var next=new CotImportGate(queue::add,()->active[0]&&current==generation[0],()->marks,source,CotPort.REAL_IMPORT_ENABLED,r->accepted[0]++);
            next.notice(record);queue.remove().run();assertEquals(1,accepted[0]);
            next.notice(record);active[0]=false;queue.remove().run();assertEquals(1,accepted[0]);next.notice(record);assertTrue(queue.isEmpty());
        }
    }
    @Test public void enabledImportStillRequiresRegisteredFenceAndSavedUidAndPreservesShortCircuitOrder(){
        assertTrue(CotPort.REAL_IMPORT_ENABLED);
        for(int state=0;state<7;state++){
            var fence=new CotFence();fence.saved(java.util.Set.of("incoming"));
            if(state>0)fence.begin(0);
            if(state>=2)fence.registered(true,0);
            if(state==4)fence.registered(false,0);
            if(state==5)fence.stop();
            if(state==6){fence=new CotFence();fence.begin(0);fence.registered(false,0);fence.saved(java.util.Set.of("incoming"));}
            var current=fence;String uid=state==3?"not-saved":"incoming";int[] containsCalls={0};
            boolean allowed=CotImportGate.fenced(CotPort.REAL_IMPORT_ENABLED,current::ready,()->{containsCalls[0]++;return current.contains(uid);});
            assertEquals(state==2,allowed);assertEquals(current.ready()?1:0,containsCalls[0]);
        }
        assertFalse(CotImportGate.fenced(false,()->{fail("disabled must not read ready");return true;},()->{fail("disabled must not read fence");return true;}));
    }
    @Test public void statusDescribesConfiguredGateWithoutClaimingEveryRecordIsImported(){
        assertEquals("有効（柵・uidの門で判定）",CotImportGate.status(CotPort.REAL_IMPORT_ENABLED));
        assertEquals("停止中",CotImportGate.status(false));
    }
}
