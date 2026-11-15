// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerOnImportTest {
    static final class Cot extends LanControllerSyncTest.Cot {
        final String uid;CotFence fence=new CotFence();final List<CotRecord> imported=new ArrayList<>();
        RuntimeException importFailure;int importAttempts;Runnable importEcho=()->{};
        Cot(String uid){this.uid=uid;}
        public String selfUid(){return uid;}
        public void start(Listener listener,java.util.function.Consumer<Runnable> guarded){
            super.start(listener,guarded);fence=new CotFence();fence.saved(saved);fence.begin(0);fence.registered(true,0);
        }
        public void saved(Set<String> received){super.saved(received);fence.saved(received);}
        public boolean ready(){return active&&fence.ready();}
        public long importAttempts(){return importAttempts;}
        public void accept(CotRecord record){
            super.accept(record);
            if(CotImportGate.fenced(CotPort.REAL_IMPORT_ENABLED,this::ready,()->fence.contains(record.uid()))){
                importAttempts++;
                if(importFailure!=null)throw importFailure;
                imported.add(record);
                importEcho.run();
            }
        }
        public void stop(){super.stop();fence.stop();}
    }
    @Test public void unexpectedFailureStopsCommunicationButKeepsRecordAndDoesNotRetrySavedVersions()throws Exception{
        failedImportKeepsRecord(new IllegalStateException("simulated unexpected failure"));
    }
    @Test public void invalidInputContinuesCountsOnceAndRetriesOnlyNewerVersionIncludingAfterRestart()throws Exception{
        var receiving=new Cot("local-position");receiving.importFailure=new CotImportInput.Invalid();
        byte[] peer=new byte[32],session=new byte[16];peer[0]=1;session[0]=1;
        long now=LanControllerHarness.CLOCK.millis(),stale=now+60_000;
        byte[] xml=CotCaptureBaselineTest.xml("peer-position",0,stale,0);
        var record=CotRecord.record("peer-position",now,peer,stale,xml,1);
        var older=CotRecord.record("peer-position",now-1,peer,stale,xml,1);
        LanControllerHarness.Disk disk;
        try(var node=new LanControllerHarness(null,receiving)){
            node.create();var sync=(CotSync)LanControllerHarness.field(node.controller,"sync");sync.connected(peer,session);
            for(var item:List.of(record,record,older)){
                sync.receive(peer,session,SyncWire.encode(item));sync.flush();node.tick();node.tick();node.drain();
                assertEquals(1,receiving.importAttempts);assertTrue(receiving.imported.isEmpty());assertTrue(node.ui.last.running);
                assertTrue(node.ui.last.text.contains("入力が無効で見送った件数: 1"));
                assertTrue(node.ui.last.text.contains("取り込みの試行: 1"));
            }
            receiving.importFailure=null;
            var newer=CotRecord.record("peer-position",now+1,peer,stale,xml,1);
            sync.receive(peer,session,SyncWire.encode(newer));sync.flush();node.tick();
            assertEquals(2,receiving.importAttempts);assertEquals(1,receiving.imported.size());assertTrue(node.ui.last.running);
            disk=node.disk;
        }
        var restoredCot=new Cot("local-position");restoredCot.importFailure=new CotImportInput.Invalid();
        try(var node=new LanControllerHarness(disk,restoredCot)){
            node.controller.connect();node.drain();var sync=(CotSync)LanControllerHarness.field(node.controller,"sync");sync.connected(peer,session);
            for(var item:List.of(record,older)){sync.receive(peer,session,SyncWire.encode(item));sync.flush();node.tick();}
            assertEquals(0,restoredCot.importAttempts);assertTrue(node.ui.last.running);
        }
    }
    private void failedImportKeepsRecord(RuntimeException failure)throws Exception{
        var receiving=new Cot("local-position");receiving.importFailure=failure;
        byte[] peer=new byte[32],session=new byte[16];peer[0]=1;session[0]=1;
        long now=LanControllerHarness.CLOCK.millis(),stale=now+60_000;
        byte[] xml=CotCaptureBaselineTest.xml("peer-position",0,stale,0);
        assertEquals(stale,CotXml.inspect(xml).stale());
        var record=CotRecord.record("peer-position",now,peer,stale,xml,1);
        var older=CotRecord.record("peer-position",now-1,peer,stale,xml,1);
        LanControllerHarness.Disk disk;
        try(var node=new LanControllerHarness(null,receiving)){
            node.create();var endpoint=node.endpoint();
            var sync=(CotSync)LanControllerHarness.field(node.controller,"sync");
            // 核の受信口から、本物の保存とmainへの通知を通す。SDKの失敗だけを偽物にする。
            sync.connected(peer,session);sync.receive(peer,session,SyncWire.encode(record));sync.flush();
            assertEquals(1,sync.statistics().received());assertEquals(0,sync.statistics().rejected());
            assertEquals(0,receiving.importAttempts);
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){
                assertTrue(record.sameRecord(node.disk.loadSync(group).get(record.uid())));
                assertTrue(node.disk.loadSync(group).receivedUids().contains(record.uid()));
            }
            node.drain();node.drain();
            assertEquals(1,receiving.importAttempts);assertTrue(receiving.imported.isEmpty());
            assertTrue(endpoint.isTerminated());assertNull(node.endpoint());
            assertNull(LanControllerHarness.field(node.controller,"sync"));
            assertFalse(receiving.active);assertFalse(node.ui.last.running);assertFalse(node.ui.last.ready);
            assertTrue(node.ui.last.text.contains("処理できません。通信を停止しました"));
            assertFalse(node.ui.last.text.contains(failure.getMessage()));
            assertFalse(node.logs.toString().contains(failure.getMessage()));
            disk=node.disk;
            try(var group=disk.load(LanControllerHarness.CLOCK)){
                assertTrue(record.sameRecord(disk.loadSync(group).get(record.uid())));
                assertTrue(disk.loadSync(group).receivedUids().contains(record.uid()));
            }
        }
        var restoredCot=new Cot("local-position");restoredCot.importFailure=failure;
        try(var restored=new LanControllerHarness(disk,restoredCot)){
            assertEquals(0,restoredCot.importAttempts);
            restored.controller.connect();restored.drain();
            assertTrue(restored.ui.last.running);assertTrue(restoredCot.ready());
            assertTrue(restoredCot.fence.contains(record.uid()));assertEquals(0,restoredCot.importAttempts);
            var sync=(CotSync)LanControllerHarness.field(restored.controller,"sync");
            sync.connected(peer,session);
            for(var repeated:List.of(record,older)){
                sync.receive(peer,session,SyncWire.encode(repeated));sync.flush();restored.drain();restored.drain();
                assertEquals(0,sync.statistics().rejected());assertEquals(0,sync.statistics().received());
                assertEquals(0,restoredCot.importAttempts);assertTrue(restoredCot.imported.isEmpty());
                assertTrue(restored.ui.last.running);assertTrue(restored.ui.last.ready);
                try(var group=disk.load(LanControllerHarness.CLOCK)){
                    assertTrue(record.sameRecord(disk.loadSync(group).get(record.uid())));
                    assertTrue(disk.loadSync(group).receivedUids().contains(record.uid()));
                }
            }
        }
    }
    @Test public void enabledControllerImportsDurablySavedPeerPositionButRejectsExternalAndOwnUid()throws Exception{
        assertTrue(CotPort.REAL_IMPORT_ENABLED);assertTrue(CotCaptureReconcile.CONFIRMED_CREATED_TYPES.isEmpty());
        for(int scenario=0;scenario<3;scenario++){
            var sending=new Cot(scenario==2?"local-position":"peer-position");var receiving=new Cot("local-position");
            try(var first=new LanControllerHarness(null,sending);var second=new LanControllerHarness(null,receiving)){
                first.create();second.beginJoin(first);
                LanControllerHarness.until(()->second.ui.last.member&&first.logs.contains("LAN_MEMBER_ISSUED"),first,second);
                first.controller.connect();first.drain();
                try(var a=first.disk.load(LanControllerHarness.CLOCK);var b=second.disk.load(LanControllerHarness.CLOCK)){
                    LanControllerHarness.until(()->first.endpoint().isEstablished(b.id())&&second.endpoint().isEstablished(a.id()),first,second);
                    var sync=(CotSync)LanControllerHarness.field(second.controller,"sync");
                    if(scenario==1){receiving.listener.external(sending.uid);second.tick();}
                    long rejected=sync.statistics().rejected(),received=sync.statistics().received();
                    byte[] xml=CotCaptureBaselineTest.xml(sending.uid,0,LanControllerHarness.CLOCK.millis()+60_000,0);
                    sending.listener.position(sending.uid,xml);first.tick();
                    LanControllerHarness.until(()->sync.statistics().received()>received||sync.statistics().rejected()>rejected,first,second);second.tick();
                    if(scenario==0){
                        assertEquals(1,receiving.imported.size());assertArrayEquals(xml,receiving.imported.get(0).xml());
                        assertTrue(second.disk.loadSync(b).receivedUids().contains(sending.uid));
                    }else assertTrue(receiving.imported.isEmpty());
                    if(scenario==1){
                        assertEquals(1,sync.externalImportsSkipped());
                        assertEquals(1,second.disk.loadExternal(b).size());
                        assertTrue(second.ui.last.text.contains("核で外来と一致して見送った件数: 1"));
                        assertTrue(second.ui.last.text.contains("取り込みの直前に外来と一致して見送った件数: 0"));
                        assertTrue(second.ui.last.text.contains("外来の印（external.bin・保存済み）件数: 1"));
                    }
                    if(scenario==2)assertNull(second.disk.loadSync(b).get(sending.uid));
                }
            }
        }
    }
}
