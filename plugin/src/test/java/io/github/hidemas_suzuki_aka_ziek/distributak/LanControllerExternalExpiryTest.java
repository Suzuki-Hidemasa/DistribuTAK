// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.nio.ByteBuffer;
import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerExternalExpiryTest {
    static final byte[] PEER=new byte[32],SESSION=new byte[16];
    static {PEER[0]=1;SESSION[0]=1;}
    static final class Wall extends Clock {
        final AtomicLong now=new AtomicLong(LanControllerHarness.CLOCK.millis());
        public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(now.get());}
    }
    static CotRecord record(Wall wall,long version){long stale=wall.millis()+60_000;return CotRecord.record("peer-position",version,PEER,stale,CotCaptureBaselineTest.xml("peer-position",0,stale,0),1);}
    static CotSync sync(LanControllerHarness node)throws Exception{return (CotSync)LanControllerHarness.field(node.controller,"sync");}
    static void receive(LanControllerHarness node,CotRecord record)throws Exception{sync(node).connected(PEER,SESSION);sync(node).receive(PEER,SESSION,SyncWire.encode(record));sync(node).flush();node.tick();node.tick();}
    static void observedImport(LanControllerOnImportTest.Cot cot,String uid){
        // AndroidCotPort.observeと同じ、柵とmain側の印を照らす口を通す。
        CotExternalObservation.observe(uid,cot.fence.contains(uid),cot.listener.externalMarked(uid),cot.listener::external);
    }
    @Test public void observationInsideFenceAndWithMarkStopsCountdownBeforeExpiry()throws Exception{
        var wall=new Wall();long base=wall.millis();var cot=new LanControllerOnImportTest.Cot("local-position");
        try(var node=new LanControllerHarness(null,cot,wall)){
            node.create();observedImport(cot,"peer-position");node.tick();receive(node,record(wall,base));
            assertTrue(cot.fence.contains("peer-position"));assertTrue(cot.listener.externalMarked("peer-position"));
            wall.now.addAndGet(300_000);observedImport(cot,"peer-position");
            assertTrue(cot.listener.externalMarked("peer-position"));node.tick();
            assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),sync(node).externalSnapshot().startedAt(ExternalMarks.fingerprint("peer-position")));
            wall.now.set(base+900_000);node.tick();node.tick();
            assertTrue(cot.imported.isEmpty());assertTrue(sync(node).externalSnapshot().contains("peer-position"));assertEquals(0,sync(node).externalExpired());
        }
    }
    @Test public void ownImportSignalsInsideFenceWithoutMarkDoNotCreateOne()throws Exception{
        var wall=new Wall();var cot=new LanControllerOnImportTest.Cot("local-position");
        try(var node=new LanControllerHarness(null,cot,wall)){
            node.create();cot.importEcho=()->observedImport(cot,"peer-position");receive(node,record(wall,wall.millis()));node.tick();
            assertEquals(1,cot.imported.size());assertFalse(cot.listener.externalMarked("peer-position"));assertEquals(0,sync(node).externalSnapshot().size());
            // 同じuidの遅い合図も、柵の中・印なしなので無視する。
            observedImport(cot,"peer-position");node.tick();assertFalse(cot.listener.externalMarked("peer-position"));
        }
    }
    @Test public void expiryPublishesRemovedMarkBeforeImportEchoAndDoesNotRecreateIt()throws Exception{
        var wall=new Wall();var cot=new LanControllerOnImportTest.Cot("local-position");int[] echoes={0};
        try(var node=new LanControllerHarness(null,cot,wall)){
            node.create();observedImport(cot,"peer-position");node.tick();receive(node,record(wall,wall.millis()));
            cot.importEcho=()->{
                assertTrue(cot.fence.contains("peer-position"));assertFalse(cot.listener.externalMarked("peer-position"));
                observedImport(cot,"peer-position");echoes[0]++;
            };
            wall.now.addAndGet(600_000);node.tick();node.tick();
            assertEquals(1,echoes[0]);assertEquals(1,cot.imported.size());assertEquals(1,sync(node).externalExpired());
            assertFalse(cot.listener.externalMarked("peer-position"));
            observedImport(cot,"peer-position");node.tick();node.tick();
            assertFalse(cot.listener.externalMarked("peer-position"));assertEquals(0,sync(node).externalSnapshot().size());
            try(var group=node.disk.load(wall)){assertEquals(0,node.disk.loadExternal(group).size());}
        }
    }
    @Test public void noReceiptKeepsMarkThenTenMinutesFromFirstReceiptImportsLatestAcrossRestart()throws Exception{
        var wall=new Wall();long base=wall.millis();var cot=new LanControllerOnImportTest.Cot("local-position");LanControllerHarness.Disk disk;CotRecord latest;
        try(var node=new LanControllerHarness(null,cot,wall)){
            node.create();cot.listener.external("peer-position");node.tick();
            wall.now.set(base+1_200_000);node.tick();assertEquals(1,sync(node).externalSnapshot().size());assertTrue(cot.imported.isEmpty());
            receive(node,record(wall,wall.millis()));assertTrue(cot.imported.isEmpty());
            wall.now.addAndGet(300_000);latest=record(wall,wall.millis());receive(node,latest);
            assertEquals(Long.valueOf(base+1_200_000),sync(node).externalSnapshot().startedAt(ExternalMarks.fingerprint("peer-position")));
            wall.now.set(base+1_799_999);node.tick();assertTrue(cot.imported.isEmpty());disk=node.disk;
        }
        var restored=new LanControllerOnImportTest.Cot("local-position");
        try(var node=new LanControllerHarness(disk,restored,wall)){
            node.controller.connect();node.drain();wall.now.incrementAndGet();node.tick();node.tick();
            assertEquals(1,restored.imported.size());assertTrue(latest.sameRecord(restored.imported.get(0)));
            try(var group=disk.load(wall)){assertEquals(0,disk.loadExternal(group).size());}
            assertTrue(node.ui.last.text.contains("外来の印の期限切れ件数: 1"));node.tick();assertEquals(1,restored.imported.size());
        }
    }
    @Test public void queuedExternalAtExpiryCancelsTimerBeforeWorkerExpiresItAndSameVersionRestartsIt()throws Exception{
        var wall=new Wall();long base=wall.millis();var cot=new LanControllerOnImportTest.Cot("local-position");
        long stale=base+2_000_000;var item=CotRecord.record("peer-position",base,PEER,stale,CotCaptureBaselineTest.xml("peer-position",0,stale,0),1);
        try(var node=new LanControllerHarness(null,cot,wall)){
            node.create();cot.listener.external(item.uid());node.tick();receive(node,item);
            wall.now.addAndGet(600_000);cot.listener.external(item.uid());node.tick();node.tick();
            assertTrue(cot.imported.isEmpty());assertEquals(0,sync(node).externalExpired());
            assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),sync(node).externalSnapshot().startedAt(ExternalMarks.fingerprint(item.uid())));
            receive(node,item);wall.now.addAndGet(599_999);node.tick();assertTrue(cot.imported.isEmpty());
            wall.now.incrementAndGet();node.tick();assertEquals(1,cot.imported.size());assertTrue(item.sameRecord(cot.imported.get(0)));
        }
    }
    private static byte[] legacy(LanGroup group){
        var out=ByteBuffer.allocate(120);var value=ExternalMarks.fingerprint("peer-position");
        return out.putInt(0x44544558).putInt(1).put("distributak-external-uids-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII)).put(group.groupId).put(group.id()).putInt(1).putLong(value.high()).putLong(value.low()).array();
    }
    @Test public void legacyMigrationIsSavedBeforeCaptureAndStaysUnstartedAcrossReload()throws Exception{
        var wall=new Wall();LanControllerHarness.Disk disk;
        try(var node=new LanControllerHarness(null,new LanControllerOnImportTest.Cot("local-position"),wall)){
            node.create();disk=node.disk;try(var group=disk.load(wall)){disk.envelope.withMaximum(ExternalMarks.MAX_ENVELOPE_BYTES).save(legacy(group),disk.external);}
        }
        for(int attempt=0;attempt<2;attempt++){
            wall.now.addAndGet(1_200_000);
            try(var node=new LanControllerHarness(disk,new LanControllerOnImportTest.Cot("local-position"),wall)){
                node.controller.connect();node.tick();assertTrue(node.ui.last.running);
                try(var group=disk.load(wall)){var marks=disk.loadExternal(group);assertFalse(marks.migrateLegacy());assertEquals(Long.valueOf(ExternalMarks.NOT_STARTED),marks.startedAt(ExternalMarks.fingerprint("peer-position")));}
            }
        }
    }
    @Test public void migrationSaveFailureStopsBeforeCapture()throws Exception{
        var wall=new Wall();LanControllerHarness.Disk disk;
        try(var node=new LanControllerHarness(null,new LanControllerOnImportTest.Cot("local-position"),wall)){node.create();disk=node.disk;}
        var cot=new LanControllerOnImportTest.Cot("local-position");
        try(var node=new LanControllerHarness(disk,cot,wall)){
            node.controller.disconnect();node.drain();
            try(var group=disk.load(wall)){disk.envelope.withMaximum(ExternalMarks.MAX_ENVELOPE_BYTES).save(legacy(group),disk.external);}
            disk.failSave=true;node.controller.connect();node.drain();
            assertFalse(cot.active);assertFalse(node.ui.last.running);assertNull(sync(node));
        }
    }
    @Test public void invalidLatestAtExpiryIsSkippedOnceAndNextVersionCanImport()throws Exception{
        var wall=new Wall();var cot=new LanControllerOnImportTest.Cot("local-position");cot.importFailure=new CotImportInput.Invalid();
        try(var node=new LanControllerHarness(null,cot,wall)){
            node.create();cot.listener.external("peer-position");node.tick();receive(node,record(wall,wall.millis()));
            assertEquals(0,cot.importAttempts);wall.now.addAndGet(600_000);node.tick();node.tick();
            assertEquals(1,cot.importAttempts);assertTrue(cot.imported.isEmpty());assertTrue(node.ui.last.running);
            assertTrue(node.ui.last.text.contains("入力が無効で見送った件数: 1"));node.tick();assertEquals(1,cot.importAttempts);
            cot.importFailure=null;receive(node,record(wall,wall.millis()));assertEquals(2,cot.importAttempts);assertEquals(1,cot.imported.size());
        }
    }
}
