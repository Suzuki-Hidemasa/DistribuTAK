// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerSyncTest {
    @Test public void captureRestartRevokesCreatedOwnershipAndOldCallbackCannotRevokeNewSync()throws Exception{
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)){
            node.create();var sync=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(node.controller,"sync");
            byte[] xml=CotCaptureBaselineTest.xml("fresh",0,LanControllerHarness.CLOCK.millis()+60000,0);
            assertTrue(sync.publish("fresh",xml,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.Origin.LOCAL_CREATED));sync.flush();cot.listener.captureStarted();node.drain();
            assertFalse(sync.publish("fresh",xml,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.Origin.LOCAL_CREATED));assertFalse(sync.remove("fresh"));
            var old=cot.listener;node.controller.disconnect();node.drain();node.controller.connect();node.drain();
            sync=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(node.controller,"sync");
            byte[] next=CotCaptureBaselineTest.xml("next",0,LanControllerHarness.CLOCK.millis()+60000,0);
            assertTrue(sync.publish("next",next,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.Origin.LOCAL_CREATED));sync.flush();old.captureStarted();node.drain();assertTrue(sync.remove("next"));
        }
    }
    @Test public void captureLimitNoticeLivesInStatusOutsideDebugDiagnostics()throws Exception {
        var cot=new Cot(){@Override public String captureStatus(){return limited?CotCapturePolicy.LIMIT_TEXT:"";}boolean limited;
            void limit(){limited=true;}};
        try(var node=new LanControllerHarness(null,cot)){
            node.create();assertFalse(node.ui.last.text.contains(CotCapturePolicy.LIMIT_TEXT));
            cot.limit();node.tick();assertTrue(node.ui.last.text.contains(CotCapturePolicy.LIMIT_TEXT));
        }
    }
    @Test public void stationaryPositionIsNotRepublishedAndRestoredXmlSuppressesReconnect()throws Exception {
        var cot=new Cot();
        try(var node=new LanControllerHarness(null,cot)){
            node.create();long now=LanControllerHarness.CLOCK.millis();
            byte[] xml=CotCaptureBaselineTest.xml("self",0,now+60_000,0);cot.listener.position("self",xml);node.tick();
            long first;
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){first=node.disk.loadSync(group).get("self").time();}
            cot.listener.position("self",CotCaptureBaselineTest.xml("self",0,now+120_000,1));node.tick();
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){var saved=node.disk.loadSync(group).get("self");assertEquals(first,saved.time());assertEquals(now+60_000,saved.stale());}
            node.controller.disconnect();node.drain();node.controller.connect();node.drain();
            cot.listener.position("self",CotCaptureBaselineTest.xml("self",0,now+240_000,2));node.tick();
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertEquals(first,node.disk.loadSync(group).get("self").time());}
        }
    }
    @Test public void controllerBaselineUsesActuallySavedStaleForLongAndShortDeadlines()throws Exception {
        for(boolean longStale:new boolean[]{true,false}){
            var cot=new Cot();
            try(var node=new LanControllerHarness(null,cot)){
                node.create();long now=LanControllerHarness.CLOCK.millis();
                long original=now+(longStale?io.github.hidemas_suzuki_aka_ziek.distributak.core.CotXml.MAX_STALE_MILLIS+60_000:60_000);
                cot.listener.position("self",CotCaptureBaselineTest.xml("self",0,original,0));node.tick();
                long first;
                try(var group=node.disk.load(LanControllerHarness.CLOCK)){first=node.disk.loadSync(group).get("self").stale();}
                var baseline=(CotCaptureBaseline)LanControllerHarness.field(node.controller,"captureBaseline");
                try(var next=baseline.candidate("self",CotCaptureBaselineTest.xml("self",1,original+10_000,1),true)){
                    assertNotNull(next);assertEquals(first,io.github.hidemas_suzuki_aka_ziek.distributak.core.CotXml.inspect(next.xml).stale());
                }
                cot.listener.position("self",CotCaptureBaselineTest.xml("self",1,original+10_000,1));node.tick();
                long version;
                try(var group=node.disk.load(LanControllerHarness.CLOCK)){var record=node.disk.loadSync(group).get("self");assertTrue(record.stale()<=first);version=record.time();}
                cot.listener.position("self",CotCaptureBaselineTest.xml("self",1,original+20_000,2));node.tick();
                try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertEquals(version,node.disk.loadSync(group).get("self").time());}
            }
        }
    }
    @Test public void syncLifecycleSurvivesControllerReplacement()throws Exception {
        io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync previous;
        try(var first=new LanControllerHarness()){
            first.create();previous=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(first.controller,"sync");assertFalse(previous.isClosed());
        }
        assertTrue(previous.isClosed());
        try(var second=new LanControllerHarness()){
            second.create();var current=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(second.controller,"sync");
            assertNotSame(previous,current);assertFalse(current.isClosed());assertTrue(second.ui.last.running);
        }
    }
    static class Cot implements CotPort {
        Listener listener;java.util.Set<String> saved=java.util.Set.of();boolean active,lost;int starts,stops,debug,debugOnly,debugSend;final java.util.List<Send> sends=new java.util.ArrayList<>();
        public String selfUid(){return "self";}
        public void start(Listener listener,java.util.function.Consumer<Runnable> guarded){this.listener=listener;active=true;starts++;}
        public void saved(java.util.Set<String> received){saved=received;}
        public void accept(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotRecord record){assertTrue(saved.contains(record.uid()));}
        public void debug(){assertTrue(saved.contains(FIXTURE_UID));debug++;}
        public void debugFenceOnly(){assertTrue(saved.contains(FIXTURE_UID));debugOnly++;}
        public void debugSend(Send method){debugSend++;sends.add(method);}
        public boolean ready(){return active&&!lost;}public boolean failed(){return active&&lost;}
        public void poll(long now){}
        public String diagnostics(){return "diagnostic-counts";}
        public void stop(){active=false;stops++;}
    }
    static final class TimedCot extends Cot {
        final CotFence fence=new CotFence();final java.util.function.LongSupplier time;
        TimedCot(java.util.function.LongSupplier time){this.time=time;}
        public void start(Listener listener,java.util.function.Consumer<Runnable> guarded){super.start(listener,guarded);fence.begin(time.getAsLong());}
        public void poll(long nanos){fence.poll(nanos);}
        public boolean ready(){return active&&fence.ready();}public boolean failed(){return active&&fence.failed();}
        void registered(){fence.registered(true,time.getAsLong());}
    }
    @Test public void controllerUsesWorkerSpillAndDiscardsItOnDisconnectAndReconnect()throws Exception {
        try(var node=new LanControllerHarness(null,new Cot())){
            node.create();assertEquals(1,node.disk.spillOpens);
            var sync=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(node.controller,"sync");
            String uid="offload-controller";byte[] xml=("<event uid=\""+uid+"\" stale=\""+LanControllerHarness.CLOCK.instant().plusSeconds(60)+"\"/>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(sync.publish(uid,xml,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.Origin.LOCAL_CREATED));node.tick();
            assertTrue(node.disk.spill.files()>0);node.controller.disconnect();node.drain();assertEquals(0,node.disk.spill.files());
            node.controller.connect();node.drain();assertEquals(2,node.disk.spillOpens);assertTrue(node.disk.spill.files()>0);
        }
    }
    @Test public void realFenceDeadlineRunsThroughControllerAtFiveSecondsButNotEarlierOrAfterSuccess()throws Exception {
        for(boolean success:new boolean[]{false,true}){
            var time=new java.util.concurrent.atomic.AtomicLong();var cot=new TimedCot(time::get);
            try(var node=new LanControllerHarness(null,cot,time::get)){
                node.create();time.set(4_900_000_000L);node.tick();assertTrue(node.ui.last.running);assertTrue(node.ui.last.ready);
                if(success)cot.registered();
                time.set(5_000_000_000L);node.tick();
                assertEquals(success,node.ui.last.running);assertEquals(success,node.ui.last.ready);
                if(!success){assertTrue(node.ui.last.text.contains("ATAK を起動し直してください"));assertFalse(node.ui.last.text.contains("消去して"));}
                else{time.set(10_000_000_000L);node.tick();assertTrue(node.ui.last.running);}
            }
        }
    }
    @Test public void receivedRegistrySurvivesQueuedExternalObservationInStoreAndFence()throws Exception {
        var fence=new CotFence();fence.begin(0);fence.registered(true,0);
        var cot=new Cot(){@Override public void saved(java.util.Set<String> received){super.saved(received);fence.saved(received);}};
        try(var node=new LanControllerHarness(null,cot)){
            node.create();node.controller.debugFence();node.drain();cot.listener.external(CotPort.FIXTURE_UID);node.tick();
            assertTrue(cot.saved.contains(CotPort.FIXTURE_UID));
            assertTrue(fence.consume(CotPort.FIXTURE_UID,false,java.util.Set.of()));
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){
                assertTrue(node.disk.loadSync(group).receivedUids().contains(CotPort.FIXTURE_UID));
            }
        }
    }
    @Test public void syncUidLimitGetsFixedNoticeOnlyWhenReachedAndSurvivesRestart()throws Exception {
        var cot=new Cot();LanControllerHarness.Disk disk;
        try(var node=new LanControllerHarness(null,cot)){
            node.create();var sync=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(node.controller,"sync");
            for(int i=0;i<4094;i++)assertTrue(sync.registerReceivedUid("received-"+i));node.tick();
            assertFalse(node.ui.last.text.contains("4096件の上限"));assertTrue(sync.registerReceivedUid("last-received"));node.tick();
            assertTrue(node.ui.last.text.contains("CoT の識別子が4096件の上限に達しました"));
            assertFalse(node.ui.last.text.contains("last-external"));assertFalse(node.ui.last.text.contains("outside-"));disk=node.disk;
        }
        try(var restored=new LanControllerHarness(disk)){assertTrue(restored.ui.last.text.contains("4096件の上限"));}
    }
    @Test public void externalFullNoticeStopsForNewExternalButKeepsExistingAndSurvivesRestart()throws Exception {
        var cot=new Cot();LanControllerHarness.Disk disk;
        try(var node=new LanControllerHarness(null,cot)){
            node.create();node.tick();node.controller.disconnect();node.drain();
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){
                var marks=node.disk.loadExternal(group);for(int n=0;n<65536;n++)assertTrue(marks.add("outside-"+n));node.disk.saveExternal(group,marks);
            }
            node.controller.connect();node.drain();assertTrue(node.ui.last.running);assertTrue(node.ui.last.text.contains("外来の印が65536件の上限"));
            cot.listener.external("outside-0");node.tick();assertTrue(node.ui.last.running);
            cot.listener.external("new-unrecorded");node.tick();assertFalse(node.ui.last.running);assertFalse(node.ui.last.ready);
            assertTrue(node.ui.last.text.contains("外来の印の上限に達したため同期を止めました"));assertFalse(node.ui.last.text.contains("new-unrecorded"));
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertEquals(65536,node.disk.loadExternal(group).size());assertEquals(1,node.disk.loadSync(group).uidCount());}
            disk=node.disk;
        }
        try(var restored=new LanControllerHarness(disk)){assertTrue(restored.ui.last.text.contains("外来の印が65536件の上限"));}
    }
    @Test public void externalFileLossOrCorruptionStopsAndEraseDeletesIt()throws Exception {
        for(boolean missing:new boolean[]{true,false})try(var node=new LanControllerHarness()){
            node.create();node.tick();node.controller.disconnect();node.drain();
            if(missing)node.disk.external.value=null;else node.disk.external.value[node.disk.external.value.length-1]^=1;
            node.controller.connect();node.drain();assertFalse(node.ui.last.ready);assertFalse(node.ui.last.running);
            node.controller.erase();node.drain();assertNull(node.disk.external.value);assertNull(node.disk.sync.value);assertTrue(node.ui.last.ready);
        }
    }
    @Test public void ownPositionIsSavedOnSeparateTimerAndLateCallbackAfterStopIsDiscarded()throws Exception {
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)) {
            node.create();assertTrue(cot.active);
            byte[] xml=("<event uid=\"self\" stale=\""+LanControllerHarness.CLOCK.instant().plusSeconds(60)+"\"/>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            cot.listener.position("self",xml);node.work.syncRepeated.run();
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertNotNull(node.disk.loadSync(group).get("self"));}
            var old=cot.listener;node.controller.disconnect();node.drain();assertFalse(cot.active);
            old.position("self",xml);
            try(var batch=((CotSourceBuffer)LanControllerHarness.field(node.controller,"source")).take()){assertNull(batch.xml);assertTrue(batch.external.isEmpty());}
            node.controller.connect();node.drain();node.tick();
        }
    }
    @Test public void failedDebugSaveAndDisconnectBeforeMainCannotImportFixture()throws Exception {
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)) {
            node.create();node.disk.failSave=true;node.controller.debugFence();node.drain();
            assertEquals(0,cot.debug);assertFalse(node.ui.last.running);
        }
        var queued=new Cot();try(var node=new LanControllerHarness(null,queued)) {
            node.create();node.controller.debugFence();node.work.drain();
            assertEquals(0,queued.debug);node.controller.disconnect();node.work.drain();node.main.drain();
            assertEquals(0,queued.debug);
            node.controller.connect();node.drain();assertTrue(queued.saved.contains(CotPort.FIXTURE_UID));
        }
    }
    @Test public void lostFenceStopsSyncAndDebugRequiresDurableRegistry()throws Exception {
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)) {
            node.create();node.controller.debugFence();node.drain();assertEquals(1,cot.debug);
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertTrue(node.disk.loadSync(group).receivedUids().contains(CotPort.FIXTURE_UID));}
            cot.lost=true;node.tick();assertFalse(node.ui.last.running);assertTrue(node.ui.last.text.contains("柵"));
        }
    }
    @Test public void fenceOnlyFixtureRequiresDurableSaveAndCannotOutliveDisconnect()throws Exception {
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)){
            node.create();node.controller.debugFenceOnly();node.drain();assertEquals(1,cot.debugOnly);assertEquals(0,cot.debug);
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertTrue(node.disk.loadSync(group).receivedUids().contains(CotPort.FIXTURE_UID));}
        }
        cot=new Cot();try(var node=new LanControllerHarness(null,cot)){
            node.create();node.disk.failSave=true;node.controller.debugFenceOnly();node.drain();
            assertEquals(0,cot.debugOnly);assertFalse(node.ui.last.running);
        }
        cot=new Cot();try(var node=new LanControllerHarness(null,cot)){
            node.create();node.controller.debugFenceOnly();node.work.drain();
            node.controller.disconnect();node.work.drain();node.main.drain();assertEquals(0,cot.debugOnly);
        }
    }
    @Test public void sendFixtureDoesNotRegisterOrImportAndCannotOutliveDisconnect()throws Exception {
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)){
            node.create();node.controller.debugFenceSend(CotPort.Send.ANY);node.drain();assertEquals(1,cot.debugSend);
            assertEquals(0,cot.debug);assertEquals(0,cot.debugOnly);assertFalse(cot.saved.contains(CotPort.FIXTURE_UID));
            try(var group=node.disk.load(LanControllerHarness.CLOCK)){assertFalse(node.disk.loadSync(group).receivedUids().contains(CotPort.FIXTURE_UID));}
            node.controller.debugFenceSend(CotPort.Send.ANY);node.work.drain();node.controller.disconnect();node.work.drain();node.main.drain();
            assertEquals(1,cot.debugSend);
        }
    }
    @Test public void eachSendEntryReachesMainOnceWithTheSelectedMethod()throws Exception {
        var cot=new Cot();try(var node=new LanControllerHarness(null,cot)){
            node.create();node.controller.debugFence();node.drain();assertTrue(cot.saved.contains(CotPort.FIXTURE_UID));
            for(var method:CotPort.Send.values()){
                cot.sends.clear();node.controller.debugFenceSend(method);node.drain();
                assertEquals(java.util.List.of(method),cot.sends);
            }
            assertEquals(4,cot.debugSend);assertEquals(1,cot.debug);assertEquals(0,cot.debugOnly);
        }
    }
    @Test public void authenticatedDataFlowsThroughControllerAndDurableSyncStore()throws Exception {
        try(var first=new LanControllerHarness();var second=new LanControllerHarness()) {
            first.create();second.beginJoin(first);
            LanControllerHarness.until(()->second.ui.last.member&&first.logs.contains("LAN_MEMBER_ISSUED"),first,second);
            first.controller.connect();first.drain();
            try(var a=first.disk.load(LanControllerHarness.CLOCK);var b=second.disk.load(LanControllerHarness.CLOCK)) {
                LanControllerHarness.until(()->first.endpoint().isEstablished(b.id())&&second.endpoint().isEstablished(a.id()),first,second);
                var source=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(first.controller,"sync");
                String stale=LanControllerHarness.CLOCK.instant().plusSeconds(60).toString();
                byte[] xml=("<event uid=\"controller-fixture\" stale=\""+stale+"\"><detail>"+"x".repeat(60000)+"</detail></event>").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                assertTrue(source.publish("controller-fixture",xml,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState.Origin.LOCAL_CREATED));
                LanControllerHarness.until(()->second.disk.loadSync(b).get("controller-fixture")!=null,first,second);
                assertArrayEquals(xml,second.disk.loadSync(b).get("controller-fixture").xml());
                assertEquals(0,second.endpoint().callbackFailures());
            }
        }
    }
    @Test public void seventyTwoAuthenticatedFragmentsCanArriveBeforeWorkerDrains()throws Exception {
        burst(false);
    }
    @Test public void maximumValidSixtyFiveFragmentsAreSaved()throws Exception {
        burst(true);
    }
    private static void varint(java.io.ByteArrayOutputStream out,long value){while((value&~127L)!=0){out.write(((int)value&127)|128);value>>>=7;}out.write((int)value);}
    private static void bytes(java.io.ByteArrayOutputStream out,int field,byte[] value){varint(out,(field<<3)|2);varint(out,value.length);out.write(value,0,value.length);}
    private static byte[] recordWire(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotRecord item,byte[] xml){
        var version=new java.io.ByteArrayOutputStream();varint(version,8);varint(version,item.time());bytes(version,2,item.author());
        var record=new java.io.ByteArrayOutputStream();bytes(record,1,item.uid().getBytes(java.nio.charset.StandardCharsets.UTF_8));bytes(record,2,version.toByteArray());bytes(record,3,item.hash());
        varint(record,32);varint(record,1);varint(record,40);varint(record,item.stale());bytes(record,6,xml);
        var envelope=new java.io.ByteArrayOutputStream();varint(envelope,8);varint(envelope,1);bytes(envelope,2,record.toByteArray());return envelope.toByteArray();
    }
    private void burst(boolean valid)throws Exception {
        try(var first=new LanControllerHarness();var second=new LanControllerHarness()) {
            first.create();second.beginJoin(first);
            LanControllerHarness.until(()->second.ui.last.member&&first.logs.contains("LAN_MEMBER_ISSUED"),first,second);
            first.controller.connect();first.drain();
            try(var a=first.disk.load(LanControllerHarness.CLOCK);var b=second.disk.load(LanControllerHarness.CLOCK)) {
                LanControllerHarness.until(()->first.endpoint().isEstablished(b.id())&&second.endpoint().isEstablished(a.id()),first,second);
                long stale=LanControllerHarness.CLOCK.millis()+60000;
                String prefix="<event uid=\"burst-fixture\" stale=\""+java.time.Instant.ofEpochMilli(stale)+"\"><detail>",suffix="</detail></event>";
                byte[] xml=(prefix+"x".repeat(65536-prefix.length()-suffix.length())+suffix).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                var item=io.github.hidemas_suzuki_aka_ziek.distributak.core.CotRecord.record("burst-fixture",LanControllerHarness.CLOCK.millis(),a.id(),stale,xml,1);
                byte[] wire=valid?io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncWire.encode(item):recordWire(item,(prefix+"x".repeat(73000-prefix.length()-suffix.length())+suffix).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                var pieces=io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncFragments.split(wire,new byte[16]);assertEquals(valid?65:72,pieces.size());
                var inbox=(SyncInbox)LanControllerHarness.field(second.controller,"inbox");
                // 先の小さいInventory等を処理し終えてから、受信callbackだけを動かす。
                first.tick();second.tick();
                for(byte[] piece:pieces)assertTrue(first.endpoint().send(b.id(),piece));
                long until=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(3);
                while(inbox.size()<pieces.size()&&System.nanoTime()<until)Thread.sleep(2);
                assertTrue(inbox.size()>=pieces.size());assertTrue(inbox.size()<=80);
                if(valid){LanControllerHarness.until(()->second.disk.loadSync(b).get("burst-fixture")!=null,first,second);assertArrayEquals(xml,second.disk.loadSync(b).get("burst-fixture").xml());}
                else{
                    var sync=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CotSync)LanControllerHarness.field(second.controller,"sync");long before=sync.statistics().rejected();
                    second.drain();assertTrue(sync.statistics().rejected()>before);second.tick();assertNull(second.disk.loadSync(b).get("burst-fixture"));
                    assertEquals(0,((io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncFragments)LanControllerHarness.field(sync,"fragments")).pendingCount());
                }
            }
        }
    }
    @Test public void memberInitializesSyncBeforeOpeningSocket()throws Exception {
        try(var node=new LanControllerHarness()) {
            node.create();
            try(var group=node.disk.load(LanControllerHarness.CLOCK)) {assertTrue(group.syncInitialized);}
        }
    }
    @Test public void missingInitializedSyncStopsAndOffersErase()throws Exception {
        try(var node=new LanControllerHarness()) {
            node.create();node.controller.disconnect();node.drain();
            try(var group=node.disk.load(LanControllerHarness.CLOCK)) {
                group.syncInitialized=true;node.disk.save(group);
            }
            node.disk.sync.value=null;
            node.controller.connect();node.drain();
            assertFalse(node.ui.last.running);assertFalse(node.ui.last.ready);
            assertTrue(node.ui.last.text.contains("消去"));
        }
    }
}
