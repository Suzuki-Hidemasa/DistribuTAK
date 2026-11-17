// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RecoveryControllerTest {
    @Test public void loneClearLegacySlotRetainsDecisionBAndCanOpenTransport()throws Exception {
        for(int offset:new int[]{0,StopMarker.SLOT_BYTES}){
            var disk=new LanControllerHarness.Disk(LanControllerHarness.freePort());
            try(var g=LanGroup.create(disk.port(),LanControllerHarness.CLOCK,new java.security.SecureRandom())){
                disk.save(g);disk.enableSix();disk.prepareNetwork(g);
            }
            disk.stopMarker.bytes[offset]^=1;
            assertEquals(StopMarker.Status.INVALID,disk.stopMarker.marker().inspect().status());
            try(var h=new LanControllerHarness(disk)){
                assertEquals(StopMarker.Status.CLEAR,disk.stopMarker.marker().inspect().status());
                assertNotNull(h.endpoint());assertEquals(1,h.link.opens);assertTrue(h.ui.last.operationsReady);
            }
        }
    }
    @Test public void corruptedLegacyMigrationMarkerStaysInvalidAndNeverOpensTransport()throws Exception {
        var disk=new LanControllerHarness.Disk(LanControllerHarness.freePort());
        try(var g=LanGroup.create(disk.port(),LanControllerHarness.CLOCK,new java.security.SecureRandom())){
            disk.save(g);
            assertEquals(5,java.nio.ByteBuffer.wrap(disk.envelope.open(disk.state.value)).getInt());
            disk.enableSix();disk.prepareNetwork(g);
            assertEquals(StopMarker.Status.CLEAR,disk.stopMarker.marker().inspect().status());
        }
        byte[] state=disk.state.value.clone(),settings=disk.settings.value.clone();
        disk.stopMarker.bytes[0]^=1;
        disk.stopMarker.bytes[StopMarker.SLOT_BYTES]^=1;
        byte[] invalid=disk.stopMarker.bytes.clone();int writes=disk.stopMarker.writes;
        assertEquals(StopMarker.Status.INVALID,disk.stopMarker.marker().inspect().status());
        try(var h=new LanControllerHarness(disk)){
            assertEquals(StopMarker.Status.INVALID,disk.stopMarker.marker().inspect().status());
            assertNull(h.endpoint());assertEquals(0,h.link.opens);
            assertNull(LanControllerHarness.field(h.controller,"sync"));
            assertNull(LanControllerHarness.field(h.controller,"dht"));
            assertNull(LanControllerHarness.field(h.controller,"recovery"));
            assertTrue(h.ui.last.text.contains("保存した停止の記録を確かめられません。通信を止めています"));
            assertFalse(h.ui.last.operationsReady);
            h.offset.addAndGet(300_000_000_000L);h.tick();h.tick();
            assertNull(h.endpoint());assertEquals(0,h.link.opens);assertEquals(writes,disk.stopMarker.writes);
            assertArrayEquals(invalid,disk.stopMarker.bytes);assertArrayEquals(state,disk.state.value);
            assertArrayEquals(settings,disk.settings.value);assertFalse(disk.erased);
        }
    }
    @Test public void recoveryCompletionDiscardsQueuedInputBeforeStartingNormalSynchronization()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();
            ((CotSync)LanControllerHarness.field(h.controller,"sync")).close();
            var sync=LanController.class.getDeclaredField("sync");sync.setAccessible(true);sync.set(h.controller,null);
            var stop=LanController.class.getDeclaredMethod("stopDht");stop.setAccessible(true);stop.invoke(h.controller);
            var limited=LanController.class.getDeclaredField("recoveringNetwork");limited.setAccessible(true);limited.setBoolean(h.controller,true);
            var inbox=(SyncInbox)LanControllerHarness.field(h.controller,"inbox");
            assertTrue(inbox.offer(0,new byte[32],new byte[16],new byte[]{1},0));assertEquals(1,inbox.size());
            var finish=LanController.class.getDeclaredMethod("finishRecovery");finish.setAccessible(true);finish.invoke(h.controller);
            assertEquals(0,inbox.size());assertNotNull(LanControllerHarness.field(h.controller,"sync"));
        }
    }
    @Test public void candidateLessStartupOpensOnlyLimitedTransportBeforeFirst()throws Exception{
        var disk=new LanControllerHarness.Disk(LanControllerHarness.freePort());disk.enableSix();
        try(var g=LanGroup.create(disk.port(),LanControllerHarness.CLOCK,new java.security.SecureRandom())){
            disk.save(g);disk.stopMarker.marker().active(new StopMarker.Target(g.saveSeq,1,new byte[32],new byte[32],StopMarker.RECEIVED));
        }
        try(var h=new LanControllerHarness(disk)){
            assertNotNull(h.endpoint());assertNull(LanControllerHarness.field(h.controller,"sync"));assertNull(LanControllerHarness.field(h.controller,"dht"));
            var c=(CorePersistenceCoordinator)LanControllerHarness.field(h.controller,"persistence");
            assertEquals(CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,c.state());
            assertTrue(h.ui.last.text.contains("保存がいっぱい"));assertEquals(0,disk.reserves);
            h.controller.sendTest();h.drain();assertTrue(h.ui.last.text.contains("保存がいっぱい"));assertEquals(0,disk.spillOpens);
        }
    }
    @Test public void memberRetrievesOriginalSignedListAndStartsNormalTrafficAfterClear()throws Exception{
        var disks=LanProofRenewalTest.legacyPair();byte[] expected;
        try(var a=disks[0].load(LanControllerHarness.CLOCK);var m=disks[1].load(LanControllerHarness.CLOCK)){
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,a.groupId,1,LanControllerHarness.CLOCK.millis(),List.of(StoredUpdatesTest.key(81)),a.administratorSecret);
            expected=body.encode();a.state.acceptRevocations(body);disks[0].save(a);
            disks[1].enableSix();disks[1].save(m);
            disks[1].stopMarker.marker().active(new StopMarker.Target(m.saveSeq,1,new byte[32],new byte[32],StopMarker.RECEIVED));
        }
        try(var a=new LanControllerHarness(disks[0]);var m=new LanControllerHarness(disks[1])){
            long deadline=System.nanoTime()+5_000_000_000L;
            while(true){
                var c=(CorePersistenceCoordinator)LanControllerHarness.field(m.controller,"persistence");
                if(c!=null&&c.state()==CorePersistenceCoordinator.State.RUNNING)break;
                if(System.nanoTime()>deadline){
                    var recovery=LanControllerHarness.field(m.controller,"recovery");
                    var sender=(ManagementPageSender)LanControllerHarness.field(LanControllerHarness.field(a.controller,"recovery"),"sender");
                    fail("recovery timeout; state="+(c==null?"none":c.state())+" requests="+(recovery==null?0:LanControllerHarness.field(recovery,"requests"))
                            +" sender-active="+sender.active()+" sender-failed="+sender.failed()+" held="+sender.heldBytes());
                }
                // 握手の再送も注入した時計で進め、実時間の再送待ちに試験を依存させない。
                // Advance handshake retries with the injected clock so the test does not depend on real-time retry waits.
                a.offset.addAndGet(100_000_000L);m.offset.addAndGet(100_000_000L);
                a.tick();m.tick();Thread.sleep(5);
            }
            assertEquals(StopMarker.Status.CLEAR,disks[1].stopMarker.marker().inspect().status());
            assertArrayEquals(expected,LanBehaviourWiringTest.group(m).state.revocations().encode());
            assertNotNull(LanControllerHarness.field(m.controller,"sync"));assertNotNull(LanControllerHarness.field(m.controller,"dht"));
        }
    }
}
