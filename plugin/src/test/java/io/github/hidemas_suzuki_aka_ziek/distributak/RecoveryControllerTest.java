// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class RecoveryControllerTest {
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
