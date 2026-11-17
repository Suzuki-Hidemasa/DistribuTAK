// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ManagementEntryTest {
    @Test public void suspendedStatesRejectSynchronizationDiscoveryAndInvitationEntries()throws Exception {
        for(var state:List.of(CorePersistenceCoordinator.State.PERSISTING,CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,
                CorePersistenceCoordinator.State.STORAGE_FAILED)){
            var cot=new Cot();
            try(var h=new LanControllerHarness(null,cot)){
                h.jitterValue=0;h.create();int polls=cot.polls,reserves=h.disk.reserves;
                var coordinator=(CorePersistenceCoordinator)LanControllerHarness.field(h.controller,"persistence");
                var status=CorePersistenceCoordinator.class.getDeclaredField("state");status.setAccessible(true);status.set(coordinator,state);
                h.work.syncRepeated.run();
                ((LanDht)LanControllerHarness.field(h.controller,"dht")).step();
                h.controller.showInvitation(h.controller.ticket());h.drain();
                assertEquals(polls,cot.polls);assertEquals(reserves,h.disk.reserves);assertEquals(0,h.ui.qrs);
                assertNull(LanControllerHarness.field(h.controller,"invitation"));
                status.set(coordinator,CorePersistenceCoordinator.State.RUNNING);
            }
        }
    }
    @Test public void discoveryReservationReturningAfterStopDoesNotSignOrDisableDiscovery()throws Exception {
        try(var h=new LanControllerHarness()){
            h.jitterValue=0;h.create();var dht=(LanDht)LanControllerHarness.field(h.controller,"dht");
            var cfg=(LanDht.Config)LanControllerHarness.field(dht,"cfg");
            var sessions=(SessionManager)LanControllerHarness.field(h.endpoint(),"sessions");
            var reserve=cfg.reserve;var issuer=cfg.issuer;int[] signed={0};
            cfg.reserve=()->{long version=reserve.reserve();sessions.close();return version;};
            cfg.issuer=(v,t)->{signed[0]++;return issuer.issue(v,t);};
            dht.step();assertEquals(0,signed[0]);assertTrue(dht.active());
        }
    }
    static final class Cot extends LanControllerSyncTest.Cot {
        int polls;
        @Override public void poll(long now){polls++;}
    }
    @Test public void persistingDoesNotConsumeCaptureOrPollSynchronization()throws Exception {
        var cot=new Cot();
        try(var h=new LanControllerHarness(null,cot)){
            h.create();int before=cot.polls;
            PersistenceControllerTest.saving(h.controller,()->{
                h.work.syncRepeated.run();assertEquals(before,cot.polls);
            });
            h.work.syncRepeated.run();assertTrue(cot.polls>before);
        }
    }
    @Test public void persistingDoesNotReserveOrPublishDiscoveryState()throws Exception {
        try(var h=new LanControllerHarness()){
            h.jitterValue=0;h.create();var dht=(LanDht)LanControllerHarness.field(h.controller,"dht");
            int before=h.disk.reserves;
            PersistenceControllerTest.saving(h.controller,()->{
                dht.step();assertEquals(before,h.disk.reserves);assertTrue(dht.active());
            });
            dht.step();assertTrue(h.disk.reserves>before);
        }
    }
    @Test public void persistingUdpMutationIsRefusedWithoutChangingCurrentList()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();var group=(LanGroup)LanControllerHarness.field(h.controller,"group");
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group.groupId,1,LanControllerHarness.CLOCK.millis(),
                    List.of(Crypto.blake2s(new byte[]{3})),group.administratorSecret);
            PersistenceControllerTest.saving(h.controller,()->{
                assertFalse(h.endpoint().acceptRevocations(body));assertEquals(0,group.state.revocations().version());
            });
            assertFalse(h.endpoint().isTerminated());
        }
    }
}
