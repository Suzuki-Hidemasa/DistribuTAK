// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.concurrent.TimeUnit;
import org.junit.Test;
import static org.junit.Assert.*;

public class InitialManagementRetryTest {
    @Test public void ordinaryRejoinRetiresPreviousMembershipWithoutPersistenceReservation()throws Exception {
        var pair=LanRejoinBehaviourTest.expiredPair();
        try(var admin=new LanControllerHarness(pair[0]);var member=new LanControllerHarness(pair[1])){
            LanGroup[] previous={null};
            member.disk.beforeAcceptRejoined=old->{
                previous[0]=old;
                try{
                    var pending=io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminState.class.getDeclaredField("pendingPersistence");pending.setAccessible(true);
                    assertNull(pending.get(old.state));assertNotNull(old.state.snapshot());
                }catch(ReflectiveOperationException failure){throw new AssertionError(failure);}
            };
            member.beginJoin(admin);
            LanControllerHarness.until(()->!member.ui.last.busy&&member.ui.last.running,admin,member);
            assertNotNull(previous[0]);assertNotSame(previous[0],LanBehaviourWiringTest.group(member));
            assertTrue(previous[0].tryClose());
        }
    }

    @Test public void savedInitialJoinCanRetryNormalEndpointWithoutPartialCoordinators()throws Exception {
        try(var admin=new LanControllerHarness();var member=new LanControllerHarness()){
            admin.disk.enableSix();member.disk.enableSix();admin.create();
            member.link.beforeOpen=()->{if(member.link.opens==2)member.link.failOpens=1;};
            member.beginJoin(admin);member.joinFuture().get(5,TimeUnit.SECONDS);member.work.repeated.run();member.drain();
            assertNotNull(member.disk.state.value);assertTrue("Saved initial join must remain retryable",member.ui.last.ready);
            assertNull(member.endpoint());
            for(String field:new String[]{"persistence","managementClock","recovery","roster","sync","dht","managedSessions"})assertNull(LanControllerHarness.field(member.controller,field));
            member.controller.connect();member.drain();assertTrue(member.ui.last.ready);assertNotNull(member.endpoint());
            for(String field:new String[]{"persistence","managementClock","recovery","roster","sync","dht","managedSessions"})assertNotNull(LanControllerHarness.field(member.controller,field));
            assertEquals(3,member.link.opens);assertEquals(2,member.disk.spillOpens);
            var endpoint=member.endpoint();member.work.repeated.run();assertSame(endpoint,member.endpoint());assertEquals(3,member.link.opens);
        }
    }
}
