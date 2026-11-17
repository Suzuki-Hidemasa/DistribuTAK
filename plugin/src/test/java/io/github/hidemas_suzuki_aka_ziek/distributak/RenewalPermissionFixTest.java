// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class RenewalPermissionFixTest {
    static final class SwitchingClock extends java.time.Clock {
        long now=LanControllerHarness.CLOCK.millis()+20L*86_400_000;
        final Thread owner=Thread.currentThread();Runnable next;
        public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}
        public java.time.Clock withZone(java.time.ZoneId zone){return this;}
        public java.time.Instant instant(){return java.time.Instant.ofEpochMilli(millis());}
        public long millis(){if(Thread.currentThread()==owner&&next!=null){var action=next;next=null;action.run();}return now;}
    }
    @Test public void permissionLossAfterEntryKeepsRequestAndDoesNotStartFirst()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new SwitchingClock();
        try(var admin=new LanControllerHarness(disks[0],CotPort.NONE,wall);var member=new LanControllerHarness(disks[1],CotPort.NONE,wall)){
            var tap=new LanProofRenewalTest.Tap();tap.dropDeliveries=true;tap.install(member);
            LanProofRenewalTest.until(()->tap.delivery!=null,admin,member);
            byte[] peer=LanBehaviourWiringTest.group(admin).id(),session=member.endpoint().sessionId(peer);
            var requests=(io.github.hidemas_suzuki_aka_ziek.distributak.core.ProofRequests)LanControllerHarness.field(member.controller,"proofRequests");
            assertNotNull(requests.match(peer,session,tap.delivery));
            var coordinator=(io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator)LanControllerHarness.field(member.controller,"persistence");
            var status=coordinator.getClass().getDeclaredField("state");status.setAccessible(true);
            wall.next=()->{try{status.set(coordinator,io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.State.PERSISTING);}catch(ReflectiveOperationException failure){throw new AssertionError(failure);}};
            var receive=LanController.class.getDeclaredMethod("receiveProofRenewal",byte[].class,byte[].class,byte[].class);receive.setAccessible(true);
            try{
                receive.invoke(member.controller,peer,session,tap.delivery.encode());assertNull(wall.next);
                assertNotNull("Denied renewal discarded the pending request",requests.match(peer,session,tap.delivery));
                assertEquals(0,LanBehaviourWiringTest.group(member).renewalCount);
                assertFalse(((io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManager)LanControllerHarness.field(member.endpoint(),"sessions")).isHandshaking(peer));
            }finally{wall.next=null;status.set(coordinator,io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.State.RUNNING);}
        }
    }

    @Test public void deniedRenewalDoesNotReportAnUnneededSuccessfulUpdate()throws Exception {
        try(var h=new LanControllerHarness()){
            h.create();var group=LanBehaviourWiringTest.group(h);
            var apply=LanController.class.getDeclaredMethod("applyRenewal",io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record.class);apply.setAccessible(true);
            PersistenceControllerTest.saving(h.controller,()->assertFalse("Denied validation must not report success",(Boolean)apply.invoke(h.controller,group.certificate)));
            assertTrue((Boolean)apply.invoke(h.controller,group.certificate));
        }
    }
}
