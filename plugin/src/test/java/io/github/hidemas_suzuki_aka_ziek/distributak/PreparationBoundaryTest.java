// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.concurrent.atomic.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class PreparationBoundaryTest {
    @Test public void resultAtDeadlineStopsEvenAfterLastFirstConfirmed()throws Exception {boundary(60_000_000_000L,true);}
    @Test public void resultAfterClockReversalStopsEvenAfterLastFirstConfirmed()throws Exception {boundary(-1,true);}
    @Test public void resultBeforeDeadlinePermitsInvitation()throws Exception {boundary(59_000_000_000L,false);}
    static void boundary(long resultElapsed,boolean stopped)throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        var now=new AtomicLong();var start=new AtomicLong();var resultReads=new AtomicInteger();
        var reference=new AtomicReference<AdministrationPreparation>();
        java.util.function.LongSupplier nanos=()->{
            for(var frame:Thread.currentThread().getStackTrace())if(frame.getClassName().equals(GroupAdministration.Preparation.class.getName())&&frame.getMethodName().equals("result")) {
                var value=reference.get();
                if(value!=null&&value.preparation.incomplete()==0){resultReads.incrementAndGet();return start.get()+resultElapsed;}
            }
            return now.get();
        };
        try(var a=new LanControllerHarness(disks[0],CotPort.NONE,nanos,wall);var m=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            drive(()->a.endpoint().isEstablished(LanBehaviourWiringTest.group(m).id()),now,a,m);
            a.controller.showRejoinInvitation(a.controller.ticket(),64);a.drain();assertEquals(0,a.ui.qrs);
            reference.set((AdministrationPreparation)LanControllerHarness.field(a.controller,"preparation"));start.set(now.get());
            now.set(start.get()+59_000_000_000L);
            drive(()->LanControllerHarness.field(a.controller,"preparation")==null, null,a,m);
            assertEquals(1,resultReads.get());assertEquals(stopped?0:1,a.ui.qrs);
            assertEquals(stopped,LanControllerHarness.field(a.controller,"invitation")==null);
            assertEquals(2,LanBehaviourWiringTest.group(m).certificate.format());assertFalse(a.disk.erased);
        }
    }
    static void drive(LanControllerHarness.Check done,AtomicLong now,LanControllerHarness a,LanControllerHarness m)throws Exception {
        long guard=System.nanoTime()+5_000_000_000L;
        while(!done.ok()) {
            if(now!=null)now.addAndGet(100_000_000L);
            m.offset.addAndGet(100_000_000L);a.tick();m.tick();
            if(System.nanoTime()>guard)throw new AssertionError("準備の試験が進みません");
            Thread.sleep(2);
        }
        a.drain();m.drain();
    }
}
