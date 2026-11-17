// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class InvitationDeadlineTest {
    @Test public void disconnectedTargetRemainsRequiredUntilDeadline()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var a=new LanControllerHarness(disks[0],CotPort.NONE,wall);var m=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            LanProofRenewalTest.until(()->a.endpoint().isEstablished(LanBehaviourWiringTest.group(m).id()),a,m);
            var tap=new LanProofRenewalTest.Tap();tap.dropReplies=true;tap.install(a);
            a.controller.showRejoinInvitation(a.controller.ticket(),64);a.drain();
            m.controller.disconnect();m.drain();
            // 失効や一覧を変えず、輸送の切断だけを再現する。
            // Model transport disconnection without revocation or list changes.
            var sessions=LanControllerHarness.field(a.controller,"managedSessions");
            synchronized(sessions){
                var peers=(java.util.Map<?,?>)LanControllerHarness.field(sessions,"peers");
                for(var peer:peers.values()){
                    var drop=sessions.getClass().getDeclaredMethod("destroy",peer.getClass());drop.setAccessible(true);drop.invoke(sessions,peer);
                }
            }
            a.offset.addAndGet(59_000_000_000L);a.tick();
            assertNotNull((String)LanControllerHarness.field(a.controller,"message"),LanControllerHarness.field(a.controller,"preparation"));assertEquals(0,a.ui.qrs);
            a.offset.addAndGet(1_000_000_000L);a.tick();
            assertNull(LanControllerHarness.field(a.controller,"preparation"));assertEquals(0,a.ui.qrs);assertFalse(a.disk.erased);
        }
    }
    @Test public void invitationWaitsForRenewedFirstBeforeShowingQr()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var a=new LanControllerHarness(disks[0],CotPort.NONE,wall);var m=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            LanProofRenewalTest.until(()->a.endpoint().isEstablished(LanBehaviourWiringTest.group(m).id()),a,m);
            a.controller.showRejoinInvitation(a.controller.ticket(),64);a.drain();assertEquals(0,a.ui.qrs);
            LanProofRenewalTest.until(()->a.ui.qrs==1,a,m);
            assertEquals(2,LanBehaviourWiringTest.group(m).certificate.format());
            assertNotNull(a.endpoint().authenticatedFirstCertificate(LanBehaviourWiringTest.group(m).id()));
        }
    }
    @Test public void waitingJustBeforeDeadlineDoesNotRegisterInvitation()throws Exception {waiting(59_000_000_000L,false,false);}
    @Test public void clockReversalStopsInvitation()throws Exception {waiting(-60_000_000_000L,true,false);}
    @Test public void changedScreenStopsInvitation()throws Exception {waiting(0,true,true);}
    @Test public void cancellationKeepsSavedMembership()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var a=new LanControllerHarness(disks[0],CotPort.NONE,wall);var m=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            LanProofRenewalTest.until(()->a.endpoint().isEstablished(LanBehaviourWiringTest.group(m).id()),a,m);
            var tap=new LanProofRenewalTest.Tap();tap.dropReplies=true;tap.install(a);
            a.controller.showRejoinInvitation(a.controller.ticket(),64);a.drain();
            a.controller.cancelManagement();a.drain();assertNull(LanControllerHarness.field(a.controller,"preparation"));
            assertEquals(0,a.ui.qrs);assertFalse(a.disk.erased);
        }
    }
    static void waiting(long elapsed,boolean stopped,boolean screen)throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var a=new LanControllerHarness(disks[0],CotPort.NONE,wall);var m=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            LanProofRenewalTest.until(()->a.endpoint().isEstablished(LanBehaviourWiringTest.group(m).id()),a,m);
            var tap=new LanProofRenewalTest.Tap();tap.dropReplies=true;tap.install(a);
            a.controller.showRejoinInvitation(a.controller.ticket(),64);a.drain();
            if(screen)a.ui.epoch++;a.offset.addAndGet(elapsed);a.tick();
            assertEquals(0,a.ui.qrs);assertNull(LanControllerHarness.field(a.controller,"invitation"));
            assertEquals(stopped,LanControllerHarness.field(a.controller,"preparation")==null);assertFalse(a.disk.erased);
        }
    }
    @Test public void onlineLegacyPeerMustSwitchBeforeInvitationIsRegistered()throws Exception {
        var disks=LanProofRenewalTest.legacyPair();var wall=new LanAutomaticRenewalTest.Wall();wall.now.incrementAndGet();
        try(var a=new LanControllerHarness(disks[0],CotPort.NONE,wall);var m=new LanControllerHarness(disks[1],CotPort.NONE,wall)) {
            LanProofRenewalTest.until(()->a.endpoint().isEstablished(LanBehaviourWiringTest.group(m).id()),a,m);
            var tap=new LanProofRenewalTest.Tap();tap.dropReplies=true;tap.install(a);
            a.controller.showRejoinInvitation(a.controller.ticket(),64);a.drain();
            assertEquals(0,a.ui.qrs);assertNull(LanControllerHarness.field(a.controller,"invitation"));
            a.offset.addAndGet(60_000_000_000L);a.tick();a.drain();
            assertEquals(0,a.ui.qrs);assertNull(LanControllerHarness.field(a.controller,"invitation"));
            assertTrue((String)LanControllerHarness.field(a.controller,"message"),a.ui.last.text.contains("招待を止めました"));assertFalse(a.disk.erased);
        }
    }
}
