// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class UnknownConfirmationTest {
    @Test public void beginFailureAfterCertificateSaveStopsWithoutRollback()throws Exception {
        try(var p=new UnknownOnlineTest.Pair()) {
            Object token=p.ask();var sessions=(SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");
            p.a.disk.afterLocalRenewal=sessions::close;
            p.a.controller.confirmUnknown(token);p.a.drain();
            assertTrue((boolean)LanControllerHarness.field(p.a.controller,"committedNotApplied"));
            assertNull(p.a.endpoint());assertTrue(p.a.ui.last.text.contains("保存した変更を適用できません"));
            try(var saved=p.a.disk.load(p.wall)){assertEquals(2,saved.certificate.format());assertEquals(0,saved.state.administrators().version());}
        }
    }
    @Test public void beginFailureCancelsOnlyManagementOperation()throws Exception {
        try(var h=new LanControllerHarness(UnknownRemovalTest.disk())) {
            Object token=UnknownRemovalTest.ask(h);
            var active=(AdministrationPreparation)LanControllerHarness.field(h.controller,"preparation");active.preparation.cancel();
            h.controller.confirmUnknown(token);h.drain();
            assertTrue(h.ui.last.ready);assertNotNull(h.endpoint());assertNull(LanControllerHarness.field(h.controller,"preparation"));
        }
    }
    @Test public void wrongHandlePreservesPendingConfirmation()throws Exception {
        try(var h=new LanControllerHarness(UnknownRemovalTest.disk())) {
            Object token=UnknownRemovalTest.ask(h);Object active=LanControllerHarness.field(h.controller,"preparation");
            String message=(String)LanControllerHarness.field(h.controller,"message");
            h.controller.confirmUnknown(new Object());h.drain();
            assertTrue(active==LanControllerHarness.field(h.controller,"preparation"));assertTrue(token==h.ui.confirmation);
            assertEquals(message,LanControllerHarness.field(h.controller,"message"));
        }
    }
    @Test public void repeatedHandlePreservesCompletedMessage()throws Exception {
        try(var h=new LanControllerHarness(UnknownRemovalTest.disk())) {
            Object token=UnknownRemovalTest.ask(h);h.controller.confirmUnknown(token);h.drain();
            String message=(String)LanControllerHarness.field(h.controller,"message");
            h.controller.confirmUnknown(token);h.drain();assertEquals(message,LanControllerHarness.field(h.controller,"message"));
        }
    }
    @Test public void lostAuthorityCancelsWholePendingOperation()throws Exception {
        try(var h=new LanControllerHarness(UnknownRemovalTest.disk())) {
            Object token=UnknownRemovalTest.ask(h);var group=LanBehaviourWiringTest.group(h);
            Crypto.wipe(group.administratorSecret);group.administratorSecret=new byte[0];
            h.controller.confirmUnknown(token);h.drain();
            assertNull(h.ui.confirmation);assertEquals(3,group.state.administrators().bindings().size());assertTrue(h.ui.last.ready);
        }
    }
    @Test public void pendingConfirmationDoesNotStopAutomaticRenewal()throws Exception {
        try(var p=new UnknownOnlineTest.Pair()) {
            p.wall.now.addAndGet(20L*86_400_000);p.ask();
            p.a.tick();
            assertTrue((boolean)LanControllerHarness.field(p.a.controller,"renewalAttempted"));
            assertNotNull(p.a.ui.confirmation);
        }
    }
}
