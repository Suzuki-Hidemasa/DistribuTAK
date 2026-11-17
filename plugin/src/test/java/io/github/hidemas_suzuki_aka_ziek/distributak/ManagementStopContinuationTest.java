// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
public class ManagementStopContinuationTest {
    @Test public void unrecoverableExplanationSurvivesClosingNetwork()throws Exception {
        try(var h=new LanControllerHarness(ManagementScreenTest.recoveringDisk())) {
            h.offset.addAndGet(240_000_000_000L);h.tick();
            assertTrue(h.ui.last.text.contains("取り直せないため"));
            h.controller.disconnect();h.drain();
            assertTrue(h.ui.last.text.contains("取り直せないため"));
            assertTrue(h.ui.last.text.contains("消去して新しい招待で入り直せます"));
            assertNull(h.endpoint());assertFalse(h.disk.erased);
        }
    }
    @Test public void recoveryRejectsNormalOperationsAndKeepsRecords()throws Exception {
        try(var h=new LanControllerHarness(ManagementScreenTest.recoveringDisk())) {
            byte[] saved=h.disk.state.value.clone();int opens=h.link.opens;var endpoint=h.endpoint();
            h.controller.create();h.drain();h.controller.showInvitation(h.controller.ticket(),64);h.drain();h.controller.connect();h.drain();
            assertTrue(java.util.Arrays.equals(saved,h.disk.state.value));assertEquals(opens,h.link.opens);
            assertTrue(endpoint==h.endpoint());assertEquals(0,h.ui.qrs);assertFalse(h.ui.last.operationsReady);assertFalse(h.disk.erased);
        }
    }
}
