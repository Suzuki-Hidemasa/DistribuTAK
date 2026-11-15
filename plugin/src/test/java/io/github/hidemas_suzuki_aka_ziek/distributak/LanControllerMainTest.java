// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerMainTest {
    @Test public void qrFailureStopsCommunicationWipesPixelsAndShowsFixedFailure()throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();var endpoint=f.endpoint();f.ui.failQr=true;
            f.controller.showInvitation(f.controller.ticket());f.drain();f.drain();
            assertTrue(endpoint.isTerminated());assertNull(f.endpoint());assertFalse(f.ui.last.ready);
            assertTrue(f.ui.last.text.contains("処理できません。通信を停止しました"));
            assertFalse(f.ui.sensitive);assertNotNull(f.ui.transferred);
            assertArrayEquals(new byte[f.ui.transferred.length],f.ui.transferred);
            assertFalse(f.logs.toString().contains("private"));
        }
    }
    @Test public void cameraActionFailureUsesSameMainGuard()throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();var endpoint=f.endpoint();f.ui.sensitive=true;
            f.controller.runMain(()->{throw new IllegalStateException("private camera detail");});f.drain();
            assertTrue(endpoint.isTerminated());assertFalse(f.ui.sensitive);assertFalse(f.ui.last.ready);
        }
    }
    @Test public void repeatedFailureInFailureNotificationDoesNotRequeueForever()throws Exception {
        try(var f=new LanControllerHarness()) {
            f.create();var endpoint=f.endpoint();f.ui.failRender=true;f.ui.failHide=true;
            f.controller.runMain(()->{throw new IllegalStateException();});f.drain();f.drain();
            int renders=f.ui.renders;f.tick();f.tick();assertEquals(renders,f.ui.renders);
            assertTrue(endpoint.isTerminated());assertTrue(f.work.tasks.isEmpty());assertTrue(f.main.tasks.isEmpty());
            assertEquals(1,java.util.Collections.frequency(f.logs,"LAN_STOPPED"));
            f.ui.failHide=false;
        }
    }
    @Test public void mainGuardDoesNotCatchErrors()throws Exception {
        try(var f=new LanControllerHarness()) {
            AssertionError error=new AssertionError("simulated Error");
            assertSame(error,assertThrows(AssertionError.class,()->f.controller.runMain(()->{throw error;})));
        }
    }
}
