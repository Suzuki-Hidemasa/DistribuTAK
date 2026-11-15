// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class LanControllerInitialTest {
    @Test public void failedFirstCreationStopsNowAndRestartsAsUnassigned()throws Exception {
        failedCreation(false);
    }
    @Test public void failedCreationAfterEraseStopsNowAndRestartsAsErased()throws Exception {
        failedCreation(true);
    }
    private void failedCreation(boolean erased)throws Exception {
        LanControllerHarness.Disk disk;
        try(var f=new LanControllerHarness()) {
            disk=f.disk;disk.erased=erased;disk.failSave=true;
            f.controller.create();f.drain();
            assertFalse(f.ui.last.ready);assertFalse(f.ui.last.member);
            assertTrue(f.ui.last.text.contains("処理できません。通信を停止しました"));
            assertNull(disk.state.value);assertNull(disk.temporary.value);
        }
        try(var restarted=new LanControllerHarness(disk)) {
            assertTrue(restarted.ui.last.ready);assertFalse(restarted.ui.last.member);
            assertEquals(erased,restarted.ui.last.erased);
            assertTrue(restarted.ui.last.text.contains(erased?"消去済み":"未所属"));
            assertFalse(restarted.ui.last.running);
        }
    }
}
