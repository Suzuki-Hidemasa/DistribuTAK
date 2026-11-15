// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.CloseReason;

public class LanControllerInternalFailureTest {
    @Test public void internalFailureAndClockFailureKeepSavedStateWhileInvalidErases() throws Exception {
        for(var reason:new CloseReason[]{CloseReason.INTERNAL_FAILURE,CloseReason.CLOCK_FAILURE,CloseReason.LOCAL_CERTIFICATE_INVALID}) {
            try(var f=new LanControllerHarness()) {
                f.create();byte[] saved=f.disk.state.value.clone();
                long epoch=((AtomicLong)LanControllerHarness.field(f.controller,"generation")).get();
                var closed=LanController.class.getDeclaredMethod("closed",long.class,CloseReason.class);closed.setAccessible(true);
                closed.invoke(f.controller,epoch,reason);f.drain();
                assertFalse(f.ui.last.running);
                if(reason==CloseReason.LOCAL_CERTIFICATE_INVALID) { assertTrue(f.disk.erased);assertNull(f.disk.state.value); }
                else { assertFalse(f.disk.erased);assertArrayEquals(saved,f.disk.state.value);assertTrue(f.ui.last.text.contains(reason==CloseReason.INTERNAL_FAILURE?"内部の異常で通信を止めました。記録は消していません":"時計の確認に失敗しました。つなぎ直します")); }
            }
        }
    }
}
