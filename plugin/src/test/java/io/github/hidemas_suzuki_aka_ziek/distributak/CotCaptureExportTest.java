// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class CotCaptureExportTest {
    @Test public void productionExportKeepsBoundsNullAndFailureBehavior(){
        assertNull(CotCaptureExport.read(()->null,(e,out)->fail()));
        var failure=new IllegalStateException();assertSame(failure,assertThrows(IllegalStateException.class,()->CotCaptureExport.read(()->{throw failure;},(e,out)->fail())));
        assertNull(CotCaptureExport.read(Object::new,(e,out)->{throw new java.io.IOException();}));
        assertNull(CotCaptureExport.read(Object::new,(e,out)->out.append("x".repeat(65537))));
        assertNull(CotCaptureExport.read(Object::new,(e,out)->out.append("あ".repeat(21846))));
        assertEquals(65536,CotCaptureExport.read(Object::new,(e,out)->out.append("x".repeat(65536))).length);
    }
}
