// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class CotPositionCleanupTest {
    @Test public void positionFailureAlwaysWipesProductionXml(){
        byte[] xml=CotCaptureBaselineTest.xml("position",0,CotCaptureBaselineTest.NOW+60_000,0);var failure=new IllegalStateException();
        assertSame(failure,assertThrows(IllegalStateException.class,()->CotPositionCapture.capture(()->xml,bytes->{throw failure;})));
        assertArrayEquals(new byte[xml.length],xml);
        CotPositionCapture.capture(()->null,bytes->fail());
        byte[] invalid={1,2,3};
        assertThrows(IllegalArgumentException.class,()->CotPositionCapture.capture(()->invalid,bytes->fail()));
        assertArrayEquals(new byte[3],invalid);
    }
}
