// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;

public class CotProductionCaptureTest {
    @Test public void nonSelfNeverCallsFactoryOrWriterAndSelfKeepsProductionBytes(){
        Object self=new Object(),other=new Object();int[] calls={0,0};
        assertNull(CotCaptureExport.position(other,self,()->{fail();return null;},(event,out)->fail()));
        byte[] xml=CotCaptureExport.position(self,self,()->{calls[0]++;return "body";},(event,out)->{calls[1]++;out.append(event);});
        assertArrayEquals(new int[]{1,1},calls);assertArrayEquals(new byte[]{98,111,100,121},xml);
    }
    @Test public void ordinaryImportStatusHasNoResearchValuesAndFixtureOperationsRemainDebugOnly(){
        var status=new CotImportStatus();status.start(2);status.attempts(1);status.invalidInput();status.gateSkipped();status.expired(1);
        String text=status.text(3);
        assertTrue(text.contains("取り込みの試行: 1"));assertTrue(text.contains("入力が無効で見送った件数: 1"));
        assertTrue(text.contains("保存済み）件数: 2"));
        for(String value:new String[]{"diag6","O1","R2","ns","metadata","成功","XML"})assertFalse(text.contains(value));
        var counts=new CotFixtureDiagnostics(false);var fixture=new CotFixtureControl(false,counts);
        assertNull(CotFixtureControl.button(false,()->{fail();return null;}));fixture.inject(true,true,false,enter->fail());
        assertEquals("",counts.text());
    }
}
