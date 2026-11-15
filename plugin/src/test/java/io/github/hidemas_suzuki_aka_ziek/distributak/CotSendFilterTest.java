// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.Set;
import org.junit.Test;
import static org.junit.Assert.*;

public class CotSendFilterTest {
    static CotFence gate(){var gate=new CotFence();gate.begin(0);gate.registered(true,0);gate.saved(Set.of("received"));return gate;}
    static CotSendFilter.Event event(String uid,boolean delete,String... targets){return new CotSendFilter.Event(){
        public String uid(){return uid;}public boolean deletion(){return delete;}
        public int linkCount(){return targets.length;}public String linkUid(int index){return targets[index];}
    };}
    @Test public void receivedUidOrDeleteTargetIsConsumedAndUnrelatedEventsAreIgnored(){
        var gate=gate();
        assertEquals(CotSendFilter.Result.CONSUMED,CotSendFilter.process(gate,event("received",false),0));
        assertEquals(CotSendFilter.Result.CONSUMED,CotSendFilter.process(gate,event("different",true,"local","received"),0));
        assertEquals(CotSendFilter.Result.IGNORED,CotSendFilter.process(gate,event("different",false,"received"),0));
        assertEquals(CotSendFilter.Result.IGNORED,CotSendFilter.process(gate,event("local",true,"other"),0));
        assertEquals(CotSendFilter.Result.IGNORED,CotSendFilter.process(gate,null,0));assertEquals(2,gate.consumed());assertFalse(gate.failed());
    }
    @Test public void runtimeExceptionsAtEachReadConsumeThatEventAndFailFenceWithoutDetails(){
        for(int fail=0;fail<4;fail++){
            int step=fail;var gate=gate();var event=new CotSendFilter.Event(){
                public String uid(){if(step==0)throw new IllegalStateException("private detail");return "local";}
                public boolean deletion(){if(step==1)throw new IllegalStateException("private detail");return true;}
                public int linkCount(){if(step==2)throw new IllegalStateException("private detail");return 1;}
                public String linkUid(int index){throw new IllegalStateException("private detail");}
            };
            assertEquals(CotSendFilter.Result.CONSUMED,CotSendFilter.process(gate,event,0));assertTrue(gate.failed());
        }
    }
    @Test public void errorsAreNotCaught(){
        var event=new CotSendFilter.Event(){public String uid(){throw new AssertionError();}public boolean deletion(){return false;}public int linkCount(){return 0;}public String linkUid(int index){return null;}};
        assertThrows(AssertionError.class,()->CotSendFilter.process(gate(),event,0));
    }
}
