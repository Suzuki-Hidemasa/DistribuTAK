// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.concurrent.atomic.AtomicInteger;

public class CotFixtureControlTest {
    @Test public void nonDebugCreatesNoButtonAndCannotImportClearMetadataOrSend() {
        var counts=new CotFixtureDiagnostics(true);var control=new CotFixtureControl(false,counts);var calls=new AtomicInteger();
        for(boolean only:new boolean[]{false,true})control.inject(true,true,only,enter->{calls.incrementAndGet();enter.run();});
        for(var method:CotPort.Send.values()){
            assertNull(CotFixtureControl.button(false,()->{calls.incrementAndGet();return new Object();}));
            control.send(true,true,method,enter->{calls.incrementAndGet();enter.run();},enter->{calls.incrementAndGet();enter.run();},enter->{calls.incrementAndGet();enter.run();},enter->{calls.incrementAndGet();enter.run();});
        }
        assertEquals(0,calls.get());assertTrue(control.nevercot(CotPort.FIXTURE_UID));
        assertTrue(counts.text().contains("架空CoT 従来 入れた: 0 入れなかった: 1 失敗: 0"));
        assertTrue(counts.text().contains("架空CoT 柵だけ 入れた: 0 入れなかった: 1 失敗: 0"));
        assertTrue(counts.text().contains("架空CoT 送らせる 押した: 4 断った: 4"));
    }
    @Test public void readinessAndSavedUidAreRequiredForBothImportModesAndSend() {
        for(boolean ready:new boolean[]{false,true})for(boolean saved:new boolean[]{false,true})for(var method:CotPort.Send.values()){
            var counts=new CotFixtureDiagnostics(true);var control=new CotFixtureControl(true,counts);var calls=new AtomicInteger();
            for(boolean only:new boolean[]{false,true})control.inject(ready,saved,only,enter->{enter.run();calls.incrementAndGet();});
            control.send(ready,saved,method,enter->{enter.run();calls.incrementAndGet();},enter->{enter.run();calls.incrementAndGet();},enter->{enter.run();calls.incrementAndGet();},enter->{enter.run();calls.incrementAndGet();});
            assertEquals(ready&&saved?3:0,calls.get());
            assertTrue(counts.text().contains("架空CoT 送らせる 押した: 1 断った: "+(ready&&saved?0:1)));
        }
    }
    @Test public void onlyFixtureLosesNevercotUntilLegacyModeOrLifecycleReset() {
        var control=new CotFixtureControl(true,new CotFixtureDiagnostics(true));
        Object button=new Object();assertSame(button,CotFixtureControl.button(true,()->button));
        control.inject(true,true,true,enter->{assertFalse(control.nevercot(CotPort.FIXTURE_UID));enter.run();});
        assertFalse(control.nevercot(CotPort.FIXTURE_UID));
        for(String uid:new String[]{null,"self","created","received","other-fixture"})assertTrue(control.nevercot(uid));
        control.inject(true,true,false,Runnable::run);assertTrue(control.nevercot(CotPort.FIXTURE_UID));
        control.inject(true,true,true,Runnable::run);control.reset();assertTrue(control.nevercot(CotPort.FIXTURE_UID));
        // 準備不足の試しでは、前に有効だった試しの期間を変えない。
        control.inject(false,true,true,enter->fail());assertTrue(control.nevercot(CotPort.FIXTURE_UID));
    }
    @Test public void beforeDispatchFailureIsCountedAndPropagatedButDispatchFailureIsAlreadyEntered() {
        for(boolean only:new boolean[]{false,true}){
            var counts=new CotFixtureDiagnostics(true);var control=new CotFixtureControl(true,counts);
            RuntimeException failure=new IllegalArgumentException("private fixture preparation");
            try{control.inject(true,true,only,enter->{throw failure;});fail();}catch(RuntimeException e){assertSame(failure,e);}
            String label=only?"柵だけ":"従来";
            assertTrue(counts.text().contains("架空CoT "+label+" 入れた: 0 入れなかった: 0 失敗: 1"));
            try{control.inject(true,true,only,enter->{enter.run();throw failure;});fail();}catch(RuntimeException e){assertSame(failure,e);}
            assertTrue(counts.text().contains("架空CoT "+label+" 入れた: 1 入れなかった: 0 失敗: 1"));
            assertFalse(counts.text().contains(failure.getMessage()));
        }
    }
    @Test public void eachEntryCallsOnlyItsOwnApiOnceAndCountsOnlyItsFailure() {
        String[] names={"broadcast","servers","ANY","TAK_SERVER"};
        for(var method:CotPort.Send.values())for(boolean fails:new boolean[]{false,true}){
            var counts=new CotFixtureDiagnostics(true);var control=new CotFixtureControl(true,counts);int[] calls=new int[4];
            control.send(true,true,method,enter->{enter.run();calls[0]++;if(fails)throw new IllegalStateException("private broadcast");},
                    enter->{enter.run();calls[1]++;if(fails)throw new IllegalStateException("private servers");},
                    enter->{enter.run();calls[2]++;if(fails)throw new IllegalStateException("private ANY");},
                    enter->{enter.run();calls[3]++;if(fails)throw new IllegalStateException("private TAK_SERVER");});
            for(int api=0;api<4;api++){
                int wanted=api==method.ordinal()?1:0;assertEquals(wanted,calls[api]);
                assertTrue(counts.text().contains(names[api]+" 呼び出し: "+wanted+" 例外: "+(fails?wanted:0)));
            }
            assertTrue(counts.text().contains("架空CoT 送らせる 押した: 1 断った: 0"));assertFalse(counts.text().contains("private"));
        }
    }
    @Test public void preparationFailureDoesNotCallTheSelectedApiOrAnyOtherApi() {
        String[] names={"broadcast","servers","ANY","TAK_SERVER"};
        for(var method:CotPort.Send.values()){
            var counts=new CotFixtureDiagnostics(true);var control=new CotFixtureControl(true,counts);
            control.send(true,true,method,enter->{throw new IllegalArgumentException("private preparation");},
                    enter->{throw new IllegalArgumentException("private preparation");},enter->{throw new IllegalArgumentException("private preparation");},enter->{throw new IllegalArgumentException("private preparation");});
            for(int api=0;api<4;api++)assertTrue(counts.text().contains(names[api]+" 呼び出し: 0 例外: "+(api==method.ordinal()?1:0)));
        }
    }
    @Test public void takServerEntryNeverPreparesBroadcastServersOrAny() {
        var counts=new CotFixtureDiagnostics(true);var control=new CotFixtureControl(true,counts);var calls=new AtomicInteger();
        control.send(true,true,CotPort.Send.TAK_SERVER,enter->fail(),enter->fail(),enter->fail(),enter->{enter.run();calls.incrementAndGet();});
        assertEquals(1,calls.get());assertTrue(counts.text().contains("TAK_SERVER 呼び出し: 1 例外: 0"));
        assertTrue(counts.text().contains("架空CoT 送らせる 押した: 1 断った: 0"));
    }
    @Test public void errorsAreNotSwallowedBySendDiagnostics() {
        var control=new CotFixtureControl(true,new CotFixtureDiagnostics(true));Error fatal=new AssertionError("fatal");
        for(var method:CotPort.Send.values())try{control.send(true,true,method,enter->{enter.run();throw fatal;},enter->{enter.run();throw fatal;},enter->{enter.run();throw fatal;},enter->{enter.run();throw fatal;});fail();}catch(Error e){assertSame(fatal,e);}
    }
}
