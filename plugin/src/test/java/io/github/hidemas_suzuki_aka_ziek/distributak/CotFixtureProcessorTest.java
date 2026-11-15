// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class CotFixtureProcessorTest {
    @Test public void nonDebugProcessMatchesFilterForAllowedBlockedAndFailingUidWithoutDisplayingCounts(){
        var counts=new CotFixtureDiagnostics(false);assertEquals("",counts.text());
        for(int method=0;method<4;method++)for(int scenario:new int[]{0,1,2}){
            int[] reads={0,0};
            java.util.function.IntFunction<CotSendFilter.Event> make=slot->new CotSendFilter.Event(){
                public String uid(){
                    reads[slot]++;if(scenario==2)throw new IllegalStateException("synthetic failure");
                    return scenario==1?CotPort.FIXTURE_UID:"non-debug-unmarked-test";
                }
                public boolean deletion(){return false;}
                public int linkCount(){throw new AssertionError();}
                public String linkUid(int index){throw new AssertionError();}
            };
            var reference=gate(true);var actual=gate(true);
            var expected=CotSendFilter.process(reference,make.apply(0),0);
            var result=counts.process(actual,make.apply(1),0,method);
            assertEquals(scenario==0?CotSendFilter.Result.IGNORED:CotSendFilter.Result.CONSUMED,result);
            assertEquals(expected,result);assertEquals(reference.failed(),actual.failed());
            assertEquals(scenario==2,actual.failed());assertEquals(reference.consumed(),actual.consumed());
            assertArrayEquals(new int[]{1,1},reads);assertEquals("",counts.text());
        }
    }
    private static CotFence gate(boolean fixture){
        var gate=new CotFence();gate.begin(0);gate.registered(true,0);
        gate.saved(fixture?Set.of(CotPort.FIXTURE_UID,"private-real-uid"):Set.of("private-real-uid"));return gate;
    }
    private static CotSendFilter.Event event(String uid){return new CotSendFilter.Event(){
        public String uid(){return uid;}public boolean deletion(){return false;}
        public int linkCount(){throw new AssertionError();}public String linkUid(int n){throw new AssertionError();}
    };}
    private static void assertRow(String text,String prefix,int[] expected){
        String row=text.lines().filter(line->line.startsWith(prefix+":")).findFirst().orElseThrow();
        String[] labels={"TAK_SERVER","POINT_TO_POINT","ANY","その他"};
        for(int n=0;n<labels.length;n++)assertTrue(row.contains(labels[n]+": "+expected[n]+" "));
    }
    @Test public void everyMethodCountsOnlyExactFixtureWhileKeepingAllUidCounts() {
        for(boolean saved:new boolean[]{false,true}){
            var counts=new CotFixtureDiagnostics(true);var gate=gate(saved);
            for(int method=0;method<4;method++){
                assertEquals(saved?CotSendFilter.Result.CONSUMED:CotSendFilter.Result.IGNORED,counts.process(gate,event(CotPort.FIXTURE_UID),0,method));
                assertEquals(CotSendFilter.Result.CONSUMED,counts.process(gate,event("private-real-uid"),0,method));
                assertEquals(CotSendFilter.Result.IGNORED,counts.process(gate,event("private-other-uid"),0,method));
                assertEquals(CotSendFilter.Result.IGNORED,counts.process(gate,event(null),0,method));
                assertEquals(CotSendFilter.Result.IGNORED,counts.process(gate,null,0,method));
            }
            String text=counts.text();int consumed=saved?2:1,fixtureConsumed=saved?1:0;
            assertRow(text,"柵 呼び出し",new int[]{5,5,5,5});assertRow(text,"柵 CONSUMED",new int[]{consumed,consumed,consumed,consumed});
            assertRow(text,"柵 呼び出し（架空）",new int[]{1,1,1,1});assertRow(text,"柵 CONSUMED（架空）",new int[]{fixtureConsumed,fixtureConsumed,fixtureConsumed,fixtureConsumed});
            for(String value:new String[]{CotPort.FIXTURE_UID,"private-real-uid","private-other-uid"})assertFalse(text.contains(value));
        }
    }
    @Test public void aUidGetterFailureKeepsTheOriginalFailClosedResultAndSingleRead() {
        for(int method=0;method<4;method++){
            var counts=new CotFixtureDiagnostics(true);var gate=gate(false);var reads=new AtomicInteger();
            var faulty=new CotSendFilter.Event(){
                public String uid(){if(reads.incrementAndGet()==1)throw new IllegalStateException("private uid failure");return "private-other-uid";}
                public boolean deletion(){throw new AssertionError();}public int linkCount(){throw new AssertionError();}public String linkUid(int n){throw new AssertionError();}
            };
            assertEquals(CotSendFilter.Result.CONSUMED,counts.process(gate,faulty,0,method));
            assertEquals(1,reads.get());assertTrue(gate.failed());assertEquals(1,gate.consumed());
            var reference=gate(false);
            assertEquals(CotSendFilter.Result.CONSUMED,CotSendFilter.process(reference,new CotSendFilter.Event(){
                public String uid(){throw new IllegalStateException("private uid failure");}public boolean deletion(){throw new AssertionError();}
                public int linkCount(){throw new AssertionError();}public String linkUid(int n){throw new AssertionError();}
            },0));
            assertEquals(reference.failed(),gate.failed());assertEquals(reference.consumed(),gate.consumed());
            assertRow(counts.text(),"柵 呼び出し（架空）",new int[4]);assertRow(counts.text(),"柵 CONSUMED（架空）",new int[4]);
            int[] one=new int[4];one[method]=1;assertRow(counts.text(),"柵 CONSUMED",one);
            assertFalse(counts.text().contains("private"));
        }
    }
    @Test public void diagnosticsDoNotAddASecondUidReadOrChangeIgnoredIntoConsumed() {
        var counts=new CotFixtureDiagnostics(true);var reads=new AtomicInteger();
        var once=new CotSendFilter.Event(){
            public String uid(){if(reads.incrementAndGet()>1)throw new IllegalStateException("second read");return CotPort.FIXTURE_UID;}
            public boolean deletion(){return false;}public int linkCount(){throw new AssertionError();}public String linkUid(int n){throw new AssertionError();}
        };
        var gate=gate(false);assertEquals(CotSendFilter.Result.IGNORED,counts.process(gate,once,0,2));
        assertEquals(1,reads.get());assertFalse(gate.failed());assertRow(counts.text(),"柵 呼び出し（架空）",new int[]{0,0,1,0});
        assertRow(counts.text(),"柵 CONSUMED（架空）",new int[4]);
    }
    @Test public void deletionTargetsAreForwardedButDoNotMakeAnotherUidAFixture() {
        var counts=new CotFixtureDiagnostics(true);var gate=gate(true);
        var deletion=new CotSendFilter.Event(){
            public String uid(){return "private-delete-uid";}public boolean deletion(){return true;}public int linkCount(){return 1;}
            public String linkUid(int n){assertEquals(0,n);return CotPort.FIXTURE_UID;}
        };
        assertEquals(CotSendFilter.Result.CONSUMED,counts.process(gate,deletion,0,0));
        assertRow(counts.text(),"柵 CONSUMED",new int[]{1,0,0,0});assertRow(counts.text(),"柵 CONSUMED（架空）",new int[4]);
        assertRow(counts.text(),"柵 呼び出し（架空）",new int[4]);
    }
    @Test public void fixtureUidStillCountsWhenLaterInspectionFailsClosed() {
        var counts=new CotFixtureDiagnostics(true);var faulty=new CotSendFilter.Event(){
            public String uid(){return CotPort.FIXTURE_UID;}public boolean deletion(){throw new IllegalStateException("private type failure");}
            public int linkCount(){throw new AssertionError();}public String linkUid(int n){throw new AssertionError();}
        };
        assertEquals(CotSendFilter.Result.CONSUMED,counts.process(gate(false),faulty,0,1));
        assertRow(counts.text(),"柵 呼び出し（架空）",new int[]{0,1,0,0});assertRow(counts.text(),"柵 CONSUMED（架空）",new int[]{0,1,0,0});
        assertFalse(counts.text().contains("private"));
    }
}
