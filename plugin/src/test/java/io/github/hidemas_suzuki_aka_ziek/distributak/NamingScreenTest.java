// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class NamingScreenTest {
    @Test public void directionalControlReturnsToInputWithoutSaveConfirmation()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            p.a.controller.confirmManagement(reconnect(p));p.a.drain();Object input=p.a.ui.input;
            p.a.ui.confirmation=null;long before=UnknownOnlineTest.group(p.a).saveSeq;
            p.a.controller.setLabel(input,label()+"\u2066");p.a.drain();
            assertNull(p.a.ui.confirmation);assertSame(input,p.a.ui.input);
            assertEquals(before,UnknownOnlineTest.group(p.a).saveSeq);
            assertTrue(p.a.ui.last.text.contains("文字の向きを変える文字"));
        }
    }
    static String label(){return UUID.randomUUID().toString().replace("-","").substring(0,12);}
    /**
     * 2 つのノードの仮の時計を、別々の歩幅（100 ms と 137 ms）で進めながら待つ。
     * 同じ歩幅だと、両側の 5 秒の再送と最初のパケットの送信が毎回重なり、
     * 負荷の高い全体実行で握手が終わらないまま 90 秒の試行の予算が切れることがある（DTAK-28）。
     * <p>
     * Waits while advancing the two nodes' fake clocks with different step sizes (100 ms and 137 ms).
     * With equal steps, both sides' 5-second retries and first-packet sends coincide every time,
     * and under a heavily loaded full run the 90-second attempt budget can expire before the handshake completes (DTAK-28).
     */
    static void untilStaggered(LanControllerHarness.Check check,LanControllerHarness a,LanControllerHarness m)throws Exception{
        long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(8);
        while(!check.ok()){
            a.offset.addAndGet(100_000_000L);a.tick();m.offset.addAndGet(137_000_000L);m.tick();
            if(System.nanoTime()>end)throw new AssertionError("renewal condition timed out");
            Thread.sleep(5);
        }
        a.drain();m.drain();
    }
    static Object reconnect(UnknownOnlineTest.Pair p)throws Exception{
        p.a.controller.namePeer(p.a.controller.ticket());p.a.drain();assertNotNull(p.a.ui.naming);
        assertNull(p.a.ui.confirmation);p.a.tick();assertNull(p.a.ui.confirmation);
        byte[] memberId=UnknownOnlineTest.group(p.m).id();
        p.m.controller.disconnect();p.m.drain();
        // 受信処理と競合せず、進行中の握手も閉じて通信喪失を1回観測する。
        // Close in-flight handshakes as well, observing connection loss once without racing the receiver.
        var sessions=(io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManager)LanControllerHarness.field(p.a.controller,"managedSessions");
        synchronized(LanControllerHarness.field(p.a.endpoint(),"lock")){
            synchronized(sessions){
                for(Object peer:((Map<?,?>)LanControllerHarness.field(sessions,"peers")).values()){
                    for(String name:List.of("active","candidate","pending")){
                        var field=peer.getClass().getDeclaredField(name);field.setAccessible(true);
                        Object connection=field.get(peer);if(connection!=null)((AutoCloseable)connection).close();field.set(peer,null);
                    }
                }
                assertNull(sessions.verifiedSession(memberId));
            }
            p.a.tick();assertNull(p.a.ui.confirmation);
        }
        p.m.controller.connect();p.m.drain();
        try{untilStaggered(()->p.a.ui.confirmation!=null,p.a,p.m);}
        catch(AssertionError failure){
            var dht=(LanDht)LanControllerHarness.field(p.a.controller,"dht");
            throw new AssertionError("名前の確認を待てませんでした。確認待ち="+(LanControllerHarness.field(p.a.controller,"managementPending")!=null)
                    +"、保持役="+(dht!=null&&dht.active())+"、接続="+(p.a.endpoint()!=null&&p.a.endpoint().isEstablished(memberId)));
        }
        return p.a.ui.confirmation;
    }
    @Test public void namingNeedsReconnectAndSeparateSaveConfirmation()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            Object token=reconnect(p);p.a.controller.confirmManagement(token);p.a.drain();assertNotNull(p.a.ui.input);
            String label=label();long version=UnknownOnlineTest.group(p.a).keyVersion;
            p.a.controller.setLabel(p.a.ui.input,label);p.a.drain();assertNotNull(p.a.ui.confirmation);
            assertTrue(UnknownOnlineTest.group(p.a).management.aliases.isEmpty());
            token=p.a.ui.confirmation;p.a.controller.confirmManagement(token);p.a.drain();
            try(var restored=p.a.disk.load(p.wall)){assertTrue(restored.management.aliases.containsValue(label));assertEquals(version,restored.keyVersion);}
            p.a.controller.confirmManagement(token);p.a.drain();
            assertFalse(String.join("",p.a.logs).contains(label));assertFalse(p.a.ui.last.text.contains(label));
            assertTrue(UnknownOnlineTest.group(p.m).management.aliases.isEmpty());
        }
    }
    @Test public void cancelledInputDoesNotSave()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            p.a.controller.confirmManagement(reconnect(p));p.a.drain();Object token=p.a.ui.input;
            p.a.controller.cancelManagement();p.a.drain();p.a.controller.setLabel(token,label());p.a.drain();
            assertTrue(UnknownOnlineTest.group(p.a).management.aliases.isEmpty());
        }
    }
    @Test public void failedLabelSaveKeepsPreviousMap()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            p.a.controller.confirmManagement(reconnect(p));p.a.drain();p.a.controller.setLabel(p.a.ui.input,label());p.a.drain();
            p.a.disk.failSave=true;p.a.controller.confirmManagement(p.a.ui.confirmation);p.a.drain();
            assertTrue(UnknownOnlineTest.group(p.a).management.aliases.isEmpty());assertNotNull(p.a.endpoint());
        }
    }
    @Test public void failureAfterLabelSaveStopsWithoutCompensation()throws Exception{
        try(var p=new UnknownOnlineTest.Pair()){
            p.a.controller.confirmManagement(reconnect(p));p.a.drain();String label=label();
            p.a.controller.setLabel(p.a.ui.input,label);p.a.drain();
            p.a.disk.afterDirectory=()->{throw new IllegalStateException("保存後に中断しました");};
            p.a.controller.confirmManagement(p.a.ui.confirmation);p.a.drain();
            assertTrue((boolean)LanControllerHarness.field(p.a.controller,"committedNotApplied"));assertNull(p.a.endpoint());
            try(var saved=p.a.disk.load(p.wall)){assertTrue(saved.management.aliases.containsValue(label));}
        }
    }
}
