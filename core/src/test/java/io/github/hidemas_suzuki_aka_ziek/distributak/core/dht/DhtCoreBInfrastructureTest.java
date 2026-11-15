// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtRoutingTableTest.*;
import static org.junit.jupiter.api.Assertions.*;

class DhtCoreBInfrastructureTest {
    @Test void everyMutatorRejectsReentryFromSendOrVerification() {
        for(boolean receiving:new boolean[]{false,true})for(int operation=0;operation<5;operation++) {
            var callback=new AtomicReference<Runnable>();var token=new AtomicLong();
            DhtTransport transport=(destination,request)->{token.set(request.id());if(!receiving&&callback.get()!=null)callback.get().run();return true;};
            var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),()->0L,transport,(key,record,clock)->{
                if(receiving&&callback.get()!=null)callback.get().run();return 1;
            },Integer::compare);
            int selected=operation;
            Runnable mutate=()->{switch(selected) {
                case 0 -> node.findNode(DhtIdTest.id(2));case 1 -> node.findValue(DhtIdTest.id(2));
                case 2 -> node.networkChanged();case 3 -> node.observe(peer(2));case 4 -> node.refreshDue();
                default -> throw new AssertionError();
            }};
            node.observe(peer(1));var lookup=node.findValue(DhtIdTest.id(1));
            if(receiving)node.poll();
            callback.set(()->assertEquals("DHTの処理を重ねて呼べません",assertThrows(IllegalStateException.class,mutate::run).getMessage()));
            if(receiving)node.receive(peer(1),token.get(),List.of(),new byte[]{1});else node.poll();
            callback.set(null);assertDoesNotThrow(node::poll);assertEquals(1,node.routing().size());
            if(receiving)assertTrue(lookup.done());
        }
    }
    @Test void readingTheActiveCountDoesNotCancelLookupsInsideSend() {
        var nanos=new AtomicLong(10);var reference=new AtomicReference<DhtNode<Integer>>();
        var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),nanos::get,(destination,request)->{
            nanos.set(5);assertEquals(1,reference.get().activeLookups());return true;
        },(key,record,clock)->1,Integer::compare);reference.set(node);
        node.observe(peer(1));var lookup=node.findValue(DhtIdTest.id(1));assertDoesNotThrow(node::poll);
        assertFalse(lookup.done());node.poll();assertEquals(DhtNode.Stop.CLOCK_RESET,lookup.result().stop());
    }
    @Test void farAwayWaitingPeerSurvivesAnOverflowOfCloserIntroductions() {
        var f=new DhtNodeTest.Fixture();f.seed(1000,1001);var lookup=f.node.findNode(DhtIdTest.id(0));f.node.poll();
        var first=f.delivery.take();var waiting=f.delivery.take();
        List<Contact> closer=new ArrayList<>();for(int n=1;n<=300;n++)closer.add(contact(n));
        f.reply(first,closer,null);f.reply(waiting,List.of(),null);DhtNodeReviewTest.complete(f,lookup);
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(256,lookup.result().candidates());
        assertEquals(22,lookup.result().queried());assertEquals(22,lookup.result().responded());
    }
    @Test void sendRuntimeFailuresHaveTheSameMeaningAsFalseForQueriesAndPings() {
        for(boolean ping:new boolean[]{false,true})for(boolean retry:new boolean[]{false,true}) {
            var nanos=new AtomicLong();var attempts=new AtomicLong();
            var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),nanos::get,(destination,request)->{
                if(retry&&attempts.getAndIncrement()==0)return true;throw new IllegalStateException("Test send failure");
            },(key,record,clock)->1,Integer::compare);
            if(ping)for(int n=128;n<=148;n++)node.observe(peer(n));else node.observe(peer(1));
            var lookup=ping?null:node.findNode(DhtIdTest.id(7));assertDoesNotThrow(node::poll);
            if(retry){nanos.set(DhtLimits.RPC_NANOS);assertDoesNotThrow(node::poll);}
            if(ping) {
                assertEquals(20,node.routing().size());assertEquals(0,node.routing().pendingCount());
                assertEquals(DhtIdTest.id(128),node.routing().bucket(7).get(0).id());
            } else {
                assertTrue(lookup.done());assertEquals(1,lookup.result().queried());assertEquals(0,lookup.result().responded());
                assertEquals(0,node.activeLookups());
            }
            nanos.set(12_000_000_000L);assertDoesNotThrow(node::poll);
        }
    }
}
