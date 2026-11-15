// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.lang.reflect.Modifier;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtRoutingTableTest.*;
import static org.junit.jupiter.api.Assertions.*;

class DhtNodeReviewTest {
    static void complete(DhtNodeTest.Fixture f,DhtNode<Integer>.Lookup lookup) {
        for(int turn=0;turn<150&&!lookup.done();turn++) {
            f.node.poll();
            while(!f.delivery.waiting.isEmpty())f.reply(f.delivery.take(),List.of(),null);
        }
        assertTrue(lookup.done());
    }
    static DhtNodeTest.Sent query(DhtNodeTest.Fixture f) {
        f.node.poll();DhtNodeTest.Sent query=null;
        while(!f.delivery.waiting.isEmpty()) {
            var sent=f.delivery.take();
            if(sent.request().operation()==DhtTransport.Operation.PING)f.reply(sent,List.of(),null);
            else {assertNull(query);query=sent;}
        }
        assertNotNull(query);return query;
    }
    @Test void aLargeRoutingTableSeedsOnlyTwentyAndContinuesAfterAnIntroduction() {
        var f=new DhtNodeTest.Fixture();
        for(int bit=8;bit<25;bit++)for(int n=0;n<16;n++) {
            byte[] bytes=new byte[32];bytes[31-bit/8]=(byte)(1<<(bit%8));bytes[31]=(byte)n;
            Contact contact=new Contact(new DhtId(bytes));f.delivery.known.add(contact.id());
            f.node.observe(AuthenticatedPeer.fromVerifiedDhtResponse(contact));
        }
        assertEquals(272,f.node.routing().size());var target=DhtIdTest.id(0);
        Set<DhtId> expected=new HashSet<>();var nearest=f.node.routing().nearest(target,20);
        for(int n=0;n<19;n++)expected.add(nearest.get(n).id());expected.add(DhtIdTest.id(1));
        var lookup=f.node.findNode(target);f.node.poll();
        f.reply(f.delivery.take(),List.of(contact(1)),null);assertFalse(lookup.done());
        while(!f.delivery.waiting.isEmpty())f.reply(f.delivery.take(),List.of(),null);
        complete(f,lookup);assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(21,lookup.result().candidates());assertEquals(20,lookup.result().queried());
        assertEquals(expected,new HashSet<>(f.delivery.sent.stream().map(sent->sent.destination().id()).toList()));
    }
    @Test void aCloserContactReplacesTheFarthestUnqueriedCandidateAtCapacity() {
        var f=new DhtNodeTest.Fixture();f.seed(1000);var lookup=f.node.findNode(DhtIdTest.id(0));f.node.poll();
        List<Contact> contacts=new ArrayList<>();for(int n=999;n>=600;n--)contacts.add(contact(n));contacts.add(contact(1));
        f.reply(f.delivery.take(),contacts,null);assertFalse(lookup.done());complete(f,lookup);
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(256,lookup.result().candidates());
        assertEquals(21,lookup.result().queried());
        assertTrue(f.delivery.sent.stream().anyMatch(sent->sent.destination().id().equals(DhtIdTest.id(1))));
        assertEquals(1,f.delivery.sent.stream().filter(sent->sent.destination().id().equals(DhtIdTest.id(1000))).count());
    }
    /** 計画 B: 期限に着いても、検証済みの値を受け取っていれば値を返す（答え 190）。 */
    @Test void deadlineReturnsAValidRecordReceivedBeforeTheDeadline() {
        var f=new DhtNodeTest.Fixture();f.seed(1,2);var lookup=f.node.findValue(DhtIdTest.id(0));f.node.poll();
        f.reply(f.delivery.take(),List.of(),new byte[]{9});assertFalse(lookup.done(),"もう 1 台の返事を待つ間は終わらない");
        f.nanos.set(DhtLimits.LOOKUP_NANOS);f.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());assertEquals(9,lookup.result().value().orElseThrow());
    }
    /** 計画 B: 最初の検証済みの値で印を立て、続きの問い合わせをしない。連絡先の列が長くても 1 回で終わる。 */
    @Test void aValidRecordEndsTheLookupAtOnceInsteadOfRunningIntoTheQueryLimit() {
        var f=new DhtNodeTest.Fixture();f.seed(1000);var lookup=f.node.findValue(DhtIdTest.id(0));
        f.reply(query(f),List.of(contact(999)),new byte[]{9});
        assertTrue(lookup.done(),"返信を受けた時点で終わる");
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(1,lookup.result().queried());
        assertEquals(1,lookup.result().candidates(),"値つきの返信の連絡先は候補に入れない");
        assertEquals(9,lookup.result().value().orElseThrow());
    }
    /** 値の無い返信が続いて問い合わせの上限に着いたときは、値が無いまま QUERY_LIMIT で終わる。 */
    @Test void queryLimitWithoutAnyRecordStillStopsWithoutAValue() {
        var f=new DhtNodeTest.Fixture();f.seed(1000);var lookup=f.node.findValue(DhtIdTest.id(0));
        for(int n=0;n<128;n++)f.reply(query(f),List.of(contact(999-n)),null);
        f.node.poll();assertEquals(DhtNode.Stop.QUERY_LIMIT,lookup.result().stop());assertTrue(lookup.result().value().isEmpty());
    }
    /** 上限ちょうどの最後の問い合わせで値が来ても、値を返して終わる。 */
    @Test void exactlyTheLastAllowedQueryCanCompleteAndReturnAValue() {
        var f=new DhtNodeTest.Fixture();f.seed(1000);var lookup=f.node.findValue(DhtIdTest.id(0));
        for(int n=0;n<128;n++)f.reply(query(f),List.of(contact(999-n)),n==127?new byte[]{9}:null);
        f.node.poll();assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(128,lookup.result().queried());assertEquals(9,lookup.result().value().orElseThrow());
    }
    @Test void clockResetAndNetworkChangeAlsoDiscardAnAlreadyReceivedRecord() {
        for(boolean reset:new boolean[]{false,true}) {
            var f=new DhtNodeTest.Fixture();f.nanos.set(10);f.seed(1,2);var lookup=f.node.findValue(DhtIdTest.id(0));f.node.poll();
            f.reply(f.delivery.take(),List.of(),new byte[]{9});
            if(reset){f.nanos.set(5);f.node.poll();}else f.node.networkChanged();
            assertEquals(reset?DhtNode.Stop.CLOCK_RESET:DhtNode.Stop.NETWORK_CHANGED,lookup.result().stop());
            assertTrue(lookup.result().value().isEmpty());
        }
    }
    @Test void unexpectedVerifierExceptionsRejectRecordsAndDoNotBlockOtherLookups() {
        var delivery=new DhtNodeTest.Delivery();delivery.known.add(DhtIdTest.id(1));
        var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),()->0L,delivery,
                (key,record,clock)->{throw new IndexOutOfBoundsException("Test failure");},Integer::compare);
        node.observe(peer(1));var value=node.findValue(DhtIdTest.id(0));var other=node.findNode(DhtIdTest.id(2));node.poll();
        while(!delivery.waiting.isEmpty()) {
            var sent=delivery.take();assertDoesNotThrow(()->node.receive(peer(1),sent.request().id(),List.of(),new byte[]{9}));
        }
        assertDoesNotThrow(node::poll);assertTrue(value.done());assertTrue(value.result().value().isEmpty());
        assertTrue(other.done());assertEquals(0,node.activeLookups());
    }
    @Test void verifierRuntimeFailureDuringFinalRecheckStillReleasesTheLookupSlot() {
        var delivery=new DhtNodeTest.Delivery();delivery.known.add(DhtIdTest.id(1));var calls=new java.util.concurrent.atomic.AtomicInteger();
        var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),()->0L,delivery,(key,record,clock)->{
            if(calls.incrementAndGet()>1)throw new IllegalStateException("Test failure");return 9;
        },Integer::compare);
        node.observe(peer(1));var lookup=node.findValue(DhtIdTest.id(0));node.poll();
        /* 計画 B では受信の検査（1 回目）で印を立て、終わりの再検査（2 回目）で例外になる。 */
        assertDoesNotThrow(()->node.receive(peer(1),delivery.take().request().id(),List.of(),new byte[]{9}));
        assertEquals(2,calls.get());assertTrue(lookup.done());assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertTrue(lookup.result().value().isEmpty());assertEquals(0,node.activeLookups());
    }
    @Test void comparatorRuntimeFailureRejectsTheCandidateWithoutBlockingCompletion() {
        var delivery=new DhtNodeTest.Delivery();delivery.introduce(List.of(contact(1),contact(2)));
        var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),()->0L,delivery,(key,record,clock)->(int)record[0],(a,b)->{
            if(a==9)throw new UnsupportedOperationException("Test failure");return Integer.compare(a,b);
        });
        node.observe(peer(1));node.observe(peer(2));var lookup=node.findValue(DhtIdTest.id(0));node.poll();
        var first=delivery.take();node.receive(peer(1),first.request().id(),List.of(),new byte[]{3});
        node.receive(peer(2),delivery.take().request().id(),List.of(),new byte[]{9});
        assertDoesNotThrow(node::poll);assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(3,lookup.result().value().orElseThrow());
    }
    @Test void localPingSendFailureKeepsTheIncumbentAndDiscardsTheReplacement() {
        for(boolean retry:new boolean[]{false,true}) {
            var nanos=new AtomicLong();var sends=new AtomicLong();
            var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),nanos::get,
                    (destination,request)->retry&&sends.getAndIncrement()==0,(key,record,clock)->null,Integer::compare);
            for(int n=128;n<=148;n++)node.observe(peer(n));node.poll();
            if(retry){nanos.set(DhtLimits.RPC_NANOS);node.poll();}
            assertEquals(0,node.routing().pendingCount());assertEquals(DhtIdTest.id(128),node.routing().bucket(7).get(0).id());
            nanos.set(10*DhtLimits.RPC_NANOS);node.poll();
            assertEquals(20,node.routing().size());assertTrue(node.routing().bucket(7).stream().noneMatch(p->p.id().equals(DhtIdTest.id(148))));
        }
    }
    @Test void authenticatedDuplicateAndCompletedRepliesKeepThePeerAlive() {
        var f=new DhtNodeTest.Fixture();for(int n=128;n<148;n++)f.seed(n);
        var lookup=f.node.findNode(DhtIdTest.id(128));f.node.poll();var duplicate=f.delivery.take();
        assertEquals(DhtIdTest.id(128),duplicate.destination().id());f.reply(duplicate,List.of(),null);
        f.seed(148);f.node.poll(); // 新しいPINGは現在の先頭129へ。
        while(!f.delivery.waiting.isEmpty())f.reply(f.delivery.take(),List.of(),null);
        complete(f,lookup);f.seed(149);f.node.poll();var oldest=f.node.routing().bucket(7).get(0).id();
        f.node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(oldest)),Long.MAX_VALUE,List.of(),null);
        assertEquals(0,f.node.routing().pendingCount());assertEquals(oldest,f.node.routing().bucket(7).get(19).id());
        f.reply(duplicate,List.of(),null);assertEquals(DhtIdTest.id(128),f.node.routing().bucket(7).get(19).id());
    }
    @Test void aPongAfterSixSecondsStillKeepsTheAuthenticatedIncumbent() {
        var f=new DhtNodeTest.Fixture();for(int n=128;n<=148;n++)f.seed(n);f.node.poll();var pong=f.delivery.take();
        f.nanos.set(2*DhtLimits.RPC_NANOS+1);f.reply(pong,List.of(),null);
        assertEquals(DhtIdTest.id(128),f.node.routing().bucket(7).get(19).id());assertEquals(0,f.node.routing().pendingCount());
        f.node.poll();assertEquals(1,f.delivery.sent.size());
    }
    @Test void oldNetworkRepliesAreDiscardedButLateRepliesFromTheNewNetworkUpdateRouting() {
        var f=new DhtNodeTest.Fixture();f.seed(128);f.node.findNode(DhtIdTest.id(0));f.node.poll();var old=f.delivery.take();
        f.node.networkChanged();f.reply(old,List.of(),null);assertEquals(0,f.node.routing().size());
        f.seed(1);var lookup=f.node.findNode(DhtIdTest.id(0));f.node.poll();var first=f.delivery.take();
        assertTrue(first.request().id()>old.request().id());f.reply(first,List.of(contact(2)),null);f.node.poll();
        var newer=f.delivery.take();assertEquals(DhtIdTest.id(2),newer.destination().id());
        assertTrue(f.node.routing().nearest(DhtIdTest.id(2),20).stream().noneMatch(p->p.id().equals(DhtIdTest.id(2))));
        f.nanos.set(2*DhtLimits.RPC_NANOS+1);f.node.poll();assertTrue(lookup.done());
        f.reply(newer,List.of(),null);
        assertTrue(f.node.routing().nearest(DhtIdTest.id(2),20).stream().anyMatch(p->p.id().equals(DhtIdTest.id(2))));
    }
    @Test void requestSequenceDoesNotWrapAcrossTheNetworkBoundary() throws Exception {
        var f=new DhtNodeTest.Fixture();var sequence=DhtNode.class.getDeclaredField("sequence");sequence.setAccessible(true);
        sequence.setLong(f.node,Long.MAX_VALUE-1);f.seed(1);f.node.findNode(DhtIdTest.id(0));f.node.poll();
        var old=f.delivery.take();assertEquals(Long.MAX_VALUE,old.request().id());
        f.node.networkChanged();f.reply(old,List.of(),null);assertEquals(0,f.node.routing().size());
        f.seed(1);f.node.findNode(DhtIdTest.id(0));
        assertEquals("DHTの要求の番号が上限に達しています",assertThrows(IllegalStateException.class,f.node::poll).getMessage());
        assertEquals("DHTの要求の番号が上限に達しています",assertThrows(IllegalStateException.class,f.node::poll).getMessage());
        assertTrue(f.delivery.waiting.isEmpty());
    }
    @Test void routingTableCannotBeClearedThroughItsPublicApi() throws Exception {
        assertFalse(Modifier.isPublic(DhtRoutingTable.class.getDeclaredMethod("clear").getModifiers()));
    }
    @Test void nestedPollAndReceiveAreRejectedWithAFixedMessageAndTheGuardIsReleased() {
        for(boolean outerReceive:new boolean[]{false,true})for(boolean innerReceive:new boolean[]{false,true}) {
            var callback=new AtomicReference<Runnable>();var nodeRef=new AtomicReference<DhtNode<Integer>>();
            var requestId=new AtomicLong();
            DhtTransport transport=(destination,request)->{
                requestId.set(request.id());if(!outerReceive&&callback.get()!=null)callback.get().run();return true;
            };
            var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),()->0L,transport,(key,record,clock)->{
                if(callback.get()!=null)callback.get().run();return 9;
            },Integer::compare);nodeRef.set(node);node.observe(peer(1));var lookup=node.findValue(DhtIdTest.id(0));
            Runnable inner=()->{if(innerReceive)nodeRef.get().receive(peer(1),requestId.get(),List.of(),null);else nodeRef.get().poll();};
            if(outerReceive) {
                node.poll();callback.set(()->assertEquals("DHTの処理を重ねて呼べません",assertThrows(IllegalStateException.class,inner::run).getMessage()));
                node.receive(peer(1),requestId.get(),List.of(),new byte[]{9});callback.set(null);node.poll();assertTrue(lookup.done());
            } else {
                callback.set(()->{
                    var failure=assertThrows(IllegalStateException.class,inner::run);
                    assertEquals("DHTの処理を重ねて呼べません",failure.getMessage());throw failure;
                });
                assertDoesNotThrow(node::poll);assertTrue(lookup.done());
                assertEquals(1,lookup.result().queried());assertEquals(0,lookup.result().responded());
                assertEquals(1,node.routing().size());assertEquals(0,node.routing().pendingCount());assertEquals(0,node.activeLookups());
                callback.set(null);var next=node.findNode(DhtIdTest.id(1));assertDoesNotThrow(node::poll);
                assertDoesNotThrow(()->node.receive(peer(1),requestId.get(),List.of(),null));node.poll();assertTrue(next.done());
            }
        }
    }
}
