// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtLookupConnectingTest.SECOND;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtLookupConnectingTest.contacts;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtRoutingTableTest.peer;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 案 B（答え 190〜194）: 値の探索は、最初の検証済みの値で印を付け、新しい問い合わせを止め、
 * つなぎ中の相手を手放し、送った問い合わせの返事が片づいたら終える。値は全ての検証済みの値から版が一番新しいものを選ぶ。
 */
class DhtPlanBTest {
    record Val(int version,int content){}
    static byte[] bytes(int version,int content){return new byte[]{(byte)version,(byte)content};}
    static final DhtId TARGET=DhtIdTest.id(0x8000);
    static final class P {
        final AtomicLong nanos=new AtomicLong();final DhtNodeTest.Wall wall=new DhtNodeTest.Wall();
        final DhtLookupConnectingTest.Script script=new DhtLookupConnectingTest.Script();
        final Set<Integer> expired=new HashSet<>();
        int minVersion;
        int finished;
        boolean finishedThrows;
        boolean compareThrows;
        final DhtNode.Verifier<Val> verifier=new DhtNode.Verifier<>() {
            @Override public Val verify(DhtId key,byte[] encoded,Clock clock) {
                if(encoded.length!=2||encoded[0]==0||expired.contains(encoded[0]&255)||(encoded[0]&255)<minVersion) {
                    throw new SecurityException("invalid");
                }
                return new Val(encoded[0]&255,encoded[1]&255);
            }
            @Override public void finished() {
                finished++;
                if(finishedThrows) {
                    throw new IllegalStateException("script");
                }
            }
        };
        final DhtNode<Val> node=new DhtNode<>(DhtIdTest.id(0),wall,nanos::get,script,verifier,(a,b)->{
            if(compareThrows) {
                throw new IllegalStateException("script");
            }
            return Integer.compare(a.version(),b.version());
        });
        void seed(int... numbers){for(int n:numbers)node.observe(peer(n));}
        /** index 番目に送った問い合わせへ答える。 */
        void reply(int index,List<Contact> contacts,byte[] record) {
            var sent=script.sent.get(index);
            node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(sent.destination())),sent.request().id(),contacts,record);
        }
        void at(long seconds){nanos.set(seconds*SECOND);}
    }

    // A: 近い 20 件の連絡先のそばに持ち主がいなくても、遠い持ち主の値を返す。
    @Test void aValueFromAHostOutsideTheClosestTwentyIsStillReturned() {
        var p=new P();p.seed(1,2,3);var lookup=p.node.findValue(TARGET);p.node.poll();
        assertEquals(3,p.script.sent.size());
        p.reply(0,contacts(0x8010,0x8023),null);
        p.reply(1,List.of(),bytes(7,1));
        assertFalse(lookup.done());
        p.reply(2,List.of(),null);
        assertTrue(lookup.done(),"返事が片づいたらその場で終わる（poll を待たない）");
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(new Val(7,1),lookup.result().value().orElseThrow());
        assertEquals(3,lookup.result().queried());assertEquals(3,lookup.result().responded());
    }
    // B: 期限に届いても、受け取った値は捨てない（receive の道と poll の道）。
    @Test void deadlineWithAValueReturnsTheValueThroughReceive() {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(4,1));
        p.nanos.set(DhtLimits.LOOKUP_NANOS);p.reply(1,List.of(),null);
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());assertEquals(new Val(4,1),lookup.result().value().orElseThrow());
    }
    @Test void deadlineWithAValueReturnsTheValueThroughPoll() {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(4,1));assertFalse(lookup.done());
        p.nanos.set(DhtLimits.LOOKUP_NANOS);p.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());assertEquals(new Val(4,1),lookup.result().value().orElseThrow());
    }
    @Test void deadlineWithoutAValueStillHasNoValue() {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.nanos.set(DhtLimits.LOOKUP_NANOS);p.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());assertTrue(lookup.result().value().isEmpty());
    }
    // C: 届いた順がどうでも、版が一番新しい値を選ぶ。
    @Test void theNewestVersionWinsInAnyArrivalOrder() {
        int[][] orders={{2,9,4},{9,2,4},{4,2,9}};
        for(int[] order:orders) {
            var p=new P();p.seed(1,2,3);var lookup=p.node.findValue(TARGET);p.node.poll();
            for(int i=0;i<3;i++)p.reply(i,List.of(),bytes(order[i],i));
            assertTrue(lookup.done());assertEquals(9,lookup.result().value().orElseThrow().version());
        }
    }
    // D: 印のあとは新しい問い合わせを出さない。送った問い合わせの 3 秒の再送と 6 秒の失敗は残る。
    @Test void afterTheMarkNoNewQueriesAreSentButResendAndFailureStay() {
        var p=new P();p.seed(1,2,3,4,5,6,7,8);var lookup=p.node.findValue(TARGET);p.node.poll();
        assertEquals(3,p.script.sent.size());
        p.reply(0,List.of(),bytes(5,1));assertFalse(lookup.done(),"返事待ちが 2 台残る");
        int prepared=p.script.prepared.size();
        p.node.poll();
        assertEquals(3,p.script.sent.size(),"空いた α の枠に新しい問い合わせを出さない");
        assertEquals(prepared,p.script.prepared.size(),"新しい相手の準備も問い合わせない");
        p.nanos.set(DhtLimits.RPC_NANOS);p.node.poll();
        assertEquals(5,p.script.sent.size(),"待っている 2 台へ 3 秒で 1 回だけ再送");
        p.nanos.set(2*DhtLimits.RPC_NANOS);p.node.poll();
        assertTrue(lookup.done());assertEquals(5,p.script.sent.size());
        assertEquals(new Val(5,1),lookup.result().value().orElseThrow());
        assertEquals(3,lookup.result().queried());assertEquals(1,lookup.result().responded());
    }
    // E: 黙ったままの相手は 6 秒で失敗にし、あとで来た値は使わない。
    @Test void aSilentWaitingPeerFailsAtSixSecondsAndALateValueIsNotUsed() {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(3,1));
        p.at(3);p.node.poll();assertEquals(3,p.script.sent.size());assertFalse(lookup.done());
        p.at(6);p.node.poll();
        assertTrue(lookup.done());assertEquals(new Val(3,1),lookup.result().value().orElseThrow());
        p.reply(1,List.of(),bytes(9,9));
        assertEquals(new Val(3,1),lookup.result().value().orElseThrow());
        assertEquals(2,lookup.result().queried());assertEquals(1,lookup.result().responded());
    }
    // F・M: つなぎ中の相手を手放す。握手そのものは閉じず、数も合う。
    @Test void theMarkReleasesConnectingPeersWithoutClosingTheirHandshakeAndTheCountsAdd() {
        var p=new P();p.script.set(3,DhtTransport.Readiness.CONNECTING);
        p.seed(1,2,3,4);var lookup=p.node.findValue(TARGET);p.node.poll();
        assertEquals(2,p.script.sent.size());
        assertTrue(p.node.isReferenced(DhtIdTest.id(3)));assertEquals(0,p.node.connectingReleased());
        int prepared=p.script.prepared.size();
        p.reply(0,List.of(),bytes(6,1));
        assertFalse(lookup.done(),"返事待ちが 1 台残る");
        assertEquals(1,p.node.connectingReleased());
        assertFalse(p.node.isReferenced(DhtIdTest.id(3)),"手放した相手は探索の参照に数えない");
        assertTrue(p.node.isReferenced(DhtIdTest.id(2)));
        assertEquals(prepared,p.script.prepared.size(),"握手の試みを閉じる問い合わせはしない");
        p.reply(1,List.of(),null);
        assertTrue(lookup.done());assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(3,lookup.result().queried(),"queried は変えない");assertEquals(2,lookup.result().responded());
        assertEquals(1,p.node.connectingReleased(),"数えるのは 1 回だけ。失敗にも時間切れにも入れない");
        assertEquals(0,p.node.connectingTimedOut());assertEquals(0,p.node.unavailableFailed());
        assertEquals(lookup.result().queried(),lookup.result().responded()+p.node.connectingReleased());
    }
    @Test void aLookupWithOnlyConnectingPeersLeftFinishesAtTheMark() {
        var p=new P();p.script.set(2,DhtTransport.Readiness.CONNECTING);p.script.set(3,DhtTransport.Readiness.CONNECTING);
        p.seed(1,2,3);var lookup=p.node.findValue(TARGET);p.node.poll();
        assertEquals(1,p.script.sent.size());
        p.reply(0,List.of(),bytes(6,1));
        assertTrue(lookup.done(),"返事待ちが 0 なら、つなぎ中が残っていても終わる");
        assertEquals(new Val(6,1),lookup.result().value().orElseThrow());assertEquals(2,p.node.connectingReleased());
        assertFalse(p.node.isReferenced(DhtIdTest.id(2)));assertFalse(p.node.isReferenced(DhtIdTest.id(3)));
    }
    // G: 同じ版で中身が違うときは最初に受けたほうを残す。保存済みより古い版は値として扱わない。
    @Test void sameVersionDifferentContentKeepsTheFirstReceived() {
        for(boolean reverse:new boolean[]{false,true}) {
            var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
            int first=reverse?1:0,second=reverse?0:1;
            p.reply(first,List.of(),bytes(5,1));p.reply(second,List.of(),bytes(5,2));
            assertEquals(1,lookup.result().value().orElseThrow().content());
        }
    }
    @Test void aValueOlderThanTheStoredVersionIsNotAValueAndDoesNotMarkTheLookup() {
        var p=new P();p.minVersion=3;p.seed(1,2,3,4);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(2,1));
        p.node.poll();assertEquals(4,p.script.sent.size(),"印が付いていないので、次の問い合わせを出す");
        p.reply(1,List.of(),null);p.reply(2,List.of(),null);p.reply(3,List.of(),null);
        p.node.poll();
        assertTrue(lookup.result().value().isEmpty());assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
    }
    // H: 一番新しい値が終わりの再検査に落ちたら、次に新しい値。全部落ちたら値なし。
    @Test void aNewestValueThatFailsTheFinalRecheckFallsBackToTheNextNewest() {
        var p=new P();p.seed(1,2,3);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(2,1));p.reply(1,List.of(),bytes(9,1));
        p.expired.add(9);p.reply(2,List.of(),null);
        assertEquals(new Val(2,1),lookup.result().value().orElseThrow());
    }
    @Test void ifEveryValueFailsTheFinalRecheckThereIsNoValue() {
        var p=new P();p.seed(1,2,3);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(2,1));p.reply(1,List.of(),bytes(9,1));
        p.expired.add(2);p.expired.add(9);p.reply(2,List.of(),null);
        assertTrue(lookup.done());assertTrue(lookup.result().value().isEmpty());
    }
    // I: 時計の巻き戻しとネットワークの変化は、受け取った値も捨てる。
    @Test void clockResetAndNetworkChangeGiveNoValueEvenAfterAMark() {
        for(boolean network:new boolean[]{false,true}) {
            var p=new P();p.at(10);p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
            p.reply(0,List.of(),bytes(5,1));assertFalse(lookup.done());
            if(network) {
                p.node.networkChanged();
            } else {
                p.at(5);
                p.node.poll();
            }
            assertEquals(network?DhtNode.Stop.NETWORK_CHANGED:DhtNode.Stop.CLOCK_RESET,lookup.result().stop());
            assertTrue(lookup.result().value().isEmpty());assertTrue(lookup.result().closest().isEmpty());
        }
    }
    // J・R1: poll を挟まなくても終わり、終わりの処理は 1 回だけ。
    @Test void finishingThroughReceiveRunsTheEndOnceAndFreesTheLookup() {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(5,1));p.reply(1,List.of(),null);
        assertTrue(lookup.done());assertEquals(1,p.finished);assertEquals(0,p.node.activeLookups());
        p.node.poll();p.at(500);p.node.poll();assertEquals(1,p.finished);
    }
    // K: 早く終わると 4 本の枠が 1 つ空く。
    @Test void anEarlyFinishFreesOneOfTheFourLookupSlots() {
        var p=new P();p.seed(1,2);
        List<DhtNode<Val>.Lookup> lookups=new ArrayList<>();
        for(int i=0;i<4;i++)lookups.add(p.node.findValue(DhtIdTest.id(0x8000+i)));
        assertThrows(IllegalStateException.class,()->p.node.findValue(DhtIdTest.id(0x9000)));
        p.node.poll();
        var key=DhtIdTest.id(0x8000);
        for(int i=0;i<p.script.sent.size();i++) {
            if(p.script.sent.get(i).request().target().equals(key)) {
                p.reply(i,List.of(),bytes(5,i));
            }
        }
        assertTrue(lookups.get(0).done());assertEquals(3,p.node.activeLookups());
        assertDoesNotThrow(()->p.node.findValue(DhtIdTest.id(0x9000)));
    }
    // N: 診断の文字列に値・数字・鍵を出さない。
    @Test void diagnosticStringsShowNoValueNumberOrKey() {
        var p=new P();p.seed(1);var lookup=p.node.findValue(TARGET);p.node.poll();p.reply(0,List.of(),bytes(77,88));
        assertEquals("DHT lookup",lookup.toString());assertEquals("DHT lookup result",lookup.result().toString());
        assertEquals("DHT node",p.node.toString());
    }
    // O: FIND_NODE は値つきの返事で変わらない。連絡先は足し、印も付けず、手放しもしない。
    @Test void findNodeIsNotChangedByAValueCarryingReply() {
        var p=new P();
        p.script.set(3,DhtTransport.Readiness.CONNECTING);
        p.seed(1,2,3);
        var lookup=p.node.findNode(TARGET);
        p.node.poll();
        assertEquals(2,p.script.sent.size());
        p.reply(0,contacts(0x8010,0x8012),bytes(5,1));
        assertFalse(lookup.done());
        assertEquals(0,p.node.connectingReleased());
        assertTrue(p.node.isReferenced(DhtIdTest.id(3)));
        p.node.poll();
        assertTrue(p.script.sent.size()>2,"連絡先を足して問い合わせを続ける");
    }
    // P: 値のある返事の連絡先は候補に足さない。
    @Test void contactsInAReplyThatCarriedAValueAreNotAddedAsCandidates() {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,contacts(0x8010,0x8014),bytes(5,1));p.reply(1,List.of(),null);
        assertTrue(lookup.done());assertEquals(2,lookup.result().candidates());assertEquals(2,p.script.sent.size());
    }
    // Q: 検査に落ちた値は印にならず、探索は最後まで続けて値なしで終わる。
    @Test void aValueThatFailsVerificationDoesNotMarkTheLookup() {
        var p=new P();p.seed(1,2,3,4,5);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),new byte[]{0,1});
        p.node.poll();assertEquals(4,p.script.sent.size(),"印が付いていないので次を出す");
        p.reply(1,List.of(),null);p.reply(2,List.of(),null);p.reply(3,List.of(),null);
        assertFalse(lookup.done(),"印の無い探索は poll で終わる");
        p.node.poll();
        assertEquals(5,p.script.sent.size(),"最後の 1 台にも問い合わせる");
        p.reply(4,List.of(),null);
        p.node.poll();
        assertTrue(lookup.done());assertTrue(lookup.result().value().isEmpty());
    }
    // R2: receive の道で終わっても、検査器と比較の参照は外れる。
    @Test void finishingThroughReceiveReleasesTheVerifierAndComparator() throws Exception {
        var p=new P();p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(5,1));p.reply(1,List.of(),null);
        assertTrue(lookup.done());DiscoveryLookupIntegrationTest.released(lookup);
    }
    // R3: 終わりの処理の例外は、探索を止めず枠も空ける。
    @Test void exceptionsInTheEndOfALookupThroughReceiveDoNotStallIt() {
        var p=new P();p.finishedThrows=true;p.compareThrows=true;p.seed(1,2);var lookup=p.node.findValue(TARGET);p.node.poll();
        p.reply(0,List.of(),bytes(2,1));
        assertDoesNotThrow(()->p.reply(1,List.of(),bytes(3,1)));
        assertTrue(lookup.done());assertEquals(0,p.node.activeLookups());
        assertEquals(2,lookup.result().value().orElseThrow().version(),"比較できなければ最初に検証した値を残す");
        assertDoesNotThrow(()->p.node.findValue(TARGET));
    }
    // R4: 検査器の中から DHT の口を重ねて呼べない（receive の道。2 台の形）。
    @Test void reentryFromTheVerifierInsideReceiveIsRejectedWithTwoHosts() {
        var holder=new java.util.concurrent.atomic.AtomicReference<DhtNode<Integer>>();
        var errors=new ArrayList<RuntimeException>();
        var script=new DhtLookupConnectingTest.Script();
        var nanos=new AtomicLong();
        var node=new DhtNode<Integer>(DhtIdTest.id(0),new DhtNodeTest.Wall(),nanos::get,script,(key,record,clock)->{
            try{holder.get().poll();}catch(IllegalStateException nested){errors.add(nested);}
            try{holder.get().findValue(TARGET);}catch(IllegalStateException nested){errors.add(nested);}
            return record[0]&255;
        },Integer::compare);
        holder.set(node);
        node.observe(peer(1));
        node.observe(peer(2));
        var lookup=node.findValue(TARGET);
        node.poll();
        for(int i=0;i<2;i++) {
            var sent=script.sent.get(i);
            node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(sent.destination())),sent.request().id(),List.of(),new byte[]{(byte)(5+i)});
        }
        assertTrue(errors.size()>=4,"受信の検査と終わりの再検査のどちらでも重ねて呼べない");
        for(var error:errors) {
            assertEquals("DHTの処理を重ねて呼べません",error.getMessage());
        }
        assertTrue(lookup.done());
        assertEquals(6,lookup.result().value().orElseThrow());
    }
    // 追加: 同じ探索の別の相手が値を持つ返事でも、印は探索ごと。他の探索の相手の参照は残る。
    @Test void aPeerStillReferencedByAnotherLookupStaysReferencedAfterTheRelease() {
        var p=new P();p.script.set(2,DhtTransport.Readiness.CONNECTING);p.seed(1,2);
        var a=p.node.findValue(TARGET);var b=p.node.findValue(DhtIdTest.id(0x8001));p.node.poll();
        int index=-1;
        for(int i=0;i<p.script.sent.size();i++) {
            if(p.script.sent.get(i).request().target().equals(TARGET)) {
                index=i;
            }
        }
        p.reply(index,List.of(),bytes(5,1));
        assertTrue(a.done());assertTrue(p.node.isReferenced(DhtIdTest.id(2)),"もう一方の探索がまだ握手を待っている");
        assertFalse(b.done());
    }
}
