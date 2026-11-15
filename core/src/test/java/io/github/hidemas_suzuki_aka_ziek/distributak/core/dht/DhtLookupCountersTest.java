// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.List;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtLookupConnectingTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 D の直し（答え 187 の必修 1）: 探索が数える件数。
 * 「初めて BUSY を受けた」知らせ（firstBusy）・QUERY_LIMIT で終わった数・DEADLINE で終わった数・UNAVAILABLE で FAILED にした数・
 * つなぎ中 90 秒で FAILED にした数。数えるのは件数だけで、相手の番号は残さない。
 */
class DhtLookupCountersTest {
    // ---- 初めての BUSY ----
    @Test void aBusyCandidateIsReportedOnceEvenWhenItIsAskedAtEveryPoll() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2,3,4);h.node.findNode(DhtIdTest.id(1));
        for(int second=0;second<5;second++){h.at(second);h.node.poll();h.answerAll(List.of());}
        assertEquals(List.of(DhtIdTest.id(1)),h.script.firstBusy,"初めて BUSY になったときの 1 回だけ知らせる");
        assertTrue(h.script.prepared.stream().filter(id->id.equals(DhtIdTest.id(1))).count()>=2,"毎回の poll で聞き直している（それでも数は増えない）");
    }
    @Test void everyBusyCandidateIsReportedOnceEach() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.script.set(2,DhtTransport.Readiness.BUSY);h.seed(1,2,3);h.node.findNode(DhtIdTest.id(1));
        for(int second=0;second<3;second++){h.at(second);h.node.poll();}
        assertEquals(2,h.script.firstBusy.size());
        assertTrue(h.script.firstBusy.containsAll(List.of(DhtIdTest.id(1),DhtIdTest.id(2))));
    }
    @Test void aCandidateThatWasReadyOrConnectingIsNotReportedAsBusy() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.at(1);h.node.poll();
        assertTrue(h.script.firstBusy.isEmpty());
    }
    @Test void aBusyAnswerAfterConnectingFailsTheCandidateButIsNotAFirstBusy() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(List.of(DhtIdTest.id(1)),h.script.firstBusy);
        h.script.set(1,DhtTransport.Readiness.CONNECTING);h.at(1);h.node.poll();// BUSY のあとに握手を始めた
        h.script.set(1,DhtTransport.Readiness.BUSY);h.at(2);h.node.poll();// 握手中に BUSY → FAILED
        assertEquals(List.of(DhtIdTest.id(1)),h.script.firstBusy,"握手中の BUSY は『初めての BUSY』ではない");
        assertEquals(0,h.node.unavailableFailed(),"BUSY で外した候補は UNAVAILABLE の件数に混ぜない");
        h.answerAll(List.of());h.at(3);h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
    }
    @Test void aFirstBusyThatThrowsDoesNotStopTheLookup() {
        var h=new H();h.script.firstBusyThrows=true;h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2,3);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(List.of(3,2),h.destinations(0));assertEquals(1,h.script.firstBusy.size());
        h.answerAll(List.of());h.script.set(1,DhtTransport.Readiness.READY);h.at(1);h.node.poll();
        assertEquals(List.of(3,2,1),h.destinations(0));h.answerAll(List.of());h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(3,lookup.result().responded());
    }

    // ---- QUERY_LIMIT ----
    @Test void aLookupEndedByTheQueryLimitIsCountedOnce() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(0xFFFF));
        int fresh=0x1000;
        for(int turn=0;turn<400&&!lookup.done();turn++) {
            h.node.poll();
            while(h.answered<h.script.sent.size()){h.reply(h.script.sent.get(h.answered++),contacts(fresh,fresh+4));fresh+=5;}
        }
        assertEquals(DhtNode.Stop.QUERY_LIMIT,lookup.result().stop());
        assertEquals(1,h.node.lookupsQueryLimit());assertEquals(0,h.node.lookupsDeadline());
        h.node.poll();assertEquals(1,h.node.lookupsQueryLimit(),"終わった探索をもう一度数えない");
    }

    // ---- DEADLINE ----
    @Test void aLookupEndedByTheDeadlineAtPollIsCountedOnce() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());
        h.at(119);h.node.poll();assertEquals(0,h.node.lookupsDeadline());
        h.at(120);h.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());
        assertEquals(1,h.node.lookupsDeadline());assertEquals(0,h.node.lookupsQueryLimit());
        h.at(121);h.node.poll();assertEquals(1,h.node.lookupsDeadline());
    }
    @Test void aLookupEndedByTheDeadlineAtReceiveIsCountedOnce() {
        var h=new H();h.seed(1);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.at(120);h.reply(h.script.sent.get(0),List.of());
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());
        assertEquals(1,h.node.lookupsDeadline());
        h.node.poll();assertEquals(1,h.node.lookupsDeadline());
    }
    @Test void twoLookupsEndedByTheDeadlineAreCountedTwice() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1);
        h.node.findNode(DhtIdTest.id(1));h.node.findNode(DhtIdTest.id(2));
        h.at(120);h.node.poll();
        assertEquals(2,h.node.lookupsDeadline());
    }

    // ---- UNAVAILABLE ----
    @Test void anUnavailableCandidateAtTheStartIsCounted() {
        var h=new H();h.script.set(3,DhtTransport.Readiness.UNAVAILABLE);h.seed(1,2,3,4);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(1,h.node.unavailableFailed());
    }
    @Test void aPrepareThatThrowsOrReturnsNullIsCountedAsUnavailable() {
        var h=new H();h.script.throwing.add(DhtIdTest.id(3));h.seed(1,2,3);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(1,h.node.unavailableFailed());
    }
    @Test void aConnectingCandidateThatBecomesUnavailableIsCounted() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(0,h.node.unavailableFailed());
        h.script.set(1,DhtTransport.Readiness.UNAVAILABLE);h.at(1);h.node.poll();
        assertEquals(1,h.node.unavailableFailed());
        h.at(2);h.node.poll();assertEquals(1,h.node.unavailableFailed(),"FAILED になった候補はもう聞かない");
    }
    @Test void aSendThatFailsIsNotCountedAsUnavailable() {
        var h=new H();h.script.sendFails.add(DhtIdTest.id(2));h.seed(1,2,3);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(0,h.node.unavailableFailed());
    }

    // ---- つなぎ中 90 秒 ----
    @Test void aCandidateConnectingForNinetySecondsIsCountedOnceWhenItIsFailed() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2,3,4);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());
        h.nanos.set(CONNECT-1);h.node.poll();assertEquals(0,h.node.connectingTimedOut());
        h.nanos.set(CONNECT);h.node.poll();assertEquals(1,h.node.connectingTimedOut());
        assertEquals(0,h.node.unavailableFailed(),"つなぎ中 90 秒は別の件数");
        h.nanos.set(CONNECT+SECOND);h.node.poll();assertEquals(1,h.node.connectingTimedOut());
    }

    // ---- 数えない終わり方 ----
    @Test void completeAndNetworkChangedEndingsAreNotCounted() {
        var h=new H();h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        var second=h.node.findNode(DhtIdTest.id(2));h.node.poll();
        h.node.networkChanged();
        assertEquals(DhtNode.Stop.NETWORK_CHANGED,second.result().stop());
        assertEquals(0,h.node.lookupsQueryLimit());assertEquals(0,h.node.lookupsDeadline());
        assertEquals(0,h.node.unavailableFailed());assertEquals(0,h.node.connectingTimedOut());
    }
    @Test void aClockResetEndingIsNotCounted() {
        var h=new H();h.at(10);h.seed(1);var lookup=h.node.findNode(DhtIdTest.id(1));h.node.poll();
        h.at(5);h.node.poll();
        assertEquals(DhtNode.Stop.CLOCK_RESET,lookup.result().stop());
        assertEquals(0,h.node.lookupsDeadline());assertEquals(0,h.node.lookupsQueryLimit());
    }
}
