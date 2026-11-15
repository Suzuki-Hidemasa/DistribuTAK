// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtRoutingTableTest.*;
import static org.junit.jupiter.api.Assertions.*;

/** 核 D: 探索の CONNECTING・BUSY・UNAVAILABLE、結果の closest()、isReferenced、探索を回す先頭のずらし。台本どおりに prepare を返す偽の配送側で調べる。 */
class DhtLookupConnectingTest {
    static final long SECOND=1_000_000_000L,CONNECT=90*SECOND;
    record Sent(DhtId destination,DhtTransport.Request request){}
    /** prepare の答えを台本で決める。何も決めていない相手は READY。 */
    static final class Script implements DhtTransport {
        final Map<DhtId,Readiness> readiness=new HashMap<>();
        final Set<DhtId> throwing=new HashSet<>();
        final List<Sent> sent=new ArrayList<>();
        final List<DhtId> prepared=new ArrayList<>();
        boolean sendOk=true;
        final Set<DhtId> sendFails=new HashSet<>();
        void set(int n,Readiness value){readiness.put(DhtIdTest.id(n),value);}
        @Override public boolean send(Contact destination,Request request) {
            if(!sendOk||sendFails.contains(destination.id()))return false;
            sent.add(new Sent(destination.id(),request));return true;
        }
        /** 探索が「初めて BUSY を受けた」と知らせてきた相手（核 D の直し。答え 187 の必修 1）。 */
        final List<DhtId> firstBusy=new ArrayList<>();
        boolean firstBusyThrows;
        @Override public void firstBusy(Contact destination) {
            firstBusy.add(destination.id());
            if(firstBusyThrows)throw new IllegalStateException("台本の例外");
        }
        @Override public Readiness prepare(Contact destination) {
            prepared.add(destination.id());
            if(throwing.contains(destination.id()))throw new IllegalStateException("台本の例外");
            return readiness.getOrDefault(destination.id(),Readiness.READY);
        }
    }
    static final class H {
        final AtomicLong nanos=new AtomicLong();final DhtNodeTest.Wall wall=new DhtNodeTest.Wall();final Script script=new Script();
        final DhtNode<Integer> node=new DhtNode<>(DhtIdTest.id(0),wall,nanos::get,script,(key,bytes,clock)->bytes[0]&255,Integer::compare);
        int answered;
        void seed(int... numbers){for(int n:numbers)node.observe(peer(n));}
        void reply(Sent sent,List<Contact> contacts) {
            node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(sent.destination)),sent.request.id(),contacts,null);
        }
        /** まだ答えていない送信すべてに、同じ紹介で答える。 */
        void answerAll(List<Contact> contacts) {
            while(answered<script.sent.size())reply(script.sent.get(answered++),contacts);
        }
        void at(long seconds){nanos.set(seconds*SECOND);}
        List<Integer> destinations(int from) {
            List<Integer> result=new ArrayList<>();
            for(int i=from;i<script.sent.size();i++){byte[] b=script.sent.get(i).destination.bytes();result.add(((b[30]&255)<<8)|(b[31]&255));}
            return result;
        }
    }
    static List<Contact> contacts(int from,int to){List<Contact> list=new ArrayList<>();for(int i=from;i<=to;i++)list.add(contact(i));return list;}

    // ---- Result.closest() (T14) ----
    @Test void closestListsOnlyRepliedPeersNearestFirstAtMostTwenty() {
        // 返事のたびに、これまでより目標に近い相手を紹介する（返事をくれる相手が 20 台を超えるように）。目標は 0xFFFF。
        var h=new H();h.seed(1,2,3);var target=DhtIdTest.id(0xFFFF);var lookup=h.node.findNode(target);
        int fresh=0x1000;Set<DhtId> replied=new HashSet<>();
        for(int turn=0;turn<200&&!lookup.done();turn++) {
            h.node.poll();
            while(h.answered<h.script.sent.size()) {
                Sent sent=h.script.sent.get(h.answered++);
                if(sent.request.operation()!=DhtTransport.Operation.FIND_NODE)continue;
                replied.add(sent.destination);
                if(replied.size()<30){h.reply(sent,contacts(fresh,fresh+2));fresh+=3;}else h.reply(sent,List.of());
            }
        }
        assertTrue(lookup.done());assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertTrue(replied.size()>20,"返事が 21 台以上ある網で調べる");
        var closest=lookup.result().closest();assertEquals(20,closest.size());
        List<DhtId> expected=new ArrayList<>(replied);expected.sort(target::compareDistance);
        assertEquals(expected.subList(0,20),closest.stream().map(Contact::id).toList());
        assertThrows(UnsupportedOperationException.class,()->closest.add(contact(5)));
        assertEquals("DHT lookup result",lookup.result().toString());
    }
    @Test void closestHasNineteenWhenOnlyNineteenPeersExist() {
        var h=new H();h.seed(1,2,3);var lookup=h.node.findNode(DhtIdTest.id(100));
        for(int turn=0;turn<50&&!lookup.done();turn++){h.node.poll();h.answerAll(contacts(4,19));}
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(19,lookup.result().closest().size());assertEquals(19,lookup.result().responded());
    }
    @Test void closestLeavesOutFailedAndStillWaitingPeers() {
        var h=new H();h.seed(1,2,3,4);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();// 1・3・2 へ送る
        assertEquals(List.of(1,3,2),h.destinations(0));
        h.reply(h.script.sent.get(1),List.of());h.answered=3;// 3 だけが答え、1 と 2 は返事なし
        h.at(7);h.node.poll();// 1・2 は 6 秒で FAILED、4 へ送る
        assertFalse(lookup.done());
        h.at(120);h.node.poll();// 4 は返事待ちのまま締切
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());
        assertEquals(List.of(DhtIdTest.id(3)),lookup.result().closest().stream().map(Contact::id).toList());
    }
    @Test void closestIsEmptyWhenTheNetworkChanged() {
        var h=new H();h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(1));h.node.poll();h.reply(h.script.sent.get(0),List.of());
        h.node.networkChanged();
        assertEquals(DhtNode.Stop.NETWORK_CHANGED,lookup.result().stop());assertTrue(lookup.result().closest().isEmpty());
    }

    // ---- CONNECTING ----
    @Test void connectingCountsAgainstAlphaButSendsNothing() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2,3,4);h.node.findNode(DhtIdTest.id(1));
        h.node.poll();
        assertEquals(List.of(3,2),h.destinations(0));// 1 は握手中、α=3 は握手中を含めて使い切る
        assertFalse(h.script.prepared.contains(DhtIdTest.id(4)));
    }
    @Test void aConnectingPeerThatBecomesReadyIsSentOnceAndCountedOnce() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2,3,4);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.script.set(1,DhtTransport.Readiness.READY);h.node.poll();
        assertEquals(List.of(3,2,1),h.destinations(0));
        h.answerAll(List.of());h.node.poll();assertEquals(4,h.destinations(0).get(3));h.answerAll(List.of());h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(4,lookup.result().queried());assertEquals(4,lookup.result().responded());
    }
    @Test void connectingFailsNinetySecondsAfterItStartedAndOnlyThatPeerFails() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2,3,4);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());h.node.poll();h.answerAll(List.of());
        h.nanos.set(CONNECT-1);h.node.poll();assertFalse(lookup.done());
        h.nanos.set(CONNECT);h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(4,lookup.result().queried());assertEquals(3,lookup.result().responded());
        assertEquals(3,lookup.result().closest().size());
    }
    @Test void theDeadlineIsNotExtendedWhileAPeerIsStillConnecting() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());
        h.at(100);h.script.set(1,DhtTransport.Readiness.CONNECTING);h.node.poll();assertFalse(lookup.done());
        h.at(119);h.node.poll();assertFalse(lookup.done());
        h.at(120);h.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());
        assertEquals(2,lookup.result().queried());assertEquals(1,lookup.result().responded());
    }
    @Test void aHandshakeThatFinishesAfterTheDeadlineStillEntersTheRoutingTable() {
        // 1 は経路表にいて、2 を紹介する。2 は握手中のまま締切になる（紹介されただけでは経路表に入らない）。
        var h=new H();h.script.set(2,DhtTransport.Readiness.CONNECTING);h.seed(1);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(contacts(2,2));h.node.poll();
        assertEquals(List.of(1),h.destinations(0),"Only the seeded peer was asked; peer 2 is still connecting");
        h.at(120);h.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());
        assertFalse(h.node.routing().contains(DhtIdTest.id(2)),"The peer that was still connecting is not in the table at the deadline");
        // 締切のあとに握手が済んで観測されたとき、握手中だった相手そのものが経路表に入る。
        h.node.observe(peer(2));
        assertTrue(h.node.routing().contains(DhtIdTest.id(2)),"The peer whose handshake finished after the deadline enters the table");
        // 締切のあとに来た紹介つきの返事でも、返事をくれた相手は経路表に入る。
        assertFalse(h.node.routing().contains(DhtIdTest.id(10)));
        h.node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(DhtIdTest.id(10))),1,List.of(),null);
        assertTrue(h.node.routing().contains(DhtIdTest.id(10)));
    }
    @Test void theRpcClockStartsWhenTheRequestIsSentNotWhenTheHandshakeStarted() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());
        h.at(60);h.script.set(1,DhtTransport.Readiness.READY);h.node.poll();
        assertEquals(List.of(2,1),h.destinations(0));
        h.at(65);h.node.poll();h.answerAll(List.of());h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(2,lookup.result().responded());
    }
    @Test void aReplyArrivingAfterTheRpcLifetimeIsStillRefused() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.at(60);h.script.set(1,DhtTransport.Readiness.READY);h.node.poll();
        Sent sent=h.script.sent.get(0);h.at(60+6);h.node.poll();// 6 秒で FAILED
        h.reply(sent,List.of());
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(0,lookup.result().responded());
    }
    @Test void aPeerStuckConnectingEndsTheLookupWithQueryLimitInsteadOfWaiting() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1,2);var lookup=h.node.findNode(DhtIdTest.id(0xFFFF));
        int fresh=0x1000;
        for(int turn=0;turn<400&&!lookup.done();turn++) {
            h.node.poll();
            while(h.answered<h.script.sent.size()){h.reply(h.script.sent.get(h.answered++),contacts(fresh,fresh+4));fresh+=5;}
        }
        assertEquals(DhtNode.Stop.QUERY_LIMIT,lookup.result().stop());
        assertEquals(DhtLimits.MAX_QUERIES,lookup.result().queried());
        assertEquals(DhtLimits.MAX_QUERIES-1,h.script.sent.stream().filter(s->s.request.operation()==DhtTransport.Operation.FIND_NODE).count());// 握手中の 1 台には送っていない
        assertTrue(h.nanos.get()<CONNECT);
    }

    // ---- UNAVAILABLE / BUSY ----
    @Test void unavailableFailsOnlyThatCandidateWithoutSendingAndCountsOneQuery() {
        var h=new H();h.script.set(3,DhtTransport.Readiness.UNAVAILABLE);h.seed(1,2,3,4);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(List.of(1,2,4),h.destinations(0));
        h.answerAll(List.of());h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(4,lookup.result().queried());assertEquals(3,lookup.result().responded());
    }
    @Test void aPrepareThatThrowsIsTreatedAsUnavailable() {
        var h=new H();h.script.throwing.add(DhtIdTest.id(3));h.seed(1,2,3);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(List.of(1,2),h.destinations(0));
        h.answerAll(List.of());h.node.poll();assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(3,lookup.result().queried());assertEquals(2,lookup.result().responded());
    }
    @Test void aReadyPeerWhoseSendFailsIsFailed() {
        var h=new H();h.script.sendFails.add(DhtIdTest.id(2));h.seed(1,2,3);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(List.of(1,3),h.destinations(0));
        h.answerAll(List.of());h.node.poll();assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(3,lookup.result().queried());assertEquals(2,lookup.result().responded());
    }
    @Test void busyStaysNewIsNotCountedAndOtherNewPeersGoFirst() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2,3);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();assertEquals(List.of(3,2),h.destinations(0));
        h.answerAll(List.of());h.at(10);h.node.poll();
        assertFalse(lookup.done(),"BUSY の NEW が残る間は COMPLETE にしない");assertEquals(2,h.script.sent.size());
        h.script.set(1,DhtTransport.Readiness.READY);h.at(11);h.node.poll();
        assertEquals(List.of(3,2,1),h.destinations(0));h.answerAll(List.of());h.node.poll();
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(3,lookup.result().queried());
    }
    @Test void busyForeverEndsAtTheDeadlineWithoutCountingAQuery() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.BUSY);h.seed(1,2,3);var lookup=h.node.findNode(DhtIdTest.id(1));
        h.node.poll();h.answerAll(List.of());
        h.at(119);h.node.poll();assertFalse(lookup.done());
        h.at(120);h.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());
        assertEquals(2,lookup.result().queried());assertEquals(2,lookup.result().responded());
    }
    @Test void connectingIsAskedAgainEveryPollAndAReadyAnswerSendsImmediately() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.seed(1);h.node.findNode(DhtIdTest.id(1));
        for(int i=0;i<3;i++){h.at(i);h.node.poll();}
        assertEquals(3,h.script.prepared.size());assertTrue(h.script.sent.isEmpty());
    }

    // ---- isReferenced ----
    @Test void isReferencedIsTrueOnlyForPeersWaitingOrConnecting() {
        var h=new H();h.script.set(1,DhtTransport.Readiness.CONNECTING);h.script.set(4,DhtTransport.Readiness.BUSY);
        h.seed(1,2,3,4);var lookup=h.node.findNode(DhtIdTest.id(1));
        for(int n=1;n<=4;n++)assertFalse(h.node.isReferenced(DhtIdTest.id(n)),"まだ何も始めていない");
        h.node.poll();
        assertTrue(h.node.isReferenced(DhtIdTest.id(1)));assertTrue(h.node.isReferenced(DhtIdTest.id(2)));assertTrue(h.node.isReferenced(DhtIdTest.id(3)));
        assertFalse(h.node.isReferenced(DhtIdTest.id(4)));assertFalse(h.node.isReferenced(DhtIdTest.id(9)));
        h.reply(h.script.sent.get(0),List.of());// 3 が DONE
        assertFalse(h.node.isReferenced(DhtIdTest.id(3)));
        h.at(120);h.node.poll();assertTrue(lookup.done());
        for(int n=1;n<=4;n++)assertFalse(h.node.isReferenced(DhtIdTest.id(n)));
    }

    // ---- 探索を回す先頭のずらし ----
    @Test void theFirstLookupPolledRotatesAndAShrinkingListStaysInRange() {
        var h=new H();h.seed(0x100,0x200,0x400);
        for(int n:new int[]{0x100,0x200,0x400})h.script.set(n,DhtTransport.Readiness.BUSY);
        h.node.findNode(DhtIdTest.id(0x100));h.node.findNode(DhtIdTest.id(0x200));h.at(100);h.node.findNode(DhtIdTest.id(0x400));
        List<Integer> firsts=new ArrayList<>();
        for(int round=0;round<3;round++) {
            h.script.prepared.clear();h.at(100+round);h.node.poll();
            byte[] b=h.script.prepared.get(0).bytes();firsts.add(((b[30]&255)<<8)|(b[31]&255));
        }
        assertEquals(List.of(0x100,0x200,0x400),firsts);
        // 2 つの探索が締切で消えても、残った 1 つは毎回回される
        h.at(120);h.node.poll();assertEquals(1,h.node.activeLookups());
        for(int round=0;round<3;round++){h.script.prepared.clear();h.at(121+round);h.node.poll();assertFalse(h.script.prepared.isEmpty());}
    }
}
