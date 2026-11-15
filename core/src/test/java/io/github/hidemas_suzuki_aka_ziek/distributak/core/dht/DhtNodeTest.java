// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtRoutingTableTest.*;
import static org.junit.jupiter.api.Assertions.*;

class DhtNodeTest {
    static final class Wall extends Clock {
        long millis=1_000;
        @Override public ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public Clock withZone(ZoneId zone){return this;}
        @Override public Instant instant(){return Instant.ofEpochMilli(millis);}
        @Override public long millis(){return millis;}
    }
    record Sent(Contact destination,DhtTransport.Request request){}
    /** 全台の番号を知っている試験側も、送り手が知る番号を無視して配送できない。 */
    static final class Delivery implements DhtTransport {
        final Set<DhtId> known=new HashSet<>();
        final ArrayDeque<Sent> waiting=new ArrayDeque<>();
        final List<Sent> sent=new ArrayList<>();
        int peak;
        void introduce(List<Contact> contacts){for(Contact c:contacts)known.add(c.id());}
        @Override public boolean send(Contact destination,Request request) {
            if(!known.contains(destination.id()))throw new AssertionError("Unknown DHT destination");
            var message=new Sent(destination,request);waiting.add(message);sent.add(message);peak=Math.max(peak,(int)waiting.stream().filter(item->item.request.operation()!=Operation.PING).count());return true;
        }
        Sent take(){return waiting.remove();}
    }
    static final class Fixture {
        final AtomicLong nanos=new AtomicLong();final Wall wall=new Wall();final Delivery delivery=new Delivery();
        final DhtNode<Integer> node;
        Fixture(){this(0);}
        Fixture(int local){node=new DhtNode<>(DhtIdTest.id(local),wall,nanos::get,delivery,(key,bytes,clock)->{
            if(bytes.length!=1||bytes[0]==0||clock.millis()<0)throw new SecurityException("Invalid test value");
            return bytes[0]&255;
        },Integer::compare);}
        void seed(int... numbers){for(int n:numbers){delivery.known.add(DhtIdTest.id(n));node.observe(peer(n));}}
        void reply(Sent sent,List<Contact> contacts,byte[] value) {
            delivery.introduce(contacts);
            node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(sent.destination),sent.request.id(),contacts,value);
        }
    }
    @Test void deterministicSixtyFourNodeRingFindsCloserPeersWithoutAnOmniscientSender() {
        int size=64;Map<Integer,Fixture> network=new HashMap<>();
        // 各台に渡すのは隣の2台だけ。配送先を選ぶ処理にはnetworkの全台の表を渡さない。
        for(int i=0;i<size;i++){var f=new Fixture(i);f.seed((i+1)%size,(i+2)%size);network.put(i,f);}
        var origin=network.get(0);var lookup=origin.node.findNode(DhtIdTest.id(63));
        Set<DhtId> queried=new HashSet<>();int turns=0;
        while(!lookup.done()&&turns++<200) {
            origin.node.poll();
            while(!origin.delivery.waiting.isEmpty()) {
                Sent sent=origin.delivery.take();
                if(sent.request.operation()==DhtTransport.Operation.PING){origin.reply(sent,List.of(),null);continue;}
                assertTrue(queried.add(sent.destination.id()));
                int remote=((sent.destination.id().bytes()[30]&255)<<8)|(sent.destination.id().bytes()[31]&255);
                List<Contact> contacts=network.get(remote).node.routing().nearest(sent.request.target(),20).stream().map(AuthenticatedPeer::contact).toList();
                origin.reply(sent,contacts,null);
            }
        }
        assertTrue(lookup.done());assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertTrue(queried.contains(DhtIdTest.id(63)));assertTrue(origin.delivery.peak<=3);
        assertEquals(queried.size(),lookup.result().queried());assertEquals(queried.size(),lookup.result().responded());
    }
    @Test void deliveryDeliberatelyRejectsAnUnknownDestination() {
        var f=new Fixture();f.seed(1);var lookup=f.node.findNode(DhtIdTest.id(9));f.node.poll();
        var request=f.delivery.take().request;
        assertThrows(AssertionError.class,()->f.delivery.send(contact(99),request));assertFalse(lookup.done());
    }
    @Test void findValueWaitsForAllClosestRepliesAndSelectsTheNewestVerifiedVersion() {
        var f=new Fixture();f.seed(1,2,3);var lookup=f.node.findValue(DhtIdTest.id(7));f.node.poll();
        Sent first=f.delivery.take(),second=f.delivery.take(),third=f.delivery.take();
        f.reply(first,List.of(),new byte[]{2});assertFalse(lookup.done());
        assertThrows(IllegalStateException.class,lookup::result);
        f.reply(second,List.of(),new byte[]{9});assertFalse(lookup.done());
        f.reply(third,List.of(),new byte[]{4});f.node.poll();
        assertEquals(9,lookup.result().value().orElseThrow());assertEquals(3,lookup.result().queried());
        assertEquals(3,lookup.result().responded());
    }
    @Test void invalidValuesAreExcludedAndTheInjectedWallClockIsUsed() {
        var f=new Fixture();f.seed(1,2);var lookup=f.node.findValue(DhtIdTest.id(7));f.node.poll();
        f.reply(f.delivery.take(),List.of(),new byte[]{0});f.wall.millis=-1;
        f.reply(f.delivery.take(),List.of(),new byte[]{8});f.node.poll();
        assertTrue(lookup.result().value().isEmpty());assertEquals(2,lookup.result().responded());
    }
    @Test void valuesAreCheckedAgainAtCompletionIfTheWallClockChanges() {
        var f=new Fixture();f.seed(1,2);var lookup=f.node.findValue(DhtIdTest.id(7));f.node.poll();
        f.reply(f.delivery.take(),List.of(),new byte[]{8});f.wall.millis=-1;
        f.reply(f.delivery.take(),List.of(),null);f.node.poll();assertTrue(lookup.result().value().isEmpty());
    }
    @Test void rpcTimesOutAfterOneRetryAndFailedPeersRemainInTheDenominator() {
        var f=new Fixture();f.seed(1,2);var lookup=f.node.findValue(DhtIdTest.id(7));f.node.poll();
        Sent a=f.delivery.take(),b=f.delivery.take();f.reply(a,List.of(),new byte[]{3});
        f.nanos.set(DhtLimits.RPC_NANOS-1);f.node.poll();assertTrue(f.delivery.waiting.isEmpty());
        f.nanos.incrementAndGet();f.node.poll();assertEquals(b.request.id(),f.delivery.take().request.id());
        f.nanos.set(2*DhtLimits.RPC_NANOS);f.node.poll();
        assertTrue(lookup.done());assertEquals(2,lookup.result().queried());assertEquals(1,lookup.result().responded());
        assertEquals(3,f.delivery.sent.size());f.nanos.set(50_000_000_000L);f.node.poll();assertEquals(3,f.delivery.sent.size());
    }
    @Test void sparsePollingDoesNotRestartTheRpcDeadline() {
        var f=new Fixture();f.seed(1);var lookup=f.node.findNode(DhtIdTest.id(7));f.node.poll();f.delivery.take();
        f.nanos.set(5_900_000_000L);f.node.poll();f.delivery.take();
        f.nanos.set(6_000_000_000L);f.node.poll();assertTrue(lookup.done());assertEquals(2,f.delivery.sent.size());
    }
    @Test void absoluteLookupDeadlineStopsWithoutSendingLateRetries() {
        var f=new Fixture();f.seed(1,2,3,4);var lookup=f.node.findNode(DhtIdTest.id(7));f.node.poll();
        f.nanos.set(DhtLimits.LOOKUP_NANOS);f.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop());assertEquals(3,f.delivery.sent.size());
    }
    @Test void candidateBudgetBoundsStateWithoutStoppingAndProtectsQueriedAndWaitingPeers() {
        var f=new Fixture();f.seed(1,2,3);var lookup=f.node.findValue(DhtIdTest.id(0));f.node.poll();
        List<Contact> contacts=new ArrayList<>();for(int i=400;i<=701;i++)contacts.add(contact(i));
        f.reply(f.delivery.take(),contacts,null);assertFalse(lookup.done());
        f.reply(f.delivery.take(),List.of(),null);f.reply(f.delivery.take(),List.of(),null);
        DhtNodeReviewTest.complete(f,lookup);
        assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());assertEquals(256,lookup.result().candidates());
        assertEquals(20,lookup.result().queried());
        assertEquals(20,lookup.result().responded());assertTrue(lookup.result().value().isEmpty());
    }
    @Test void queryBudgetStopsEvenWhenEveryResponseIntroducesACloserPeer() {
        var f=new Fixture();f.seed(1000);var lookup=f.node.findNode(DhtIdTest.id(0));
        for(int i=0;i<128;i++) {
            f.node.poll();Sent query=null;
            while(!f.delivery.waiting.isEmpty()) {
                Sent message=f.delivery.take();
                if(message.request.operation()==DhtTransport.Operation.PING)f.reply(message,List.of(),null);
                else {assertNull(query);query=message;}
            }
            assertNotNull(query);f.reply(query,List.of(contact(999-i)),null);
        }
        f.node.poll();assertTrue(lookup.done());assertEquals(DhtNode.Stop.QUERY_LIMIT,lookup.result().stop());
        assertEquals(128,lookup.result().queried());assertEquals(128,f.delivery.sent.stream().filter(item->item.request.operation()==DhtTransport.Operation.FIND_NODE).count());
    }
    @Test void repeatedContactsAndCyclesDoNotCauseRepeatedQueries() {
        var f=new Fixture();f.seed(1,2);var lookup=f.node.findNode(DhtIdTest.id(7));f.node.poll();
        var repeated=List.of(contact(0),contact(1),contact(2),contact(1),contact(2));
        f.reply(f.delivery.take(),repeated,null);f.reply(f.delivery.take(),repeated,null);f.node.poll();
        assertTrue(lookup.done());assertEquals(2,lookup.result().queried());assertEquals(2,f.delivery.sent.size());
    }
    @Test void completedTwentyClosestPeersStopQueriesToKnownFartherPeers() {
        var f=new Fixture();for(int n=1;n<=32;n++)f.seed(n);var lookup=f.node.findNode(DhtIdTest.id(0));
        for(int turn=0;turn<20&&!lookup.done();turn++) {
            f.node.poll();while(!f.delivery.waiting.isEmpty())f.reply(f.delivery.take(),List.of(),null);
        }
        assertTrue(lookup.done());assertEquals(20,lookup.result().queried());assertEquals(20,lookup.result().responded());
        assertEquals(20,f.delivery.sent.size());
        assertTrue(f.delivery.sent.stream().allMatch(sent->DhtIdTest.id(0).compareDistance(sent.destination.id(),DhtIdTest.id(20))<=0));
    }
    /** 計画 B: 遠い相手の値でも、検証できれば印を立てる。値つきの返信の近い連絡先は候補に入れず、問い合わせも続けない。 */
    @Test void aValueFromAFartherPeerEndsTheLookupWithoutFollowingItsCloserContacts() {
        var f=new Fixture();f.seed(100,101,102);var lookup=f.node.findValue(DhtIdTest.id(0));f.node.poll();
        List<Contact> closer=new ArrayList<>();for(int n=1;n<=20;n++)closer.add(contact(n));
        f.reply(f.delivery.take(),closer,new byte[]{99});assertFalse(lookup.done(),"残りの 2 台の返事を待つ");
        f.reply(f.delivery.take(),List.of(),null);f.reply(f.delivery.take(),List.of(),null);
        assertTrue(lookup.done());assertEquals(DhtNode.Stop.COMPLETE,lookup.result().stop());
        assertEquals(99,lookup.result().value().orElseThrow());assertEquals(3,lookup.result().queried());
        assertEquals(3,lookup.result().candidates(),"近い連絡先は候補に入れない");
        assertEquals(3,f.delivery.sent.size(),"続きの問い合わせを出さない");
    }
    @Test void aTransportThatCannotStartDeliveryCountsAsAFailedQuery() {
        var node=new DhtNode<Integer>(DhtIdTest.id(0),Clock.systemUTC(),()->0L,(destination,request)->false,
                (key,record,clock)->null,Integer::compare);
        node.observe(peer(1));var lookup=node.findNode(DhtIdTest.id(7));node.poll();
        assertTrue(lookup.done());assertEquals(1,lookup.result().queried());assertEquals(0,lookup.result().responded());
    }
    @Test void onlyFourLookupsRunAtOnceAndFinishedSlotsAreReusable() {
        var f=new Fixture();f.seed(1,2,3);for(int i=0;i<4;i++)f.node.findNode(DhtIdTest.id(i));
        f.node.poll();assertEquals(12,f.delivery.waiting.size());assertEquals(4,f.node.activeLookups());
        assertThrows(IllegalStateException.class,()->f.node.findNode(DhtIdTest.id(7)));
        while(!f.delivery.waiting.isEmpty())f.reply(f.delivery.take(),List.of(),null);
        f.node.poll();assertEquals(0,f.node.activeLookups());assertNotNull(f.node.findNode(DhtIdTest.id(7)));
    }
    @Test void wrongResponderDuplicateReplyAndUnsolicitedResponseHaveNoEffect() {
        var f=new Fixture();f.seed(1);var lookup=f.node.findValue(DhtIdTest.id(7));f.node.poll();Sent sent=f.delivery.take();
        f.node.receive(peer(2),sent.request.id(),List.of(contact(99)),new byte[]{99});assertFalse(lookup.done());
        f.node.receive(peer(1),sent.request.id()+1,List.of(contact(99)),new byte[]{99});
        f.reply(sent,List.of(),new byte[]{3});f.reply(sent,List.of(contact(99)),new byte[]{99});f.node.poll();
        assertEquals(1,lookup.result().responded());assertEquals(1,lookup.result().candidates());
        assertEquals(3,lookup.result().value().orElseThrow());
    }
    @Test void pingUsesOneRetryAndPromotesTheReplacementOnlyAtSixSeconds() {
        var f=new Fixture();for(int n=128;n<=148;n++)f.seed(n);f.node.poll();
        assertEquals(DhtTransport.Operation.PING,f.delivery.take().request.operation());
        f.nanos.set(DhtLimits.RPC_NANOS);f.node.poll();f.delivery.take();assertEquals(1,f.node.routing().pendingCount());
        f.nanos.set(2*DhtLimits.RPC_NANOS);f.node.poll();
        assertEquals(DhtIdTest.id(148),f.node.routing().bucket(7).get(19).id());assertEquals(2,f.delivery.sent.size());
    }
    @Test void pongOrOtherAuthenticatedDhtTrafficKeepsTheIncumbent() {
        for(boolean pong:new boolean[]{false,true}) {
            var f=new Fixture();for(int n=128;n<=148;n++)f.seed(n);f.node.poll();Sent sent=f.delivery.take();
            if(pong)f.reply(sent,List.of(),null);else f.node.observe(peer(128));
            f.nanos.set(6_000_000_000L);f.node.poll();
            assertEquals(DhtIdTest.id(128),f.node.routing().bucket(7).get(19).id());assertEquals(1,f.delivery.sent.size());
        }
    }
    @Test void clockResetCancelsLookupsAndProbesAndRebasesTheHourlyClock() {
        var f=new Fixture();f.nanos.set(10_000_000_000L);
        for(int n=128;n<=148;n++)f.seed(n);var lookup=f.node.findValue(DhtIdTest.id(7));f.node.poll();
        f.nanos.set(5_000_000_000L);f.node.poll();
        assertEquals(DhtNode.Stop.CLOCK_RESET,lookup.result().stop());assertTrue(lookup.result().value().isEmpty());
        assertEquals(0,f.node.routing().pendingCount());assertEquals(20,f.node.routing().size());
        assertFalse(f.node.refreshDue());f.nanos.addAndGet(DhtLimits.REFRESH_NANOS-1);assertFalse(f.node.refreshDue());
        f.nanos.incrementAndGet();assertTrue(f.node.refreshDue());assertFalse(f.node.refreshDue());
        var next=f.node.findNode(DhtIdTest.id(9));f.nanos.addAndGet(DhtLimits.LOOKUP_NANOS);f.node.poll();
        assertEquals(DhtNode.Stop.DEADLINE,next.result().stop());assertEquals(DhtNode.Stop.CLOCK_RESET,lookup.result().stop());
    }
    @Test void networkChangeClearsTheTableAndRejectsOldResponsesWithoutReusingIds() {
        var f=new Fixture();for(int n=128;n<=148;n++)f.seed(n);
        var lookup=f.node.findNode(DhtIdTest.id(7));f.node.poll();List<Sent> previous=List.copyOf(f.delivery.sent);
        f.node.networkChanged();assertEquals(0,f.node.routing().size());assertEquals(0,f.node.routing().pendingCount());
        assertEquals(DhtNode.Stop.NETWORK_CHANGED,lookup.result().stop());
        for(Sent sent:previous)f.reply(sent,List.of(contact(99)),null);
        assertEquals(0,f.node.routing().size());f.delivery.waiting.clear();f.seed(1);
        f.node.findNode(DhtIdTest.id(7));f.node.poll();long next=f.delivery.take().request.id();
        assertTrue(previous.stream().noneMatch(sent->sent.request.id()==next));
    }
    @Test void diagnosticStringsDoNotPrintIdentifiersKeysOrValues() {
        var f=new Fixture();f.seed(1);var lookup=f.node.findNode(DhtIdTest.id(7));f.node.poll();Sent sent=f.delivery.take();
        f.reply(sent,List.of(),null);f.node.poll();
        assertEquals("DHT request",sent.request.toString());assertEquals("DHT contact",contact(1).toString());
        assertEquals("Authenticated DHT peer",peer(1).toString());assertEquals("DHT lookup result",lookup.result().toString());
    }
}
