// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtRoutingTableTest.*;
import static org.junit.jupiter.api.Assertions.*;

class DiscoveryLookupIntegrationTest {
    static void released(Object lookup) throws Exception {
        for(var field:lookup.getClass().getDeclaredFields())if(DhtNode.Verifier.class.isAssignableFrom(field.getType())||Comparator.class.isAssignableFrom(field.getType())) {
            field.setAccessible(true);assertNull(field.get(lookup));
        }
    }
    @Test void twoConcurrentLookupsOfTheSameKeyKeepIndependentPayloadHistories() throws Exception {
        var f=new DiscoveryStoreTest.Fixture();var delivery=new DhtNodeTest.Delivery();delivery.introduce(List.of(contact(1),contact(2)));
        var node=new DhtNode<DiscoveryRecord>(DhtIdTest.id(0),f.wall,f.nanos::get,delivery,
                (key,raw,clock)->{throw new AssertionError("Default verifier used");},(a,b)->{throw new AssertionError("Default comparator used");});
        node.observe(peer(1));node.observe(peer(2));var a=f.store.newLookupVerifier();var b=f.store.newLookupVerifier();
        var key=record(7,1,NOW).key();var first=node.findValue(key,a,a);var second=node.findValue(key,b,b);node.poll();
        for(int n=0;n<4;n++) {
            var sent=delivery.take();int version=n%2+1,port=n<2?50000+version:51000+version;
            var record=DiscoveryRecord.issue(GROUP,secret(7),HANDSHAKE,IP,port,version,NOW);
            node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(sent.destination()),sent.request().id(),List.of(),record.encode());
        }
        node.poll();assertEquals(50002,first.result().value().orElseThrow().port());assertEquals(51002,second.result().value().orElseThrow().port());
        assertEquals(0,f.store.size());assertEquals(0,f.store.maximumSize());released(first);released(second);
    }
    @Test void everyIncompleteTerminationAlsoReleasesThePerLookupFunctions() throws Exception {
        for(int reason=0;reason<3;reason++) {
            var f=new DiscoveryStoreTest.Fixture();var delivery=new DhtNodeTest.Delivery();delivery.introduce(List.of(contact(1)));
            var node=new DhtNode<DiscoveryRecord>(DhtIdTest.id(0),f.wall,f.nanos::get,delivery,(key,raw,clock)->null,(a,b)->0);
            node.observe(peer(1));var policy=f.store.newLookupVerifier();var lookup=node.findValue(record(7,1,NOW).key(),policy,policy);node.poll();
            if(reason==0){f.nanos.set(DhtLimits.LOOKUP_NANOS);node.poll();}
            else if(reason==1){f.nanos.set(-1);node.poll();}else node.networkChanged();
            assertTrue(lookup.done());assertTrue(lookup.result().value().isEmpty());released(lookup);
        }
        var f=new DhtNodeTest.Fixture();f.seed(1000);var lookup=f.node.findValue(DhtIdTest.id(0),(key,raw,clock)->1,Integer::compare);
        for(int n=0;n<128;n++)f.reply(DhtNodeReviewTest.query(f),List.of(contact(999-n)),null);
        f.node.poll();assertEquals(DhtNode.Stop.QUERY_LIMIT,lookup.result().stop());released(lookup);
        /* 計画 B: 値を受け取って終わるときも、探索ごとの関数を放す。 */
        var g=new DhtNodeTest.Fixture();g.seed(1000);var found=g.node.findValue(DhtIdTest.id(0),(key,raw,clock)->1,Integer::compare);
        g.reply(DhtNodeReviewTest.query(g),List.of(),new byte[]{1});
        assertTrue(found.done());assertEquals(DhtNode.Stop.COMPLETE,found.result().stop());released(found);
    }
    @Test void newOverloadRejectsNullAndReentryAndEnforcesFourActiveLookups() {
        var f=new DiscoveryStoreTest.Fixture();var reference=new AtomicReference<DhtNode<DiscoveryRecord>>();var policy=f.store.newLookupVerifier();
        var key=record(7,1,NOW).key();var node=new DhtNode<DiscoveryRecord>(DhtIdTest.id(0),f.wall,f.nanos::get,(destination,request)->{
            assertEquals("DHTの処理を重ねて呼べません",assertThrows(IllegalStateException.class,()->reference.get().findValue(key,policy,policy)).getMessage());return true;
        },policy,policy);reference.set(node);node.observe(peer(1));
        assertEquals("DHTの検査器が必要です",assertThrows(NullPointerException.class,()->node.findValue(key,null,policy)).getMessage());
        assertEquals("DHTの比較が必要です",assertThrows(NullPointerException.class,()->node.findValue(key,policy,null)).getMessage());
        assertEquals("DHTの番号が必要です",assertThrows(NullPointerException.class,()->node.findValue(null,policy,policy)).getMessage());
        assertEquals(0,node.activeLookups());for(int n=0;n<4;n++)node.findValue(key,f.store.newLookupVerifier(),policy);
        node.poll();assertEquals(4,node.activeLookups());assertThrows(IllegalStateException.class,()->node.findValue(key,policy,policy));
    }
    @Test void perLookupVerificationFailuresRemainRejectionsRatherThanEscapingTheNode() throws Exception {
        var f=new DiscoveryStoreTest.Fixture();var delivery=new DhtNodeTest.Delivery();delivery.introduce(List.of(contact(1)));
        var node=new DhtNode<DiscoveryRecord>(DhtIdTest.id(0),f.wall,f.nanos::get,delivery,(key,raw,clock)->null,(a,b)->0);
        node.observe(peer(1));var policy=f.store.newLookupVerifier();var lookup=node.findValue(record(7,1,NOW).key(),policy,policy);node.poll();
        assertDoesNotThrow(()->node.receive(peer(1),delivery.take().request().id(),List.of(),new byte[]{0}));node.poll();
        assertTrue(lookup.result().value().isEmpty());assertEquals(1,policy.counts().count(DiscoveryStatus.INVALID));released(lookup);
    }
    /** 探索が終わると、その探索の件数が預かりの表の件数へ 1 回だけ足される（終わるまでは足さない）。 */
    @Test void aFinishedLookupAddsItsCountsToTheStoreExactlyOnce() {
        var f=new DiscoveryStoreTest.Fixture();var delivery=new DhtNodeTest.Delivery();delivery.introduce(List.of(contact(1)));
        f.put(record(7,3,NOW));
        var node=new DhtNode<DiscoveryRecord>(DhtIdTest.id(0),f.wall,f.nanos::get,delivery,(key,raw,clock)->null,(a,b)->0);
        node.observe(peer(1));var policy=f.store.newLookupVerifier();var lookup=node.findValue(record(7,1,NOW).key(),policy,policy);node.poll();
        var sent=delivery.take();
        node.receive(AuthenticatedPeer.fromVerifiedDhtResponse(sent.destination()),sent.request().id(),List.of(),record(7,2,NOW).encode());
        assertEquals(1,policy.counts().count(DiscoveryStatus.OLD_VERSION));
        assertEquals(0,f.store.counts().count(DiscoveryStatus.OLD_VERSION));
        node.poll();
        assertTrue(lookup.done());
        assertEquals(1,f.store.counts().count(DiscoveryStatus.OLD_VERSION));
        node.poll();node.poll();
        assertEquals(1,f.store.counts().count(DiscoveryStatus.OLD_VERSION));
    }
}
