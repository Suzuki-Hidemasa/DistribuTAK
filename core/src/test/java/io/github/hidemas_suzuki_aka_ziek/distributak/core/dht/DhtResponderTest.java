// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryStatus.*;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C1: 相手の DHT 要求に答える側と、署名の計算の前の速度の上限。 */
class DhtResponderTest {
    static final long SECOND=1_000_000_000L;
    static final class Fixture {
        final DhtNodeTest.Fixture core=new DhtNodeTest.Fixture();final AtomicLong nanos=core.nanos;
        final Set<DhtId> revoked=new HashSet<>();final DiscoveryStore store;final DhtResponder responder;
        Fixture() {
            core.wall.millis=NOW;store=new DiscoveryStore(GROUP,core.wall,nanos::get,revoked::contains);
            responder=new DhtResponder(core.node,store,nanos::get);
        }
        DhtResponder.Response answer(AuthenticatedPeer peer,DhtResponder.Request request) {
            return responder.answer(peer,request).orElseThrow();
        }
    }
    static AuthenticatedPeer peer(int number){return AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(DhtIdTest.id(number)));}
    static AuthenticatedPeer peer(int number,long generation){return AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(DhtIdTest.id(number)),generation);}

    @Test void pingGetsPongWithTheSameRequestNumber() {
        var f=new Fixture();var response=f.answer(peer(1),DhtResponder.Request.ping(77));
        assertEquals(DhtResponder.Kind.PONG,response.kind());assertEquals(77,response.id());
    }
    @Test void findNodeReturnsTheNearestKnownPeersWithoutTheAskerItself() {
        var f=new Fixture();f.core.seed(1,2,3,4);
        var response=f.answer(peer(1),DhtResponder.Request.findNode(5,DhtIdTest.id(2)));
        assertEquals(DhtResponder.Kind.NODES,response.kind());
        assertEquals(3,response.contacts().size());
        assertEquals(DhtIdTest.id(2),response.contacts().get(0).id());
        for(Contact c:response.contacts())assertNotEquals(DhtIdTest.id(1),c.id());
    }
    @Test void findNodeNeverReturnsMoreThanKContacts() {
        var f=new Fixture();for(int n=1;n<=60;n++)f.core.seed(n);
        var response=f.answer(peer(1000),DhtResponder.Request.findNode(1,DhtIdTest.id(0)));
        assertTrue(response.contacts().size()<=DhtLimits.K);
    }
    @Test void findValueReturnsAValidStoredRecordOtherwiseTheSameNeighbours() {
        var f=new Fixture();f.core.seed(1,2);var r=record(1,1,NOW);
        assertEquals(ACCEPTED,f.store.put(DiscoveryStoreTest.publisher(r),r.encode()));
        var hit=f.answer(peer(2),DhtResponder.Request.findValue(9,r.key()));
        assertEquals(DhtResponder.Kind.VALUE,hit.kind());assertArrayEquals(r.encode(),hit.record());
        var miss=f.answer(peer(2),DhtResponder.Request.findValue(10,DhtIdTest.id(99)));
        assertEquals(DhtResponder.Kind.NODES,miss.kind());assertNull(miss.record());assertFalse(miss.contacts().isEmpty());
    }
    @Test void storeReturnsTheStoreStatusAndNoFreeText() {
        var f=new Fixture();var r=record(1,1,NOW);
        var first=f.answer(DiscoveryStoreTest.publisher(r),DhtResponder.Request.store(1,r.encode()));
        assertEquals(DhtResponder.Kind.STORE_RESULT,first.kind());assertEquals(ACCEPTED,first.status());
        assertEquals(DUPLICATE,f.answer(DiscoveryStoreTest.publisher(r),DhtResponder.Request.store(2,r.encode())).status());
        assertEquals(SENDER_MISMATCH,f.answer(peer(5),DhtResponder.Request.store(3,r.encode())).status());
        assertEquals(1,f.store.size());
    }
    @Test void malformedStoreIsAnsweredInvalidWithoutUsingARateToken() {
        var f=new Fixture();var p=peer(1);
        for(int i=0;i<DhtResponder.PEER_BURST*3;i++) {
            var response=f.answer(p,DhtResponder.Request.store(i+1,new byte[]{1,2,3}));
            assertEquals(INVALID,response.status());
        }
        assertEquals(0,f.responder.rateLimited());
        assertTrue(f.answer(p,DhtResponder.Request.ping(1)).kind()==DhtResponder.Kind.PONG);
        assertEquals(INVALID,f.answer(p,DhtResponder.Request.store(1,new byte[DiscoveryRecord.MAX_BYTES+1])).status());
        assertEquals(INVALID,f.answer(p,DhtResponder.Request.store(1,null)).status());
    }
    @Test void aPeerOverItsBucketGetsNoAnswerAndTheCountIsKeptSeparately() {
        var f=new Fixture();var p=peer(1);
        for(int i=0;i<DhtResponder.PEER_BURST;i++)assertTrue(f.responder.answer(p,DhtResponder.Request.ping(i+1)).isPresent());
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(99)).isEmpty());
        assertEquals(1,f.responder.rateLimited());assertEquals(0,f.store.counts().screenRejected());
        // 毎秒 10 件の割合で戻る。
        f.nanos.addAndGet(SECOND/2);
        for(int i=0;i<5;i++)assertTrue(f.responder.answer(p,DhtResponder.Request.ping(i+1)).isPresent());
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(100)).isEmpty());
    }
    @Test void oneBucketIsSharedByAllFourKindsOfRequest() {
        var f=new Fixture();var r=record(1,1,NOW);var p=DiscoveryStoreTest.publisher(r);int n=0;
        for(int i=0;i<DhtResponder.PEER_BURST/4;i++) {
            assertTrue(f.responder.answer(p,DhtResponder.Request.ping(++n)).isPresent());
            assertTrue(f.responder.answer(p,DhtResponder.Request.findNode(++n,DhtIdTest.id(1))).isPresent());
            assertTrue(f.responder.answer(p,DhtResponder.Request.findValue(++n,r.key())).isPresent());
            assertTrue(f.responder.answer(p,DhtResponder.Request.store(++n,r.encode())).isPresent());
        }
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(++n)).isEmpty());
        assertTrue(f.responder.answer(p,DhtResponder.Request.findNode(++n,DhtIdTest.id(1))).isEmpty());
        assertTrue(f.responder.answer(p,DhtResponder.Request.findValue(++n,r.key())).isEmpty());
        assertTrue(f.responder.answer(p,DhtResponder.Request.store(++n,r.encode())).isEmpty());
    }
    @Test void anOverLimitStoreDoesNotComputeASignatureOrTouchTheStore() {
        var f=new Fixture();var good=record(1,1,NOW);var p=DiscoveryStoreTest.publisher(good);
        for(int i=0;i<DhtResponder.PEER_BURST;i++)f.responder.answer(p,DhtResponder.Request.ping(i+1));
        // 署名が正しい記録でも、上限を超えたら預からない（署名の計算より前に捨てる）。
        assertTrue(f.responder.answer(p,DhtResponder.Request.store(1,good.encode())).isEmpty());
        assertEquals(0,f.store.size());assertEquals(0,f.store.counts().count(INVALID));
        // 偽の署名の記録も同じ。署名の失敗を数えない（計算していない）。
        byte[] forged=good.encode();forged[forged.length-1]^=1;
        assertTrue(f.responder.answer(p,DhtResponder.Request.store(2,forged)).isEmpty());
        assertEquals(0,f.store.counts().count(INVALID));
        f.nanos.addAndGet(SECOND);
        assertEquals(INVALID,f.answer(p,DhtResponder.Request.store(3,forged)).status());
        assertEquals(1,f.store.counts().count(INVALID));
    }
    @Test void theTotalBucketLimitsAllPeersTogetherAndLimitedPeersDoNotDrainIt() {
        var f=new Fixture();int accepted=0;
        // 各相手は瞬間 20 件までなので、20 台で 400 件を試すと全体の 200 件で止まる。
        for(int peerNumber=1;peerNumber<=20;peerNumber++)
            for(int i=0;i<DhtResponder.PEER_BURST;i++)
                if(f.responder.answer(peer(peerNumber),DhtResponder.Request.ping(i+1)).isPresent())accepted++;
        assertEquals(DhtResponder.TOTAL_BURST,accepted);
        // 全体が空になると、新しい相手も答えてもらえない。
        assertTrue(f.responder.answer(peer(500),DhtResponder.Request.ping(1)).isEmpty());
        // 1 台が自分の上限を超えて叩いても、全体の袋は減らない。
        var g=new Fixture();var p=peer(1);
        for(int i=0;i<DhtResponder.PEER_BURST;i++)g.responder.answer(p,DhtResponder.Request.ping(i+1));
        for(int i=0;i<1000;i++)assertTrue(g.responder.answer(p,DhtResponder.Request.ping(i+1)).isEmpty());
        int others=0;
        for(int peerNumber=2;peerNumber<=11;peerNumber++)
            for(int i=0;i<DhtResponder.PEER_BURST;i++)
                if(g.responder.answer(peer(peerNumber),DhtResponder.Request.ping(i+1)).isPresent())others++;
        assertEquals(DhtResponder.TOTAL_BURST-DhtResponder.PEER_BURST,others);
    }
    @Test void theTotalBucketRefillsAtTheTotalRate() {
        var f=new Fixture();
        for(int peerNumber=1;peerNumber<=10;peerNumber++)
            for(int i=0;i<DhtResponder.PEER_BURST;i++)f.responder.answer(peer(peerNumber),DhtResponder.Request.ping(i+1));
        f.nanos.addAndGet(SECOND);int accepted=0;
        for(int peerNumber=11;peerNumber<=20;peerNumber++)
            for(int i=0;i<DhtResponder.PEER_BURST;i++)
                if(f.responder.answer(peer(peerNumber),DhtResponder.Request.ping(i+1)).isPresent())accepted++;
        assertEquals(DhtResponder.TOTAL_PER_SECOND,accepted);
    }
    @Test void aClockThatGoesBackNeitherRefillsNorBreaksTheBuckets() {
        var f=new Fixture();var p=peer(1);f.nanos.set(100*SECOND);
        for(int i=0;i<DhtResponder.PEER_BURST;i++)f.responder.answer(p,DhtResponder.Request.ping(i+1));
        f.nanos.set(10*SECOND);
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(99)).isEmpty());
        f.nanos.set(11*SECOND);
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(100)).isPresent());
    }
    @Test void aVeryLongIdleTimeGivesOnlyTheBurst() {
        var f=new Fixture();var p=peer(1);
        f.nanos.set(Long.MAX_VALUE/2);int accepted=0;
        for(int i=0;i<DhtResponder.PEER_BURST*3;i++)if(f.responder.answer(p,DhtResponder.Request.ping(i+1)).isPresent())accepted++;
        assertEquals(DhtResponder.PEER_BURST,accepted);
    }
    @Test void theNumberOfRememberedPeerBucketsIsBounded() {
        var f=new Fixture();
        for(int peerNumber=1;peerNumber<=DhtResponder.MAX_PEER_BUCKETS*4;peerNumber++){
            f.nanos.addAndGet(SECOND);f.responder.answer(peer(peerNumber),DhtResponder.Request.ping(1));
        }
        assertTrue(f.responder.peerBuckets()<=DhtResponder.MAX_PEER_BUCKETS);
    }
    @Test void forgettingAPeerDropsOnlyItsBucketAndLeavesTheTotalBucketAlone() {
        var f=new Fixture();var p=peer(1);var q=peer(2);
        for(int i=0;i<DhtResponder.PEER_BURST;i++)f.responder.answer(p,DhtResponder.Request.ping(i+1));
        f.responder.answer(q,DhtResponder.Request.ping(1));
        assertEquals(2,f.responder.peerBuckets());
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(99)).isEmpty());
        f.responder.forget(p.id());
        assertEquals(1,f.responder.peerBuckets());
        // 袋が空になった相手を消して作り直すと、新しい袋（瞬間 20）で始まる。
        for(int i=0;i<DhtResponder.PEER_BURST;i++)assertTrue(f.responder.answer(p,DhtResponder.Request.ping(i+1)).isPresent());
        // 知らない相手を消しても何も起きない。他の相手の袋は残る。
        f.responder.forget(DhtIdTest.id(200));
        assertEquals(2,f.responder.peerBuckets());
        assertThrows(NullPointerException.class,()->f.responder.forget(null));
    }
    @Test void aPeerRequestWithASmallNumberIsStillAnsweredAfterTheNetworkChanged() {
        var f=new Fixture();f.core.node.networkChanged();f.core.node.networkChanged();
        // 自分が付けた番号の境目（networkFloor）は相手の要求に使わない。
        var response=f.answer(peer(1,f.core.node.generation()),DhtResponder.Request.ping(1));
        assertEquals(DhtResponder.Kind.PONG,response.kind());assertEquals(1,response.id());
    }
    @Test void aRequestFromAnOldGenerationIsDroppedAndNotCountedAsRateLimited() {
        var f=new Fixture();var old=peer(1,0);f.core.node.networkChanged();
        assertTrue(f.responder.answer(old,DhtResponder.Request.ping(1)).isEmpty());
        assertEquals(1,f.responder.staleDropped());assertEquals(0,f.responder.rateLimited());
        assertEquals(0,f.core.node.routing().size());
        assertTrue(f.responder.answer(peer(1,1),DhtResponder.Request.ping(1)).isPresent());
    }
    @Test void anAnsweredRequestIsEvidenceThatThePeerIsAlive() {
        var f=new Fixture();assertEquals(0,f.core.node.routing().size());
        f.answer(peer(1),DhtResponder.Request.ping(1));assertEquals(1,f.core.node.routing().size());
    }
    @Test void aDroppedRequestDoesNotTouchTheRoutingTable() {
        var f=new Fixture();var p=peer(1);
        for(int i=0;i<DhtResponder.PEER_BURST;i++)f.responder.answer(p,DhtResponder.Request.ping(i+1));
        f.core.node.routing().clear();
        assertTrue(f.responder.answer(p,DhtResponder.Request.ping(99)).isEmpty());
        assertEquals(0,f.core.node.routing().size());
    }
    @Test void findValueChecksExpiryAndRevocationOfTheRecordItReturns() {
        var f=new Fixture();f.core.seed(2);var r=record(1,1,NOW);f.store.put(DiscoveryStoreTest.publisher(r),r.encode());
        f.revoked.add(r.nodeId());
        var response=f.answer(peer(2),DhtResponder.Request.findValue(1,r.key()));
        assertEquals(DhtResponder.Kind.NODES,response.kind());assertNull(response.record());
        var g=new Fixture();g.core.seed(2);var s=record(3,1,NOW);g.store.put(DiscoveryStoreTest.publisher(s),s.encode());
        g.core.wall.millis=NOW+DhtLimits.RECORD_LIFETIME_MILLIS;
        assertEquals(DhtResponder.Kind.NODES,g.answer(peer(2),DhtResponder.Request.findValue(1,s.key())).kind());
    }
    @Test void requestsRefuseMissingParts() {
        assertThrows(NullPointerException.class,()->DhtResponder.Request.findNode(1,null));
        assertThrows(NullPointerException.class,()->DhtResponder.Request.findValue(1,null));
        var f=new Fixture();
        assertThrows(NullPointerException.class,()->f.responder.answer(null,DhtResponder.Request.ping(1)));
        assertThrows(NullPointerException.class,()->f.responder.answer(peer(1),null));
    }
    @Test void textOfTheResponderAndItsMessagesShowsNothingSecret() {
        var f=new Fixture();var response=f.answer(peer(1),DhtResponder.Request.ping(1));
        for(String text:new String[]{f.responder.toString(),response.toString(),DhtResponder.Request.ping(1).toString()}) {
            assertFalse(text.contains(DhtIdTest.id(1).toString()));assertTrue(text.length()<60);
        }
    }
}
