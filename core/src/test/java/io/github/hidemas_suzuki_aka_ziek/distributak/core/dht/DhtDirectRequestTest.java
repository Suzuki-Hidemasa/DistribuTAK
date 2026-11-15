// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 直接つながった1人の相手への FIND_VALUE（findValueFrom）と、結果を返す STORE（store(…,done)）。
 * 結果は1回だけ渡し、記録は預かりの表に入れない。試験の失敗の文にも、番地・端末の番号・鍵・線の中身は出さない。
 */
class DhtDirectRequestTest {
    /** 相手 p[1] が、p[0] の記録（版 1）を預かった状態にする。 */
    static Rig[] pairWithStoredRecord(Net net) {
        var p=pair(net);
        assertTrue(p[0].dispatcher.store(p[1].contact(),record(1,1,NOW).encode()));net.pump();
        assertEquals(1,p[1].store.size());
        return p;
    }
    static final class Seen<T> {
        final List<T> values=new ArrayList<>();
        void accept(T value){values.add(value);}
    }
    static byte[] takeRequestId(Net net){return net.queue.poll().message().requestId();}

    // ---- findValueFrom ----

    @Test void aVerifiedValueFromThePeerIsPassedOnceAndIsNotPutInTheLocalStore() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        net.pump();
        assertEquals(1,seen.values.size());assertNotNull(seen.values.get(0));
        assertEquals(key,seen.values.get(0).key());assertEquals(1,seen.values.get(0).version());
        assertEquals(0,p[0].store.size(),"The reply must not be put in the local store");
        assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void nothingIsSentAndNoResultIsGivenWhenThePeerIsNotYes() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var c=net.rig(DhtIdTest.id(3));Seen<DiscoveryRecord> seen=new Seen<>();
        assertFalse(a.dispatcher.findValueFrom(c.contact(),record(1,1,NOW).key(),seen::accept));
        assertTrue(net.sent.isEmpty());assertTrue(seen.values.isEmpty());assertEquals(0,a.dispatcher.pendingCount());
    }
    @Test void aSendFailureReturnsFalseAndLeavesNothingPending() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        p[0].sendOk=false;
        assertFalse(p[0].dispatcher.findValueFrom(p[1].contact(),record(1,1,NOW).key(),seen::accept));
        assertEquals(0,p[0].dispatcher.pendingCount());assertTrue(seen.values.isEmpty());
    }
    @Test void aNodesReplyEndsTheWaitWithNoRecord() {
        var net=new Net();var p=pair(net);Seen<DiscoveryRecord> seen=new Seen<>();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),record(1,1,NOW).key(),seen::accept));
        net.pump();
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void aValueWhoseRecordHasAnotherKeyOrIsTamperedWithGivesNoRecord() {
        var net=new Net();var p=pair(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid,key,record(2,1,NOW).encode())));
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0),"A record of another key is not the answer");

        Seen<DiscoveryRecord> second=new Seen<>();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,second::accept));
        var rid2=takeRequestId(net);
        byte[] bad=record(1,1,NOW).encode();bad[bad.length-1]^=1;
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid2,key,bad)));
        assertEquals(1,second.values.size());assertNull(second.values.get(0),"A tampered record fails verification");
        assertEquals(0,p[0].store.size());
    }
    @Test void anExpiredRecordGivesNoRecord() {
        var net=new Net();var p=pair(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        p[0].wall.millis=record(1,1,NOW).expiresAt()+1;
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid,key,record(1,1,NOW).encode())));
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));
    }
    @Test void aReplyFromAnotherSessionStaysPendingAndEndsWithNullAtExpiry() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        net.deliver(new Packet(p[1],p[0],OTHER_SESSION,DhtWire.value(GROUP,rid,key,record(1,1,NOW).encode())));
        assertTrue(seen.values.isEmpty(),"A mismatched reply does not end the wait");
        assertEquals(1,p[0].dispatcher.statistics().mismatched());
        net.advance(DhtLimits.RPC_NANOS+1);
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void noReplyEndsWithNullOnceAtExpiry() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),record(1,1,NOW).key(),seen::accept));
        net.queue.poll();
        net.advance(DhtLimits.RPC_NANOS+1);net.advance(SECOND);
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));
    }
    @Test void aReplyAfterTheDeadlineGivesNullOnce() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        net.nanos.addAndGet(DhtLimits.RPC_NANOS+1); // poll を呼ばずに時間だけ進める
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid,key,record(1,1,NOW).encode())));
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));
        net.advance(SECOND);assertEquals(1,seen.values.size());
    }
    @Test void aReplyBoundToAnotherGenerationGivesNullOnce() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        p[0].peerGeneration=5;
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid,key,record(1,1,NOW).encode())));
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));assertEquals(1,p[0].dispatcher.statistics().stale());
    }
    @Test void aNetworkChangeOrAForgottenPeerDropsTheWaitWithNullOnce() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        Seen<DiscoveryRecord> forgotten=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        net.queue.poll();
        p[0].network();
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));assertEquals(0,p[0].dispatcher.pendingCount());
        net.connect(p[0],p[1]);
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,forgotten::accept));
        net.queue.poll();
        p[0].dispatcher.volatilePeerForgotten(p[1].id.bytes());
        assertEquals(1,forgotten.values.size());assertNull(forgotten.values.get(0));assertEquals(0,p[0].dispatcher.pendingCount());
        net.advance(DhtLimits.RPC_NANOS+SECOND);assertEquals(1,seen.values.size());assertEquals(1,forgotten.values.size());
    }
    @Test void aSecondReplyWithTheSameRequestIdIsDroppedAsUnsolicited() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        var reply=new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid,key,record(1,1,NOW).encode()));
        long before=p[0].dispatcher.statistics().unsolicited();
        net.deliver(reply);net.deliver(reply);
        assertEquals(1,seen.values.size());assertNotNull(seen.values.get(0));
        assertEquals(before+1,p[0].dispatcher.statistics().unsolicited());
    }
    @Test void aCallbackThatThrowsDoesNotBreakTheDispatcher() {
        var net=new Net();var p=pairWithStoredRecord(net);
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,r->{throw new IllegalStateException();}));
        net.pump();
        assertEquals(0,p[0].dispatcher.pendingCount());
        Seen<DiscoveryRecord> seen=new Seen<>();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));net.pump();
        assertEquals(1,seen.values.size());assertNotNull(seen.values.get(0));
    }
    @Test void directRequestsCountInTheSamePendingAndPerPeerLimits() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        for(int i=0;i<DhtDispatcher.MAX_PENDING_PER_PEER;i++) {
            assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept),"request "+i);
        }
        assertFalse(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
                assertEquals(DhtDispatcher.MAX_PENDING_PER_PEER,p[0].dispatcher.pendingCount());
        assertTrue(seen.values.isEmpty());
    }
    @Test void aDirectWaitDoesNotTakeALargeTransferAsItsAnswer() {
        var net=new Net();var p=pairWithStoredRecord(net);Seen<DiscoveryRecord> seen=new Seen<>();
        var key=record(1,1,NOW).key();
        assertTrue(p[0].dispatcher.findValueFrom(p[1].contact(),key,seen::accept));
        var rid=takeRequestId(net);
        byte[] data=new byte[2500];
        p[1].dispatcher.transfers().start(p[0].id,SESSION,DhtWire.TransferKind.VALUE,rid,data);
        net.run(50);
        assertTrue(p[0].sunk.isEmpty(),"A direct wait does not receive a large transfer");
        assertTrue(seen.values.isEmpty());
        net.advance(DhtLimits.RPC_NANOS+1);
        assertEquals(1,seen.values.size());assertNull(seen.values.get(0));
    }

    // ---- store(…, done) ----

    @Test void acceptedAndDuplicateGiveTrueAndAnotherMemberRecordGivesFalse() {
        var net=new Net();var p=pair(net);Seen<Boolean> first=new Seen<>();
        Seen<Boolean> again=new Seen<>();
        Seen<Boolean> other=new Seen<>();
        var r=record(1,1,NOW).encode();
        assertTrue(p[0].dispatcher.store(p[1].contact(),r,first::accept));net.pump();
        assertEquals(List.of(true),first.values);
        assertTrue(p[0].dispatcher.store(p[1].contact(),r,again::accept));net.pump();
        assertEquals(List.of(true),again.values,"DUPLICATE counts as received");
        assertTrue(p[0].dispatcher.store(p[1].contact(),record(2,1,NOW).encode(),other::accept));net.pump();
        assertEquals(List.of(false),other.values);
        assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void storeThatCannotSendReturnsFalseAndNeverCallsDone() {
        var net=new Net();var p=pair(net);var c=net.rig(DhtIdTest.id(3));Seen<Boolean> seen=new Seen<>();
        assertFalse(p[0].dispatcher.store(p[1].contact(),new byte[]{1,2,3},seen::accept));
        assertFalse(p[0].dispatcher.store(c.contact(),record(1,1,NOW).encode(),seen::accept));
        p[0].sendOk=false;
        assertFalse(p[0].dispatcher.store(p[1].contact(),record(1,1,NOW).encode(),seen::accept));
        assertEquals(0,p[0].dispatcher.pendingCount());assertTrue(seen.values.isEmpty());
    }
    @Test void aDroppedStoreWaitGivesNullOnceForExpiryGenerationNetworkAndForgottenPeer() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW).encode();
        Seen<Boolean> expiry=new Seen<>();
        Seen<Boolean> generation=new Seen<>();
        Seen<Boolean> network=new Seen<>();
        Seen<Boolean> forgotten=new Seen<>();
        assertTrue(p[0].dispatcher.store(p[1].contact(),r,expiry::accept));net.queue.poll();
        net.advance(DhtLimits.RPC_NANOS+1);
        assertEquals(1,expiry.values.size());assertNull(expiry.values.get(0));

        assertTrue(p[0].dispatcher.store(p[1].contact(),r,generation::accept));var rid=takeRequestId(net);
        p[0].peerGeneration=5;
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.storeResult(GROUP,rid,record(1,1,NOW).key(),DhtWire.StoreStatus.ACCEPTED)));
        assertEquals(1,generation.values.size());assertNull(generation.values.get(0));
        p[0].peerGeneration=AuthenticatedPeer.UNBOUND;

        assertTrue(p[0].dispatcher.store(p[1].contact(),r,network::accept));net.queue.poll();
        p[0].network();
        assertEquals(1,network.values.size());assertNull(network.values.get(0));
        net.connect(p[0],p[1]);

        assertTrue(p[0].dispatcher.store(p[1].contact(),r,forgotten::accept));net.queue.poll();
        p[0].dispatcher.volatilePeerForgotten(p[1].id.bytes());
        assertEquals(1,forgotten.values.size());assertNull(forgotten.values.get(0));
        net.advance(DhtLimits.RPC_NANOS+SECOND);
        assertEquals(1,expiry.values.size());assertEquals(1,network.values.size());assertEquals(1,forgotten.values.size());
    }
    @Test void aSecondStoreResultWithTheSameRequestIdIsDroppedAndDoneIsCalledOnce() {
        var net=new Net();var p=pair(net);Seen<Boolean> seen=new Seen<>();var r=record(1,1,NOW);
        assertTrue(p[0].dispatcher.store(p[1].contact(),r.encode(),seen::accept));
        var rid=takeRequestId(net);
        var reply=new Packet(p[1],p[0],SESSION,DhtWire.storeResult(GROUP,rid,r.key(),DhtWire.StoreStatus.ACCEPTED));
        net.deliver(reply);net.deliver(reply);
        assertEquals(List.of(true),seen.values);
    }
    @Test void thePublisherListenerAndTheDirectStoreResultNeverMix() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        List<DhtWire.StoreStatus> told=new ArrayList<>();Seen<Boolean> direct=new Seen<>();
        p[0].dispatcher.setStoreListener((peer,status)->told.add(status));
        assertTrue(p[0].dispatcher.store(p[1].contact(),r.encode(),direct::accept));net.pump();
        assertEquals(List.of(true),direct.values);assertTrue(told.isEmpty(),"A direct STORE must not reach the publisher listener");
        assertTrue(p[0].dispatcher.store(p[1].contact(),r.encode()));net.pump();
        assertEquals(1,told.size());assertEquals(1,direct.values.size(),"A publisher STORE must not call the direct callback");
    }
}
