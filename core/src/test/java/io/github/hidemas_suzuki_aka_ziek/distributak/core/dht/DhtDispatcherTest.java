// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 C2: DHT の線の形と核の間の配送側。2〜10 台を時計と待ち行列でつないで、要求・応答・探り・ページ分け・保留の結び付けを確かめる。
 * 試験の失敗の文にも、番地・端末の番号・鍵・線の中身は出さない。
 */
class DhtDispatcherTest {
    static final long SECOND=1_000_000_000L;
    static final byte[] SESSION=filled(16,7),OTHER_SESSION=filled(16,9);
    static byte[] filled(int n,int v){byte[] b=new byte[n];Arrays.fill(b,(byte)v);return b;}

    record Packet(Rig from,Rig to,byte[] session,byte[] wire) {
        DhtWire.Message message(){return DhtWire.parse(wire);}
    }
    record Sunk(DhtId peer,DhtWire.TransferKind kind,byte[] data){}

    static final class Net {
        final AtomicLong nanos=new AtomicLong(1_000*SECOND);
        final Map<DhtId,Rig> rigs=new HashMap<>();
        final ArrayDeque<Packet> queue=new ArrayDeque<>();
        final List<Packet> sent=new ArrayList<>();
        final Set<DhtId> dropTo=new HashSet<>();
        Rig rig(DhtId id){return rig(id,new Random(1));}
        Rig rig(DhtId id,Random rng){Rig r=new Rig(this,id,rng);rigs.put(id,r);return r;}
        void deliver(Packet p){p.to.dispatcher.receive(p.from.id.bytes(),p.session,p.wire);}
        void pump() {
            int n=0;
            while(!queue.isEmpty()) {
                if(n++>20_000)throw new AssertionError("Delivery loop");
                deliver(queue.poll());
            }
        }
        void advance(long nanosToAdd){nanos.addAndGet(nanosToAdd);for(Rig r:new ArrayList<>(rigs.values()))r.dispatcher.poll();}
        void run(int rounds){for(int i=0;i<rounds;i++){pump();advance(10_000_000L);}}
        void connect(Rig a,Rig b) {
            a.dispatcher.sessionStarted(b.id.bytes(),SESSION);b.dispatcher.sessionStarted(a.id.bytes(),SESSION);pump();
        }
        int count(Rig from,Rig to,DhtWire.Op op) {
            int n=0;
            for(Packet p:sent)if(p.from==from&&p.to==to&&p.message().op()==op)n++;
            return n;
        }
    }

    static final class Rig {
        final Net net;final DhtId id;final DhtNodeTest.Wall wall=new DhtNodeTest.Wall();
        final DhtNode<Integer> node;final DiscoveryStore store;final DhtResponder responder;final DhtDispatcher dispatcher;
        final Set<DhtId> revoked=new HashSet<>();
        final Map<DhtId,DhtWire.NodeContact> directory=new HashMap<>();
        final List<Sunk> sunk=new ArrayList<>();
        boolean sendOk=true,slotFree=true,startAllowed=true,usePrepare;
        /** 保存した相手（手放せない）と、手放した相手（セッションが閉じたので authenticated が null を返す）。 */
        final Set<DhtId> storedPeers=new HashSet<>(),goneSessions=new HashSet<>();
        final List<DhtId> released=new ArrayList<>();
        long peerGeneration=AuthenticatedPeer.UNBOUND;
        DhtId claimAs;
        Rig(Net net,DhtId id,Random rng) {this(net,id,rng,GROUP);}
        Rig(Net net,DhtId id,Random rng,byte[] group) {
            this.net=net;this.id=id;wall.millis=NOW;
            DhtDispatcher[] holder=new DhtDispatcher[1];
            DhtTransport transport=new DhtTransport() {
                @Override public boolean send(Contact destination,Request request){return holder[0].send(destination,request);}
                /** 握手を受け持つ試験（核 D の冷えた探索）だけ、本物の prepare を通す。既定は従来どおり READY。 */
                @Override public Readiness prepare(Contact destination){return usePrepare?holder[0].prepare(destination):Readiness.READY;}
                /** 探索が「初めての BUSY」を知らせる口。本物の prepare を通すときだけ、理由別の件数へつなぐ。 */
                @Override public void firstBusy(Contact destination){if(usePrepare)holder[0].firstBusy(destination);}
            };
            node=new DhtNode<>(id,wall,net.nanos::get,transport,
                (key,bytes,clock)->{if(bytes.length==0)throw new SecurityException("Invalid test value");return bytes.length;},Integer::compare);
            store=new DiscoveryStore(group,wall,net.nanos::get,revoked::contains);
            responder=new DhtResponder(node,store,net.nanos::get);
            DhtLink link=new DhtLink() {
                @Override public AuthenticatedPeer authenticated(byte[] peerId,byte[] sessionId) {
                    if(peerId.length!=32)return null;
                    DhtId peer=new DhtId(peerId);
                    if(!net.rigs.containsKey(peer)||goneSessions.contains(peer))return null;
                    Contact contact=new Contact(claimAs!=null?claimAs:peer);
                    return peerGeneration==AuthenticatedPeer.UNBOUND?AuthenticatedPeer.fromVerifiedDhtResponse(contact)
                        :AuthenticatedPeer.fromVerifiedDhtResponse(contact,peerGeneration);
                }
                @Override public boolean send(byte[] peerId,byte[] sessionId,byte[] plaintext) {
                    if(!sendOk)return false;
                    Rig to=net.rigs.get(new DhtId(peerId));
                    Packet packet=new Packet(Rig.this,to,sessionId.clone(),plaintext.clone());
                    net.sent.add(packet);
                    if(to!=null&&!net.dropTo.contains(to.id))net.queue.add(packet);
                    return true;
                }
                @Override public boolean releaseVolatile(byte[] peerId) {
                    DhtId peer=new DhtId(peerId);
                    if(storedPeers.contains(peer)||!net.rigs.containsKey(peer)||goneSessions.contains(peer))return false;
                    goneSessions.add(peer);released.add(peer);return true;
                }
                @Override public boolean volatileSlotFree(){return slotFree;}
                @Override public boolean startAllowed(){return startAllowed;}
            };
            dispatcher=new DhtDispatcher(group,node,responder,store,link,peerId->directory.get(peerId),
                (peer,kind,data)->sunk.add(new Sunk(peer,kind,data.clone())),net.nanos::get,rng,DhtTransfers.Limits.defaults());
            holder[0]=dispatcher;
        }
        Contact contact(){return new Contact(id);}
        void network() {
            dispatcher.networkChanged(1,new LocalNetwork(new byte[]{(byte)192,(byte)168,1,2},24));
        }
    }

    static DhtWire.NodeContact nodeContact(int n) {
        return new DhtWire.NodeContact(DhtIdTest.id(n),HANDSHAKE,new byte[]{(byte)192,(byte)168,1,(byte)(10+n)},50000);
    }
    static DhtTransport.Request request(long id,DhtTransport.Operation op,DhtId target){return new DhtTransport.Request(id,op,target);}
    static DhtTransport.Request ping(long id){return request(id,DhtTransport.Operation.PING,DhtIdTest.id(0));}
    static void seed(Rig r,int from,int to) {
        for(int n=from;n<=to;n++){r.node.observe(DhtResponderTest.peer(n));r.directory.put(DhtIdTest.id(n),nodeContact(n));}
    }
    static DhtNode<Integer>.Lookup drive(Net net,Rig origin,DhtNode<Integer>.Lookup lookup) {
        for(int i=0;i<60&&!lookup.done();i++){origin.node.poll();net.pump();net.advance(SECOND/10);}
        return lookup;
    }
    static Rig[] pair(Net net) {
        Rig a=net.rig(record(1,1,NOW).nodeId()),b=net.rig(DhtIdTest.id(2));net.connect(a,b);return new Rig[]{a,b};
    }

    // ---- 相手を見つけて握手する（探り） ----

    @Test void bothSidesBecomeYesAndEnterTheRoutingTableAfterTheProbes() {
        var net=new Net();var p=pair(net);
        assertTrue(p[0].dispatcher.peers().isYes(p[1].id));assertTrue(p[1].dispatcher.peers().isYes(p[0].id));
        assertEquals(1,p[0].node.routing().size());assertEquals(1,p[1].node.routing().size());
        assertEquals(0,p[0].dispatcher.pendingCount());assertEquals(0,p[1].dispatcher.pendingCount());
    }
    @Test void nothingIsSentToAPeerThatIsNotYes() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var b=net.rig(DhtIdTest.id(2));
        assertFalse(a.dispatcher.send(b.contact(),ping(1)));
        assertTrue(net.sent.isEmpty());
    }
    @Test void noRequestOfAnyKindIsSentToAPeerThatIsNotYes() {
        var net=new Net();var a=net.rig(record(1,1,NOW).nodeId());var b=net.rig(DhtIdTest.id(2));
        // b とは握手していない（YES ではない）。探り（PING）以外は何も送らない。
        assertFalse(a.dispatcher.send(b.contact(),request(1,DhtTransport.Operation.FIND_NODE,DhtIdTest.id(5))));
        assertFalse(a.dispatcher.send(b.contact(),request(2,DhtTransport.Operation.FIND_VALUE,DhtIdTest.id(5))));
        assertFalse(a.dispatcher.send(b.contact(),request(3,DhtTransport.Operation.STORE,DhtIdTest.id(5))));
        assertFalse(a.dispatcher.store(b.contact(),record(1,1,NOW).encode()));
        assertTrue(net.sent.isEmpty());
        assertEquals(0,a.dispatcher.pendingCount());
    }
    @Test void aRequestFromAnUnknownPeerStartsAProbeBackAndBothBecomeYes() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var b=net.rig(DhtIdTest.id(2));
        a.dispatcher.sessionStarted(b.id.bytes(),SESSION);net.pump();
        assertTrue(a.dispatcher.peers().isYes(b.id));assertTrue(b.dispatcher.peers().isYes(a.id));
    }
    @Test void aSilentPeerBecomesNoAfterThreeSecondsAndGetsNoMoreRequests() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var c=net.rig(DhtIdTest.id(3));net.dropTo.add(c.id);
        a.dispatcher.sessionStarted(c.id.bytes(),SESSION);net.pump();
        net.advance(3*SECOND);
        assertEquals(DhtPeers.State.NO,a.dispatcher.peers().state(c.id));
        assertFalse(a.dispatcher.send(c.contact(),ping(1)));
        assertEquals(1,net.count(a,c,DhtWire.Op.PING));
    }
    @Test void anOldPeerThatNeverAnswersGetsAtMostTwelveProbesInADayWhateverTheTrigger() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var c=net.rig(DhtIdTest.id(3));net.dropTo.add(c.id);
        for(int i=0;i<2880;i++) { // 30 秒ごとに 24 時間
            net.advance(30*SECOND);
            if(i%20==0)a.dispatcher.sessionStarted(c.id.bytes(),filled(16,i%200));
            if(i%120==0)a.dispatcher.peers().retryAll();
        }
        int sent=net.count(a,c,DhtWire.Op.PING);
        assertTrue(sent<=12,"probes "+sent);assertTrue(sent>=6,"probes "+sent);
        assertEquals(sent,a.dispatcher.statistics().probesSent());
    }
    @Test void aProbeForAnotherSessionDoesNotMakeThePeerYes() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var b=net.rig(DhtIdTest.id(2));
        a.dispatcher.sessionStarted(b.id.bytes(),SESSION);
        var probe=net.queue.poll();net.deliver(probe);
        Packet pong=null;
        for(Packet q:net.queue)if(q.message().op()==DhtWire.Op.PONG)pong=q;
        assertNotNull(pong);net.queue.remove(pong);
        net.deliver(new Packet(pong.from,pong.to,OTHER_SESSION,pong.wire));
        assertFalse(a.dispatcher.peers().isYes(b.id));assertEquals(1,a.dispatcher.statistics().mismatched());
        net.deliver(pong);
        assertTrue(a.dispatcher.peers().isYes(b.id));
    }

    // ---- 核の要求と応答 ----

    @Test void aFindNodeLookupGetsNodesFromThePeerAndPassesTheContactsToTheCore() {
        var net=new Net();var a=net.rig(record(1,1,NOW).nodeId());var b=net.rig(DhtIdTest.id(2));
        a.network();net.connect(a,b);seed(b,10,12);
        var lookup=drive(net,a,a.node.findNode(DhtIdTest.id(11)));
        assertTrue(lookup.done());assertEquals(1,lookup.result().responded());
        assertEquals(3,a.node.candidates().size());
        assertEquals(1,net.count(a,b,DhtWire.Op.FIND_NODE));
        assertEquals(0,a.dispatcher.pendingCount());
    }
    @Test void aNodesReplyWithTwentyContactsIsFetchedInTwoPagesAndHandedOverOnce() {
        var net=new Net();var a=net.rig(record(1,1,NOW).nodeId());var b=net.rig(DhtIdTest.id(2));
        a.network();net.connect(a,b);seed(b,10,34);
        var lookup=drive(net,a,a.node.findNode(DhtIdTest.id(11)));
        assertTrue(lookup.done());assertEquals(1,lookup.result().responded());
        assertEquals(2,net.count(a,b,DhtWire.Op.FIND_NODE));assertEquals(2,net.count(b,a,DhtWire.Op.NODES));
        List<Packet> pages=new ArrayList<>();
        for(Packet p:net.sent)if(p.from==b&&p.to==a&&p.message().op()==DhtWire.Op.NODES)pages.add(p);
        assertEquals(10,pages.get(0).message().contacts().size());assertFalse(pages.get(0).message().last());
        assertEquals(10,pages.get(1).message().contacts().size());assertTrue(pages.get(1).message().last());
        assertEquals(0,a.dispatcher.pendingCount());
    }
    @Test void ifThePageTwoAnswerNeverComesThePageOneContactsAreStillHandedOver() {
        var net=new Net();var a=net.rig(record(1,1,NOW).nodeId());var b=net.rig(DhtIdTest.id(2));
        a.network();net.connect(a,b);seed(b,10,34);
        var lookup=a.node.findNode(DhtIdTest.id(11));a.node.poll();
        net.deliver(net.queue.poll());net.deliver(net.queue.poll()); // 要求 → ページ 1 の答え
        assertEquals(DhtWire.Op.FIND_NODE,net.queue.peek().message().op());
        net.queue.clear();                                           // ページ 2 の要求を失う
        net.advance(SECOND);
        assertEquals(1,a.dispatcher.statistics().expired());assertEquals(0,a.dispatcher.pendingCount());
        drive(net,a,lookup);
        assertTrue(lookup.done());assertEquals(1,lookup.result().responded());
    }
    @Test void aFindValueLookupFindsTheRecordThePeerHolds() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        assertEquals(DiscoveryStatus.ACCEPTED,p[1].store.put(DiscoveryStoreTest.publisher(r),r.encode()));
        var lookup=drive(net,p[0],p[0].node.findValue(r.key()));
        assertTrue(lookup.done());assertTrue(lookup.result().value().isPresent());
        assertEquals(r.encode().length,lookup.result().value().get());
    }
    @Test void aFindValueLookupWithoutARecordGetsNodesForTheSameKey() {
        var net=new Net();var p=pair(net);
        var lookup=drive(net,p[0],p[0].node.findValue(DhtIdTest.id(99)));
        assertTrue(lookup.done());assertTrue(lookup.result().value().isEmpty());assertEquals(1,lookup.result().responded());
        assertEquals(0,p[0].dispatcher.statistics().mismatched());
    }
    @Test void aFindValueWithoutARecordAgainstAPeerWithTwentyContactsIsContinuedByAFindNodeForPageTwo() {
        var net=new Net();var a=net.rig(record(1,1,NOW).nodeId());var b=net.rig(DhtIdTest.id(2));
        a.network();net.connect(a,b);seed(b,10,34);
        var lookup=drive(net,a,a.node.findValue(DhtIdTest.id(11)));
        assertTrue(lookup.done());assertTrue(lookup.result().value().isEmpty());assertEquals(1,lookup.result().responded());
        assertEquals(1,net.count(a,b,DhtWire.Op.FIND_VALUE));assertEquals(1,net.count(a,b,DhtWire.Op.FIND_NODE));
        List<Packet> pages=new ArrayList<>();
        for(Packet p:net.sent)if(p.from==b&&p.to==a&&p.message().op()==DhtWire.Op.NODES)pages.add(p);
        assertEquals(2,pages.size());
        assertEquals(10,pages.get(0).message().contacts().size());assertFalse(pages.get(0).message().last());
        assertEquals(10,pages.get(1).message().contacts().size());assertTrue(pages.get(1).message().last());
        assertEquals(0,a.dispatcher.pendingCount());assertEquals(0,a.dispatcher.statistics().mismatched());
    }
    @Test void aDirectoryWithoutAnAddressLeavesTheContactOutOfTheReply() {
        var net=new Net();var a=net.rig(record(1,1,NOW).nodeId());var b=net.rig(DhtIdTest.id(2));
        net.connect(a,b);seed(b,10,12);b.directory.remove(DhtIdTest.id(11));
        var lookup=drive(net,a,a.node.findNode(DhtIdTest.id(11)));
        assertTrue(lookup.done());
        for(Packet p:net.sent)if(p.from==b&&p.message().op()==DhtWire.Op.NODES)assertEquals(2,p.message().contacts().size());
    }

    // ---- 記録を預ける（STORE） ----

    @Test void aSignedRecordIsStoredByThePeerAndTheResultIsMatched() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        assertTrue(p[0].dispatcher.store(p[1].contact(),r.encode()));net.pump();
        assertEquals(1,p[1].store.size());assertEquals(0,p[0].dispatcher.pendingCount());
        assertEquals(DhtWire.StoreStatus.ACCEPTED,net.sent.get(net.sent.size()-1).message().status());
    }
    @Test void storeRefusesAMalformedRecordAndAPeerThatIsNotYes() {
        var net=new Net();var p=pair(net);var c=net.rig(DhtIdTest.id(3));
        assertFalse(p[0].dispatcher.store(p[1].contact(),new byte[]{1,2,3}));
        assertFalse(p[0].dispatcher.store(c.contact(),record(1,1,NOW).encode()));
        assertFalse(p[0].dispatcher.send(p[1].contact(),request(1,DhtTransport.Operation.STORE,DhtIdTest.id(0))));
    }
    @Test void aRecordFromAnotherMemberIsAnsweredWithInvalidAndNotStored() {
        var net=new Net();var p=pair(net);
        assertTrue(p[0].dispatcher.store(p[1].contact(),record(2,1,NOW).encode()));net.pump();
        assertEquals(0,p[1].store.size());
        assertEquals(DhtWire.StoreStatus.INVALID,net.sent.get(net.sent.size()-1).message().status());
    }
    @Test void aStoreWhoseWireKeyDiffersFromTheRecordKeyIsRefusedBeforeTheSignatureIsChecked() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        byte[] wire=DhtWire.store(GROUP,filled(16,5),DhtIdTest.id(77),r.encode());
        assertTrue(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,wire));
        assertEquals(0,p[1].store.size());assertEquals(1,p[1].store.counts().count(DiscoveryStatus.INVALID));
        var reply=net.queue.poll();assertEquals(DhtWire.Op.STORE_RESULT,reply.message().op());
        assertEquals(DhtWire.StoreStatus.INVALID,reply.message().status());assertEquals(DhtIdTest.id(77),reply.message().target());
    }
    @Test void aFloodOfStoresWithAWrongWireKeyIsStoppedByThePeerRateLimit() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        byte[] wire=DhtWire.store(GROUP,filled(16,5),DhtIdTest.id(77),r.encode());
        int sentCount=DhtResponder.PEER_BURST*3;
        int tokens=DhtResponder.PEER_BURST-1; // 握手の探りのPINGに1通答えた分を引く
        long invalidBefore=p[1].store.counts().count(DiscoveryStatus.INVALID);
        for(int i=0;i<sentCount;i++)assertTrue(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,wire));
        assertEquals(tokens,net.queue.size());
        assertEquals(sentCount-tokens,p[1].responder.rateLimited());
        assertEquals(tokens,p[1].store.counts().count(DiscoveryStatus.INVALID)-invalidBefore);
    }
    @Test void aSecondIdenticalStoreIsAnsweredWithDuplicate() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        p[0].dispatcher.store(p[1].contact(),r.encode());net.pump();
        p[0].dispatcher.store(p[1].contact(),r.encode());net.pump();
        assertEquals(1,p[1].store.size());
        assertEquals(DhtWire.StoreStatus.DUPLICATE,net.sent.get(net.sent.size()-1).message().status());
    }

    // ---- 保留の結び付け ----

    private static Packet askPing(Net net,Rig from,Rig to) {
        assertTrue(from.dispatcher.send(to.contact(),ping(1)));return net.queue.poll();
    }
    @Test void aResponseIsAcceptedOnceAndTheSecondCopyIsUnsolicited() {
        var net=new Net();var p=pair(net);var ask=askPing(net,p[0],p[1]);
        net.deliver(ask);var pong=net.queue.poll();
        net.deliver(pong);assertEquals(0,p[0].dispatcher.pendingCount());
        net.deliver(pong);assertEquals(1,p[0].dispatcher.statistics().unsolicited());
    }
    @Test void aResponseFromAnotherPeerWithTheSameRequestNumberIsUnsolicited() {
        var net=new Net();var p=pair(net);var c=net.rig(DhtIdTest.id(3));
        var ask=askPing(net,p[0],p[1]);
        net.deliver(new Packet(c,p[0],SESSION,DhtWire.pong(GROUP,ask.message().requestId())));
        assertEquals(1,p[0].dispatcher.statistics().unsolicited());assertEquals(1,p[0].dispatcher.pendingCount());
    }
    @Test void aResponseOfTheWrongKindKeepsThePendingRequest() {
        var net=new Net();var p=pair(net);var ask=askPing(net,p[0],p[1]);var rid=ask.message().requestId();
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.nodes(GROUP,rid,DhtIdTest.id(0),0,true,List.of())));
        assertEquals(1,p[0].dispatcher.statistics().mismatched());assertEquals(1,p[0].dispatcher.pendingCount());
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.pong(GROUP,rid)));
        assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void aNodesReplyForAnotherTargetOrPageIsMismatched() {
        var net=new Net();var p=pair(net);
        assertTrue(p[0].dispatcher.send(p[1].contact(),request(1,DhtTransport.Operation.FIND_NODE,DhtIdTest.id(5))));
        var rid=net.queue.poll().message().requestId();
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.nodes(GROUP,rid,DhtIdTest.id(6),0,true,List.of())));
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.nodes(GROUP,rid,DhtIdTest.id(5),1,true,List.of())));
        assertEquals(2,p[0].dispatcher.statistics().mismatched());assertEquals(1,p[0].dispatcher.pendingCount());
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.nodes(GROUP,rid,DhtIdTest.id(5),0,true,List.of())));
        assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void aValueForAnotherKeyIsMismatchedAndAStoreResultForAnotherKeyToo() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        assertTrue(p[0].dispatcher.send(p[1].contact(),request(1,DhtTransport.Operation.FIND_VALUE,DhtIdTest.id(5))));
        var rid=net.queue.poll().message().requestId();
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.value(GROUP,rid,DhtIdTest.id(6),r.encode())));
        assertEquals(1,p[0].dispatcher.statistics().mismatched());
        assertTrue(p[0].dispatcher.store(p[1].contact(),r.encode()));
        var storeRid=net.queue.poll().message().requestId();
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.storeResult(GROUP,storeRid,DhtIdTest.id(8),DhtWire.StoreStatus.ACCEPTED)));
        assertEquals(2,p[0].dispatcher.statistics().mismatched());
    }
    @Test void aResponseAfterTheDeadlineIsExpiredAndTheRequestIsGone() {
        var net=new Net();var p=pair(net);var ask=askPing(net,p[0],p[1]);
        net.deliver(ask);var pong=net.queue.poll();
        net.nanos.addAndGet(DhtLimits.RPC_NANOS+1); // poll を呼ばずに時間だけ進める
        net.deliver(pong);
        assertEquals(1,p[0].dispatcher.statistics().expired());assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void aResponseBoundToAnotherGenerationIsStaleAndDropsThePendingRequest() {
        var net=new Net();var p=pair(net);var ask=askPing(net,p[0],p[1]);
        net.deliver(ask);var pong=net.queue.poll();
        p[0].peerGeneration=5;
        net.deliver(pong);
        assertEquals(1,p[0].dispatcher.statistics().stale());assertEquals(0,p[0].dispatcher.pendingCount());
    }
    @Test void aStoreResultBoundToAnotherGenerationIsStaleAndTellsTheStoreListenerItEndedWithoutAnAnswer() {
        var net=new Net();var p=pair(net);var r=record(1,1,NOW);
        List<DhtWire.StoreStatus> told=new ArrayList<>();List<DhtId> peers=new ArrayList<>();
        p[0].dispatcher.setStoreListener((peer,status)->{peers.add(peer);told.add(status);});
        assertTrue(p[0].dispatcher.store(p[1].contact(),r.encode()));
        var storeRid=net.queue.poll().message().requestId();
        p[0].peerGeneration=5;
        net.deliver(new Packet(p[1],p[0],SESSION,DhtWire.storeResult(GROUP,storeRid,r.key(),DhtWire.StoreStatus.ACCEPTED)));
        assertEquals(1,p[0].dispatcher.statistics().stale());assertEquals(0,p[0].dispatcher.pendingCount());
        assertEquals(1,told.size(),"The listener must hear that the STORE ended");
        assertEquals(p[1].id,peers.get(0));assertNull(told.get(0),"A stale result is not an answer");
    }
    @Test void aNetworkChangeDropsPendingRequestsAndMakesPeersUnknownUntilTheyAreProbedAgain() {
        var net=new Net();var p=pair(net);var ask=askPing(net,p[0],p[1]);
        net.deliver(ask);var pong=net.queue.poll();
        p[0].network();
        assertEquals(0,p[0].dispatcher.pendingCount());assertFalse(p[0].dispatcher.peers().isYes(p[1].id));
        net.deliver(pong);assertEquals(1,p[0].dispatcher.statistics().unsolicited());
        assertFalse(p[0].dispatcher.send(p[1].contact(),ping(2)));
        net.connect(p[0],p[1]);assertTrue(p[0].dispatcher.peers().isYes(p[1].id));
    }
    @Test void forgettingAVolatilePeerRemovesItsStateAndItsPendingRequests() {
        var net=new Net();var p=pair(net);askPing(net,p[0],p[1]);
        assertEquals(1,p[0].dispatcher.pendingCount());
        p[0].dispatcher.volatilePeerForgotten(p[1].id.bytes());
        assertEquals(0,p[0].dispatcher.pendingCount());assertFalse(p[0].dispatcher.peers().isYes(p[1].id));
    }
    @Test void eightRequestsToOnePeerAreTheLimitAndTheNinthIsRefused() {
        var net=new Net();var p=pair(net);
        for(int i=0;i<DhtDispatcher.MAX_PENDING_PER_PEER;i++)assertTrue(p[0].dispatcher.send(p[1].contact(),ping(i)),"request "+i);
        assertFalse(p[0].dispatcher.send(p[1].contact(),ping(99)));
        assertEquals(DhtDispatcher.MAX_PENDING_PER_PEER,p[0].dispatcher.pendingCount());
    }
    @Test void sixtyFourRequestsInTotalAreTheLimitAcrossPeers() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));List<Rig> others=new ArrayList<>();
        for(int i=0;i<9;i++) {
            var b=net.rig(DhtIdTest.id(100+i));others.add(b);net.connect(a,b);
            if(i%5==4)net.advance(61*SECOND);
        }
        for(Rig b:others)assertTrue(a.dispatcher.peers().isYes(b.id));
        for(int i=0;i<8;i++)for(int k=0;k<DhtDispatcher.MAX_PENDING_PER_PEER;k++)assertTrue(a.dispatcher.send(others.get(i).contact(),ping(k)));
        assertEquals(DhtDispatcher.MAX_PENDING,a.dispatcher.pendingCount());
        assertFalse(a.dispatcher.send(others.get(8).contact(),ping(1)));
    }
    @Test void aRepeatedRequestNumberIsRefusedInsteadOfOverwritingThePendingRequest() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1),new Random(){@Override protected int next(int bits){return 0;}});
        var b=net.rig(DhtIdTest.id(2));
        // 探りの 1 通目は番号 0 で通る。同じ相手への次の要求は、同じ番号になるので送らない。
        a.dispatcher.sessionStarted(b.id.bytes(),SESSION);
        assertEquals(1,a.dispatcher.pendingCount());
        a.dispatcher.peers().probeAnswered(b.id,SESSION);
        assertTrue(a.dispatcher.peers().isYes(b.id));
        assertFalse(a.dispatcher.send(b.contact(),ping(1)));
        assertEquals(1,a.dispatcher.pendingCount());
    }
    @Test void aRequestThatCouldNotBeSentLeavesNoPendingRequest() {
        var net=new Net();var p=pair(net);p[0].sendOk=false;
        assertFalse(p[0].dispatcher.send(p[1].contact(),ping(1)));assertEquals(0,p[0].dispatcher.pendingCount());
    }

    // ---- 受け口で捨てるもの ----

    @Test void plaintextThatIsNotDhtIsLeftToTheCaller() {
        var net=new Net();var p=pair(net);
        long before=p[1].dispatcher.statistics().received();
        assertFalse(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,new byte[]{1,2,3}));
        assertFalse(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,new byte[0]));
        assertEquals(before,p[1].dispatcher.statistics().received());
    }
    @Test void aMalformedDhtMessageIsCountedAndDroppedWithoutAReply() {
        var net=new Net();var p=pair(net);
        assertTrue(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,new byte[]{0x08,0x02,0x4A,0x7F}));
        assertEquals(1,p[1].dispatcher.statistics().malformed());assertTrue(net.queue.isEmpty());
    }
    @Test void aMessageForAnotherGroupIsCountedAndDroppedWithoutAReply() {
        var net=new Net();var p=pair(net);
        assertTrue(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,DhtWire.ping(filled(32,3),filled(16,1))));
        assertEquals(1,p[1].dispatcher.statistics().wrongGroup());assertTrue(net.queue.isEmpty());
    }
    @Test void aMessageFromAnUnauthenticatedSenderIsCountedAndDroppedWithoutAReply() {
        var net=new Net();var p=pair(net);var stranger=DhtIdTest.id(50);
        assertTrue(p[1].dispatcher.receive(stranger.bytes(),SESSION,DhtWire.ping(GROUP,filled(16,1))));
        assertEquals(1,p[1].dispatcher.statistics().unauthenticated());assertTrue(net.queue.isEmpty());
        p[1].claimAs=DhtIdTest.id(60); // 認証が別の端末だと言う
        assertTrue(p[1].dispatcher.receive(p[0].id.bytes(),SESSION,DhtWire.ping(GROUP,filled(16,1))));
        assertEquals(2,p[1].dispatcher.statistics().unauthenticated());assertTrue(net.queue.isEmpty());
    }
    @Test void aShortPeerIdentifierIsTreatedAsUnauthenticatedWithoutAnException() {
        var net=new Net();var p=pair(net);
        assertTrue(p[1].dispatcher.receive(new byte[5],SESSION,DhtWire.ping(GROUP,filled(16,1))));
        assertEquals(1,p[1].dispatcher.statistics().unauthenticated());
    }

    // ---- 大きな転送の口 ----

    @Test void aTransferForAValueIsDeliveredOnlyWhenAFindValueIsWaitingForIt() {
        var net=new Net();var p=pair(net);byte[] data=new byte[2500];new Random(3).nextBytes(data);
        // 待っている FIND_VALUE がないので、届いても渡さない。
        p[1].dispatcher.transfers().start(p[0].id,SESSION,DhtWire.TransferKind.VALUE,filled(16,4),data);
        net.run(50);assertTrue(p[0].sunk.isEmpty());
        assertTrue(p[0].dispatcher.transfers().rejected()>0);
        p[1].dispatcher.transfers().forget(p[0].id); // 同じ相手への転送は 1 本まで。前の分を片づける
        // 自分が出した FIND_VALUE の request_id と同じ transfer_id なら受ける。
        assertTrue(p[0].dispatcher.send(p[1].contact(),request(1,DhtTransport.Operation.FIND_VALUE,DhtIdTest.id(5))));
        byte[] rid=net.queue.poll().message().requestId();
        p[1].dispatcher.transfers().start(p[0].id,SESSION,DhtWire.TransferKind.VALUE,rid,data);
        net.run(50);
        assertEquals(1,p[0].sunk.size());assertArrayEquals(data,p[0].sunk.get(0).data());assertEquals(p[1].id,p[0].sunk.get(0).peer());
    }
    @Test void aTransferIsStartedOnlyToAYesPeerAndUsesItsCurrentSession() {
        var net=new Net();var p=pair(net);var c=net.rig(DhtIdTest.id(3));byte[] data=new byte[4000];
        int before=net.sent.size();
        assertNull(p[0].dispatcher.startTransfer(c.contact(),DhtWire.TransferKind.STORE,data)); // 握手していない相手
        assertEquals(0,p[0].dispatcher.transfers().activeOut());assertEquals(before,net.sent.size());
        byte[] id=p[0].dispatcher.startTransfer(p[1].contact(),DhtWire.TransferKind.STORE,data);
        assertNotNull(id);assertEquals(1,p[0].dispatcher.transfers().activeOut());
        p[0].network(); // 覚えが未確認に戻る
        assertNull(p[0].dispatcher.startTransfer(p[1].contact(),DhtWire.TransferKind.STORE,data));
        assertEquals(0,p[0].dispatcher.transfers().activeOut());
    }
    @Test void threeExpiredRequestsInARowMakeAYesPeerUnknownAndItIsProbedAgainWithinTheLimit() {
        var net=new Net();var p=pair(net);
        long before=p[0].dispatcher.statistics().probesSent();
        net.dropTo.add(p[1].id);
        for(int i=1;i<=2;i++){assertTrue(p[0].dispatcher.send(p[1].contact(),ping(i)));net.pump();net.advance(DhtLimits.RPC_NANOS+1);}
        assertTrue(p[0].dispatcher.peers().isYes(p[1].id),"2 回の期限切れではまだ YES");
        assertEquals(before,p[0].dispatcher.statistics().probesSent());
        assertTrue(p[0].dispatcher.send(p[1].contact(),ping(3)));net.pump();net.advance(DhtLimits.RPC_NANOS+1);
        assertFalse(p[0].dispatcher.peers().isYes(p[1].id),"3 回続けて期限切れなら未確認に戻る");
        assertEquals(before+1,p[0].dispatcher.statistics().probesSent(),"新しい一巡の最初の探りだけ送る");
        assertFalse(p[0].dispatcher.send(p[1].contact(),ping(4)),"YES に戻るまで要求は送らない");
        net.advance(3*SECOND);
        assertEquals(DhtPeers.State.NO,p[0].dispatcher.peers().state(p[1].id));
    }
    @Test void threeRequestsExpiringInOneSweepWhileAnotherIsStillWaitingMakeTheYesPeerUnknown() {
        var net=new Net();var p=pair(net);
        long before=p[0].dispatcher.statistics().probesSent();
        net.dropTo.add(p[1].id);
        for(int i=1;i<=3;i++)assertTrue(p[0].dispatcher.send(p[1].contact(),ping(i)));
        net.advance(DhtLimits.RPC_NANOS/2);
        assertTrue(p[0].dispatcher.send(p[1].contact(),ping(4))); // 掃除のとき、まだ待っている 4 件目
        net.advance(DhtLimits.RPC_NANOS/2+1); // 1〜3 件目が同じ掃除で期限切れになる
        assertFalse(p[0].dispatcher.peers().isYes(p[1].id),"同じ掃除での 3 回の期限切れでも未確認に戻る");
        assertEquals(before+1,p[0].dispatcher.statistics().probesSent());
        net.advance(DhtLimits.RPC_NANOS); // 4 件目も期限切れ。もう YES でないので数えず、探りも増えない
        assertEquals(before+1,p[0].dispatcher.statistics().probesSent());
    }
    @Test void anAnswerBetweenExpiredRequestsCountsTheExpiriesFromZero() {
        var net=new Net();var p=pair(net);
        net.dropTo.add(p[1].id);
        for(int i=1;i<=2;i++){assertTrue(p[0].dispatcher.send(p[1].contact(),ping(i)));net.pump();net.advance(DhtLimits.RPC_NANOS+1);}
        net.dropTo.remove(p[1].id);
        assertTrue(p[0].dispatcher.send(p[1].contact(),ping(3)));net.pump(); // 答えが戻る
        net.dropTo.add(p[1].id);
        for(int i=4;i<=5;i++){assertTrue(p[0].dispatcher.send(p[1].contact(),ping(i)));net.pump();net.advance(DhtLimits.RPC_NANOS+1);}
        assertTrue(p[0].dispatcher.peers().isYes(p[1].id),"答えのあとは数え直すので 2 回ではまだ YES");
    }
    @Test void aPeerThatKeepsComingBackAndGoingSilentIsProbedWithinTheDailyLimitOverThreeDays() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var c=net.rig(DhtIdTest.id(3));net.connect(a,c);
        var times=new ArrayList<Long>();long last=a.dispatcher.statistics().probesSent();
        net.dropTo.add(c.id);
        for(int i=0;i<3*2880;i++) { // 30 秒ごとに 3 日
            net.advance(30*SECOND);
            if(i%720==0){ // 6 時間ごとに少しだけ答える
                net.dropTo.remove(c.id);a.dispatcher.sessionStarted(c.id.bytes(),filled(16,10+i/720));net.pump();net.dropTo.add(c.id);
            }
            a.dispatcher.send(c.contact(),ping(i+1)); // YES のときだけ送られ、答えが無いので期限切れになる
            long now=a.dispatcher.statistics().probesSent();
            for(long k=last;k<now;k++)times.add(net.nanos.get());
            last=now;
        }
        assertTrue(times.size()>=DhtPeers.PEER_PER_DAY,"probes "+times.size());
        for(int i=0;i<times.size();i++) {
            int n=0;
            for(int j=i;j<times.size()&&times.get(j)-times.get(i)<86_400L*SECOND;j++)n++;
            assertTrue(n<=DhtPeers.PEER_PER_DAY,"probes in one day: "+n);
        }
    }
    @Test void aNetworkChangeAbandonsTheTransfersInFlight() {
        var net=new Net();var p=pair(net);byte[] data=new byte[4000];
        p[0].dispatcher.transfers().start(p[1].id,SESSION,DhtWire.TransferKind.STORE,data);
        assertEquals(1,p[0].dispatcher.transfers().activeOut());
        p[0].network();
        assertEquals(0,p[0].dispatcher.transfers().activeOut());assertEquals(0,p[0].dispatcher.transfers().activeIn());
    }

    // ---- 形の決まり ----

    @Test void theGroupIdentifierMustBeThirtyTwoBytes() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));
        var error=assertThrows(IllegalArgumentException.class,()->new DhtDispatcher(new byte[31],a.node,a.responder,a.store,
            null==null?new DhtLink(){
                public AuthenticatedPeer authenticated(byte[] p,byte[] s){return null;}
                public boolean send(byte[] p,byte[] s,byte[] t){return false;}
                public boolean releaseVolatile(byte[] p){return false;}
            }:null,id->null,(peer,kind,data)->{},net.nanos::get));
        assertEquals("Invalid group",error.getMessage());
    }
    @Test void stringFormsNeverShowIdentifiersOrCounters() {
        var net=new Net();var p=pair(net);
        assertEquals("DHT dispatcher",p[0].dispatcher.toString());assertEquals("DHT statistics",p[0].dispatcher.statistics().toString());
        assertEquals("DHT peers",p[0].dispatcher.peers().toString());assertEquals("DHT transfers",p[0].dispatcher.transfers().toString());
    }
    @Test void theStatisticsCountOnlyNumbers() {
        var net=new Net();var p=pair(net);var s=p[0].dispatcher.statistics();
        assertEquals(1,s.yesPeers());assertEquals(0,s.noPeers());assertEquals(1,s.probesSent());
        assertTrue(s.received()>=1);assertEquals(0,s.malformed()+s.unauthenticated()+s.wrongGroup()+s.unsolicited()+s.mismatched()+s.expired()+s.stale());
    }
}
