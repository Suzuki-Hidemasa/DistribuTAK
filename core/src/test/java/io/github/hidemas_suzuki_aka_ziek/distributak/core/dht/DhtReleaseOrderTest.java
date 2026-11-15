// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.List;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherPrepareTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 D の直し（答え 187 の推奨 1）: 手放す相手を選ぶ順番・守る条件を、壊して赤くなることを確かめた試験。
 * 揮発の枠が満杯のとき、どの相手を手放すか（満杯の桶の古い方・YES でない方・表の外の方）と、
 * どの相手を手放さないか（使用中・転送中・保留の要求・セッションが無い・時計が戻った・ネットワークが変わった）を 1 つずつ見る。
 * 試験の失敗の文にも、番地・端末の番号・鍵は出さない。
 */
class DhtReleaseOrderTest {
    private static int seq;

    /** a から見て、桶 bit（16 以上）に入る番号。n で同じ桶の中の別の番号を作る。 */
    static DhtId inBucket(Rig a,int bit,int n) {
        byte[] bytes=a.id.bytes().clone();
        bytes[31-bit/8]^=(byte)(1<<(bit%8));
        bytes[31]^=(byte)n;bytes[30]^=(byte)(n>>8);
        return new DhtId(bytes);
    }
    static Rig connectedId(Net net,Rig a,DhtId id) {
        int k=++seq%100;
        Rig c=net.rig(id);
        DhtWire.NodeContact nc=new DhtWire.NodeContact(id,HANDSHAKE,new byte[]{(byte)192,(byte)168,1,(byte)(100+k)},50000);
        assertTrue(a.node.candidates().offer(DhtIdTest.id(500+k),new DhtCandidates.Candidate(nc.node(),nc.ipv4(),nc.port(),nc.handshakeKey())));
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        handshake(net,a,c);a.dispatcher.poll();
        assertTrue(a.dispatcher.peers().isYes(c.id));assertFalse(a.node.candidates().isActive(c.id));
        return c;
    }
    static void reobserve(Rig a,Rig x){a.node.observe(AuthenticatedPeer.fromVerifiedDhtResponse(x.contact()));}
    /** 満杯にして、番号 n（n は 3〜9 の探索用）の候補で prepare する。 */
    static DhtTransport.Readiness askWhenFull(Net net,Rig a,int n) {
        a.slotFree=false;net.rig(DhtIdTest.id(n));offer(a,n);
        return a.dispatcher.prepare(new Contact(DhtIdTest.id(n)));
    }

    // ---- どの相手を手放すか ----

    @Test void whenAllAreInTheTableTheOldestPeerOfTheMostCrowdedBucketGoes() {
        var net=new Net();var a=base(net);
        var y1=connectedId(net,a,inBucket(a,80,1));
        var x1=connectedId(net,a,inBucket(a,40,1));
        var x2=connectedId(net,a,inBucket(a,40,2));
        net.advance(GRACE);
        // x1 をもう一度観察して、桶 40 の中で x2 を一番古くする（x2 が 0 番・x1 が 1 番）。
        reobserve(a,x1);
        assertEquals(1,a.node.routing().bucketLoadOf(y1.id));assertEquals(2,a.node.routing().bucketLoadOf(x1.id));assertEquals(2,a.node.routing().bucketLoadOf(x2.id));
        assertEquals(0,a.node.routing().ageRankOf(x2.id));assertEquals(1,a.node.routing().ageRankOf(x1.id));
        assertEquals(DhtTransport.Readiness.CONNECTING,askWhenFull(net,a,6));
        assertEquals(List.of(x2.id),a.released);
        assertEquals(1,a.dispatcher.statistics().releasedCrowdedBucket());assertEquals(0,a.dispatcher.statistics().releasedOutsideTable());
        assertTrue(a.node.routing().contains(y1.id));assertTrue(a.node.routing().contains(x1.id));assertFalse(a.node.routing().contains(x2.id));
    }
    @Test void aPeerThatIsNotYesGoesBeforeAYesPeerOutsideTheTableEvenWhenItWasStartedLater() {
        var net=new Net();var a=base(net);
        var y=connected(net,a,3);
        a.node.routing().remove(y.id); // y は YES で表の外
        // 探りは全体で毎分 30 通までなので、y の 1 通＋ほかの 29 台で使い切り、u の探りは出ないまま未確認で残す。
        for(int n=10;n<39;n++){var f=net.rig(DhtIdTest.id(n));handshake(net,a,f);}
        var u=net.rig(DhtIdTest.id(4));offer(a,4);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(u.contact()));
        a.dispatcher.sessionStarted(u.id.bytes(),SESSION);net.pump();
        assertEquals(DhtPeers.State.UNKNOWN,a.dispatcher.peers().state(u.id));
        assertTrue(a.dispatcher.peers().isYes(y.id));assertFalse(a.node.routing().contains(y.id));
        net.advance(GRACE);
        assertEquals(DhtPeers.State.UNKNOWN,a.dispatcher.peers().state(u.id));
        assertEquals(DhtTransport.Readiness.CONNECTING,askWhenFull(net,a,6));
        assertEquals(List.of(u.id),a.released);
        assertEquals(1,a.dispatcher.statistics().releasedNotYes());assertEquals(0,a.dispatcher.statistics().releasedOutsideTable());
        assertTrue(a.dispatcher.peers().isYes(y.id));
    }

    // ---- 手放さない相手 ----

    @Test void aConnectingPeerWhoseHandshakeIsDoneButWhoseProbeWasBlockedIsKeptOnlyByTheLookupReference() {
        // M01: 握手は済んだが探りが毎分 30 通の枠で出せず、保留の要求が無い CONNECTING の相手 P。
        // 守っているのは「探索が P を見ている」（node.isReferenced）だけ。30 秒を過ぎ、枠が満杯でも手放さない。
        var net=new Net();var a=base(net);a.usePrepare=true;
        // 探りの枠（毎分 30 通）を使い切る。桶 K=20 を超えないよう、30 台は別々の桶（16〜45）に置く。
        for(int i=0;i<30;i++){var f=net.rig(inBucket(a,16+i,1));handshake(net,a,f);}
        var p=net.rig(DhtIdTest.id(3));offer(a,3);
        a.node.observe(AuthenticatedPeer.fromVerifiedDhtResponse(p.contact())); // 探索が拾えるよう経路表に入れる（握手は未だ）
        a.node.findNode(DhtIdTest.id(3));a.node.poll();
        assertTrue(a.node.candidates().isActive(p.id));
        a.dispatcher.sessionStarted(p.id.bytes(),SESSION);net.pump();
        assertNotEquals(DhtPeers.State.YES,a.dispatcher.peers().state(p.id));
        assertTrue(a.node.candidates().isActive(p.id)); // 試みは開いたまま
        assertTrue(a.node.isReferenced(p.id));
        net.advance(GRACE);
        assertTrue(a.node.isReferenced(p.id));assertTrue(a.node.candidates().isActive(p.id));
        assertEquals(DhtTransport.Readiness.BUSY,askWhenFull(net,a,6));
        assertFalse(a.released.contains(p.id));
        assertTrue(a.released.isEmpty());
    }

    @Test void aConnectingPeerMarkedReleasedByTheValueMarkIsTheOneReleasedWhenTheSlotsAreFull() {
        // 推-2: 値の印で RELEASED になった相手は、探索がまだ開いていても「探索が見ている相手」から外れ、枠が満杯のときに実際に手放される。
        // q は値を持つ相手、d は返事をしない相手（探索を開いたままにする）、p は握手は済んだが探りの枠が尽きて YES になれない相手。
        var net=new Net();var a=base(net);a.usePrepare=true;
        var r=record(1,1,NOW);
        var q=connected(net,a,3);var d=connected(net,a,4);
        assertEquals(DiscoveryStatus.ACCEPTED,q.store.put(DiscoveryStoreTest.publisher(r),r.encode()));
        net.dropTo.add(d.id);
        // 探りの枠（毎分 30 通）を使い切る。q・d の 2 通＋ここの 28 台。28 台は探索に入らないよう経路表から外す。
        for(int i=0;i<28;i++){var f=net.rig(inBucket(a,16+i,1));handshake(net,a,f);a.node.routing().remove(f.id);}
        var p=net.rig(DhtIdTest.id(5));offer(a,5);
        a.node.observe(AuthenticatedPeer.fromVerifiedDhtResponse(p.contact()));
        var lookup=a.node.findValue(r.key());a.node.poll();
        assertTrue(a.node.candidates().isActive(p.id),"p は探索がつなぎ中にした");
        assertTrue(a.node.isReferenced(p.id),"印の前は、探索が p を見ている");
        // p の握手を通す。net.pump() で q の返事（値）も届き、印が付く。d の返事は来ないので探索は開いたまま。
        a.dispatcher.sessionStarted(p.id.bytes(),SESSION);net.pump();
        assertNotEquals(DhtPeers.State.YES,a.dispatcher.peers().state(p.id));
        for(int i=0;i<20&&a.node.connectingReleased()==0;i++){a.node.poll();net.pump();net.advance(SECOND/10);}
        assertEquals(1,a.node.connectingReleased(),"値の印で p が手放しの印になる");
        assertFalse(lookup.done(),"d の返事待ちで、探索は開いたまま");
        assertFalse(a.node.isReferenced(p.id),"印の付いた p は探索が見ている相手に数えない");
        net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.CONNECTING,askWhenFull(net,a,6));
        assertEquals(List.of(p.id),a.released,"手放されるのは印の付いた p だけ");
        assertEquals(1,a.dispatcher.statistics().releasedNotYes());
    }
    @Test void peersTheLookupStillWaitsForOrHasAskedAreNotReleased() {
        var net=new Net();var a=base(net);
        var ps=new java.util.ArrayList<Rig>();
        for(int n=3;n<6;n++)ps.add(connected(net,a,n)); // 同時に問い合わせる数（3）ちょうど
        net.advance(GRACE);
        for(Rig p:ps)net.dropTo.add(p.id);
        a.node.findNode(DhtIdTest.id(11));a.node.poll();
        // 3 台とも探索が見ていて、保留の要求もある（守りが二重なので、この試験は片方だけを外しても赤くならない）。
        assertEquals(3,a.dispatcher.pendingCount());
        int referenced=0;for(Rig p:ps)if(a.node.isReferenced(p.id))referenced++;
        assertEquals(3,referenced);
        assertEquals(DhtTransport.Readiness.BUSY,askWhenFull(net,a,8));
        assertTrue(a.released.isEmpty());
        assertEquals(1,a.dispatcher.statistics().nothingReleasable());
    }
    @Test void aPeerWithALargeTransferInProgressIsNotReleased() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        net.advance(GRACE);
        net.dropTo.add(c3.id);
        assertNotNull(a.dispatcher.startTransfer(c3.contact(),DhtWire.TransferKind.STORE,new byte[4000]));
        assertEquals(1,a.dispatcher.transfers().activeOut());
        assertEquals(DhtTransport.Readiness.BUSY,askWhenFull(net,a,6));
        assertTrue(a.released.isEmpty());
        assertTrue(a.dispatcher.peers().isYes(c3.id));
    }
    @Test void aPeerWhoseSessionIsAlreadyGoneIsSkippedAndTheNextOneIsReleased() {
        // 自分が始めた相手の覚えが残っているのに、DhtPeers のセッションが無い相手（通常は同時に覚えも消える）は、守りの二重の備えで飛ばす。
        var net=new Net();var a=base(net);var c3=connected(net,a,3);var c4=connected(net,a,4);
        net.advance(GRACE);
        a.dispatcher.peers().forget(c3.id);
        assertNull(a.dispatcher.peers().sessionOf(c3.id));
        assertEquals(DhtTransport.Readiness.CONNECTING,askWhenFull(net,a,6));
        assertEquals(List.of(c4.id),a.released);
    }
    @Test void aPeerWhoseSessionWeHaveNotSeenStartedIsNotReleasedEvenIfThePeersTableHasASession() {
        // 自分が始めた握手がまだ通っていない相手（sessionSeen が偽）は、DhtPeers にセッションがあっても手放さない。
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        net.dropTo.add(c.id);
        a.dispatcher.peers().sessionStarted(c.id,SESSION);
        net.advance(GRACE);
        assertNotNull(a.dispatcher.peers().sessionOf(c.id));
        assertEquals(DhtTransport.Readiness.BUSY,askWhenFull(net,a,6));
        assertTrue(a.released.isEmpty());
    }

    // ---- 自分が始めた相手の表が空になる場面 ----

    @Test void whenTheClockGoesBackTheStartedTableIsDroppedAndNothingIsReleasedLater() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        net.advance(GRACE);
        net.nanos.addAndGet(-SECOND);a.dispatcher.poll();
        net.advance(2*GRACE);
        assertTrue(a.dispatcher.peers().isYes(c3.id));
        assertEquals(DhtTransport.Readiness.BUSY,askWhenFull(net,a,6));
        assertTrue(a.released.isEmpty());
    }
    /** 32 台を自分で始めた状態にする（探りは毎分 30 通までなので、1 台ごとに 11 秒あけておけば足りる）。 */
    static Rig[] fillThirtyTwo(Net net,Rig a) {
        var all=new Rig[32];
        for(int i=0;i<32;i++){all[i]=connected(net,a,3+i);net.advance(11*SECOND);}
        assertEquals(0,a.dispatcher.statistics().droppedStarted());
        return all;
    }
    @Test void whenTheNetworkChangesTheStartedTableIsEmptiedSoNewStartsDropNothing() {
        var net=new Net();var a=base(net);
        fillThirtyTwo(net,a);
        a.dispatcher.networkChanged(2,new LocalNetwork(new byte[]{(byte)192,(byte)168,1,2},24)); // 世代を進める
        net.rig(DhtIdTest.id(40));offer(a,40);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(40))));
        assertEquals(0,a.dispatcher.statistics().droppedStarted());
    }
    @Test void aForgottenVolatilePeerLeavesTheStartedTableSoOneMoreStartDropsNothing() {
        var net=new Net();var a=base(net);
        var all=fillThirtyTwo(net,a);
        a.dispatcher.volatilePeerForgotten(all[5].id.bytes());
        net.rig(DhtIdTest.id(40));offer(a,40);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(40))));
        assertEquals(0,a.dispatcher.statistics().droppedStarted());
    }
}
