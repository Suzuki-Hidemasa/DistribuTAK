// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.List;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherPrepareTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 D の直し（答え 187 の必修 1）: BUSY の理由別の件数と、手放したあとの再握手・探りの枠が尽きた数。
 * 理由別の件数は「探索の候補が NEW から初めて BUSY になった知らせ（firstBusy）」のときだけ 1 つ足す。合計の件数は従来どおり prepare ごと。
 * 数えるのは件数だけで、番地・端末の番号・鍵は出さない（答え 166 (5)）。
 */
class DhtBusyStatisticsTest {
    /** 候補を 1 つ入れて握手の試みを始め、すぐ閉じる（開始の数だけが残る）。 */
    static void startAndClose(Rig a,int n) {
        offer(a,n);
        assertEquals(DhtCandidates.Start.STARTED,a.node.candidates().startFor(DhtIdTest.id(n)));
        a.node.candidates().release(a.node.candidates().attemptFor(DhtIdTest.id(n)).orElseThrow());
    }
    /** 同時 8 件の試みを動かす（3〜10）。 */
    static void eightActive(Net net,Rig a) {
        for(int n=3;n<=10;n++){net.rig(DhtIdTest.id(n));offer(a,n);assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(n))));}
    }
    static Contact contactOf(int n){return new Contact(DhtIdTest.id(n));}

    // ---- 理由別 ----
    @Test void aNinthCandidateWhileEightAttemptsRunIsCountedAsConcurrentOnlyWhenTheLookupReportsIt() {
        var net=new Net();var a=base(net);eightActive(net,a);net.rig(DhtIdTest.id(11));offer(a,11);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(11)));
        var s=a.dispatcher.statistics();
        assertEquals(1,s.busy());assertEquals(0,s.busyConcurrent(),"prepare だけでは理由別を数えない");
        a.dispatcher.firstBusy(contactOf(11));
        s=a.dispatcher.statistics();
        assertEquals(1,s.busyConcurrent());assertEquals(0,s.busyWindow());assertEquals(0,s.busyNothingReleasable());assertEquals(0,s.busyRecent30s());
        a.dispatcher.firstBusy(contactOf(11));
        assertEquals(1,a.dispatcher.statistics().busyConcurrent(),"同じ知らせをもう一度受けても増えない");
    }
    @Test void sixtyFourStartsInFiveMinutesAreCountedAsTheWindow() {
        var net=new Net();var a=base(net);
        for(int n=100;n<164;n++)startAndClose(a,n);
        assertEquals(64,a.node.candidates().startsInWindow());assertEquals(0,a.node.candidates().active());
        net.rig(DhtIdTest.id(3));offer(a,3);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(3)));
        a.dispatcher.firstBusy(contactOf(3));
        var s=a.dispatcher.statistics();
        assertEquals(1,s.busyWindow());assertEquals(0,s.busyConcurrent());assertEquals(0,s.busyNothingReleasable());assertEquals(0,s.busyRecent30s());
    }
    @Test void whenBothTheConcurrentLimitAndTheWindowHoldTheConcurrentLimitIsTheReason() {
        var net=new Net();var a=base(net);
        for(int n=100;n<156;n++)startAndClose(a,n);
        eightActive(net,a);
        assertEquals(64,a.node.candidates().startsInWindow());assertEquals(8,a.node.candidates().active());
        net.rig(DhtIdTest.id(11));offer(a,11);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(11)));a.dispatcher.firstBusy(contactOf(11));
        assertEquals(1,a.dispatcher.statistics().busyConcurrent());assertEquals(0,a.dispatcher.statistics().busyWindow());
        // 試みを 1 つ閉じると、残る理由は 5 分 64 件だけになる。
        a.node.candidates().release(a.node.candidates().attemptFor(DhtIdTest.id(3)).orElseThrow());
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(11)));a.dispatcher.firstBusy(contactOf(11));
        assertEquals(1,a.dispatcher.statistics().busyConcurrent());assertEquals(1,a.dispatcher.statistics().busyWindow());
    }
    @Test void aFullSlotWithNothingToReleaseIsCountedAsNothingReleasable() {
        var net=new Net();var a=base(net);a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(6)));a.dispatcher.firstBusy(contactOf(6));
        var s=a.dispatcher.statistics();
        assertEquals(1,s.busyNothingReleasable());assertEquals(0,s.busyRecent30s());assertEquals(0,s.busyConcurrent());assertEquals(0,s.busyWindow());
        assertEquals(1,s.nothingReleasable(),"従来の件数（prepare ごと）は変えない");assertEquals(1,s.busy());
    }
    @Test void aFullSlotWhereOnlyTheThirtySecondRuleHoldsIsCountedAsRecent() {
        var net=new Net();var a=base(net);connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        net.advance(29*SECOND);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(6)));a.dispatcher.firstBusy(contactOf(6));
        var s=a.dispatcher.statistics();
        assertEquals(1,s.busyRecent30s());assertEquals(0,s.busyNothingReleasable());assertEquals(0,s.busyConcurrent());assertEquals(0,s.busyWindow());
        assertEquals(1,s.nothingReleasable(),"30 秒だけが理由でも、従来の手放せなかった件数には入る");
    }
    @Test void aFullSlotWithOnePeerInUseAndOneRecentPeerIsCountedAsRecentBecauseRecentWasTheOnlyBlockerThatCouldClear() {
        // 使用中の相手は手放せない（理由は『手放せる相手なし』）。30 秒だけが理由の相手が 1 台でもいれば『30 秒だけ』に数える。
        var net=new Net();var a=base(net);var c3=connected(net,a,3);net.advance(GRACE);var c4=connected(net,a,4);
        a.dispatcher.setPublishInUse(id->id.equals(c3.id));
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(6)));a.dispatcher.firstBusy(contactOf(6));
        assertEquals(1,a.dispatcher.statistics().busyRecent30s());assertEquals(0,a.dispatcher.statistics().busyNothingReleasable());
        assertTrue(a.dispatcher.peers().isYes(c4.id));
    }
    @Test void noReasonIsCountedWithoutTheFirstBusyNotice() {
        var net=new Net();var a=base(net);a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        for(int i=0;i<5;i++)assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(6)));
        var s=a.dispatcher.statistics();
        assertEquals(5,s.busy());assertEquals(5,s.nothingReleasable());
        assertEquals(0,s.busyNothingReleasable());assertEquals(0,s.busyRecent30s());assertEquals(0,s.busyConcurrent());assertEquals(0,s.busyWindow());
    }
    @Test void aFirstBusyNoticeForAnotherPeerOrAfterAReadyAnswerCountsNothing() {
        var net=new Net();var a=base(net);eightActive(net,a);net.rig(DhtIdTest.id(11));offer(a,11);net.rig(DhtIdTest.id(12));
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(contactOf(11)));
        a.dispatcher.firstBusy(contactOf(12));
        assertEquals(0,a.dispatcher.statistics().busyConcurrent(),"別の相手の知らせでは数えない");
        // 次の prepare が BUSY でなければ、覚えていた理由は消える。
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(contactOf(12)));
        a.dispatcher.firstBusy(contactOf(11));
        assertEquals(0,a.dispatcher.statistics().busyConcurrent());
    }

    // ---- 探索から通す（統合） ----
    @Test void aLookupThatAsksTheBusyCandidateAtEveryPollCountsTheReasonOnce() {
        var net=new Net();var a=base(net);eightActive(net,a);
        net.rig(DhtIdTest.id(11));offer(a,11);a.node.observe(DhtResponderTest.peer(11));a.usePrepare=true;
        a.node.findNode(DhtIdTest.id(11));
        for(int i=0;i<6;i++)a.node.poll();
        var s=a.dispatcher.statistics();
        assertEquals(1,s.busyConcurrent());assertEquals(0,s.busyWindow());
        assertTrue(s.busy()>=3,"合計の件数は poll ごとに聞き直した分だけ増える");
    }

    // ---- 手放したあとの再握手 ----
    @Test void startingAHandshakeAgainWithAReleasedPeerIsCountedOnce() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(6)));
        assertEquals(List.of(c3.id),a.released);assertEquals(0,a.dispatcher.statistics().rehandshakeAfterRelease());
        a.slotFree=true;offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c3.contact()));
        assertEquals(1,a.dispatcher.statistics().rehandshakeAfterRelease());
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c3.contact()));
        assertEquals(1,a.dispatcher.statistics().rehandshakeAfterRelease(),"同じ試みを聞き直しても増えない");
    }
    @Test void aPeerThatWasNeverReleasedIsNotCountedAsARehandshake() {
        var net=new Net();var a=base(net);connected(net,a,3);connected(net,a,4);
        assertEquals(0,a.dispatcher.statistics().rehandshakeAfterRelease());
    }
    @Test void aNetworkChangeForgetsTheReleasedPeers() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(6)));
        assertEquals(List.of(c3.id),a.released);
        a.slotFree=true;a.dispatcher.networkChanged(2,new LocalNetwork(new byte[]{(byte)192,(byte)168,1,2},24));offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c3.contact()));
        assertEquals(0,a.dispatcher.statistics().rehandshakeAfterRelease(),"ネットワークが変わったら、手放した相手の覚えは捨てる");
    }
    @Test void theReleasedTableKeepsThirtyTwoPeersAndForgetsTheOldestFirst() {
        var net=new Net();var a=base(net);
        // 1 台つなぎ→31 秒待つ→新しい候補を始めて 1 台手放す、を 34 回。新しい候補の試みはすぐ閉じる（同時 8 件の上限を避ける）。
        for(int n=3;n<=36;n++) {
            a.slotFree=true;connected(net,a,n);
            a.slotFree=false;net.advance(GRACE);
            net.rig(DhtIdTest.id(100+n));offer(a,100+n);
            assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(100+n)),"round "+n);
            assertEquals(n-2,a.released.size(),"round "+n);
            a.node.candidates().release(a.node.candidates().attemptFor(DhtIdTest.id(100+n)).orElseThrow());
        }
        assertEquals(34,a.released.size());
        a.slotFree=true;
        // 一番古く手放した 3 は 32 件の外へ出ているので、再握手として数えない。
        offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(3)));
        a.node.candidates().release(a.node.candidates().attemptFor(DhtIdTest.id(3)).orElseThrow());
        assertEquals(0,a.dispatcher.statistics().rehandshakeAfterRelease());
        // 一番新しく手放した 36 は残っている。
        offer(a,36);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(36)));
        a.node.candidates().release(a.node.candidates().attemptFor(DhtIdTest.id(36)).orElseThrow());
        assertEquals(1,a.dispatcher.statistics().rehandshakeAfterRelease());
        // 32 件目に当たる 5 も残っていて、4 は外へ出ている。
        offer(a,4);assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(4)));
        a.node.candidates().release(a.node.candidates().attemptFor(DhtIdTest.id(4)).orElseThrow());
        assertEquals(1,a.dispatcher.statistics().rehandshakeAfterRelease(),"4 は 33 番目に古いので、もう覚えていない");
        offer(a,5);assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(contactOf(5)));
        assertEquals(2,a.dispatcher.statistics().rehandshakeAfterRelease());
    }

    // ---- 探りの枠が尽きた数 ----
    @Test void aPeerWhoseDailyProbeBudgetIsUsedUpIsTreatedAsNoAndCounted() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));net.dropTo.add(c.id);
        assertEquals(0,a.dispatcher.statistics().probeBudgetBlocked());
        for(int i=0;i<40;i++) {
            a.dispatcher.peers().forget(c.id);
            a.dispatcher.sessionStarted(c.id.bytes(),filled(16,i+1));net.pump();
            net.advance(60*SECOND);
        }
        assertTrue(a.dispatcher.statistics().probeBudgetBlocked()>=1);
        assertEquals(DhtPeers.State.NO,a.dispatcher.peers().state(c.id));
    }
}
