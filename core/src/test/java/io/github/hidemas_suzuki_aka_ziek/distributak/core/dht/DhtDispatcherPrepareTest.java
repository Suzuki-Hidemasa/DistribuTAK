// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.List;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 D: 探索が欲しい相手の握手を始める（prepare）・探りの結果で試みを閉じる・自分が始めた揮発の相手を手放す。
 * 握手そのもの（UDP・Noise）は外側が駆動するので、試験では sessionStarted を呼んで握手の成功を真似る。
 * 試験の失敗の文にも、番地・端末の番号・鍵は出さない。
 */
class DhtDispatcherPrepareTest {
    static void offer(Rig r,int n) {
        DhtWire.NodeContact c=nodeContact(n);
        assertTrue(r.node.candidates().offer(DhtIdTest.id(200+n),new DhtCandidates.Candidate(c.node(),c.ipv4(),c.port(),c.handshakeKey())));
    }
    /** a の核から見て、b の握手を成功させる（両側にセッションができる）。 */
    static void handshake(Net net,Rig a,Rig b) {
        a.dispatcher.sessionStarted(b.id.bytes(),SESSION);b.dispatcher.sessionStarted(a.id.bytes(),SESSION);net.pump();
    }
    static Rig base(Net net) {
        Rig a=net.rig(record(1,1,NOW).nodeId());a.network();return a;
    }

    @Test void aYesPeerWithASessionIsReady() {
        var net=new Net();var p=pair(net);
        assertEquals(DhtTransport.Readiness.READY,p[0].dispatcher.prepare(p[1].contact()));
    }
    @Test void aNoPeerIsUnavailable() {
        var net=new Net();var a=net.rig(DhtIdTest.id(1));var c=net.rig(DhtIdTest.id(3));net.dropTo.add(c.id);
        a.dispatcher.sessionStarted(c.id.bytes(),SESSION);net.pump();net.advance(3*SECOND);
        assertEquals(DhtPeers.State.NO,a.dispatcher.peers().state(c.id));
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(c.contact()));
    }
    @Test void aPeerWithNoCandidateAndNoSessionIsUnavailableAndStartsNothing() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(c.contact()));
        assertEquals(0,a.node.candidates().startsInWindow());assertTrue(net.sent.isEmpty());
    }
    @Test void aCandidateStartsOneHandshakeAttemptAndAskingAgainDoesNotCountAnotherStart() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        assertTrue(a.node.candidates().isActive(c.id));assertEquals(1,a.node.candidates().startsInWindow());
        for(int i=0;i<5;i++)assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        assertEquals(1,a.node.candidates().startsInWindow());assertEquals(1,a.node.candidates().active());
    }
    @Test void afterTheHandshakeAndAYesAnswerTheAttemptClosesAsASuccessAndThePeerIsReady() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        handshake(net,a,c);
        assertTrue(a.dispatcher.peers().isYes(c.id));
        a.dispatcher.poll();
        assertFalse(a.node.candidates().isActive(c.id));assertEquals(0,a.node.candidates().failures());
        assertEquals(DhtTransport.Readiness.READY,a.dispatcher.prepare(c.contact()));
        assertEquals(1,a.node.candidates().startsInWindow());
    }
    @Test void whileTheProbeAnswerIsStillWaitedForTheAttemptStaysOpenAndThePeerIsConnecting() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);net.dropTo.add(c.id);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        a.dispatcher.sessionStarted(c.id.bytes(),SESSION);net.pump();
        net.advance(SECOND);
        assertEquals(DhtPeers.State.PROBING,a.dispatcher.peers().state(c.id));
        assertTrue(a.node.candidates().isActive(c.id));
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
    }
    @Test void aSilentPeerClosesTheAttemptAsAFailureAndIsReleasedAtOnce() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);net.dropTo.add(c.id);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        a.dispatcher.sessionStarted(c.id.bytes(),SESSION);net.pump();
        net.advance(3*SECOND);
        assertFalse(a.node.candidates().isActive(c.id));assertEquals(1,a.node.candidates().failures());
        assertEquals(List.of(c.id),a.released);
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(c.contact()));
    }
    @Test void aPeerThatNeverAnswersTheHandshakeIsFailedByTheAttemptClockAndThePeerIsUnavailable() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        a.node.candidates().firstSent(a.node.candidates().attemptFor(c.id).get());
        net.advance(31*SECOND);
        assertFalse(a.node.candidates().isActive(c.id));assertEquals(1,a.node.candidates().failures());
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(c.contact()));
    }
    @Test void aNinthCandidateIsBusyWhenEightAttemptsRunAndNothingCanBeReleasedAndItsCandidateStays() {
        var net=new Net();var a=base(net);
        for(int n=3;n<=11;n++){net.rig(DhtIdTest.id(n));offer(a,n);}
        for(int n=3;n<=10;n++)assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(n))));
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(11))));
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(11))));
        assertEquals(8,a.node.candidates().startsInWindow());assertEquals(1,a.node.candidates().size());
        assertTrue(a.released.isEmpty());
        // 同時 8 件の上限で断られたので、手放せる相手がいなかった数（nothingReleasable）には入らない。
        assertEquals(2,a.dispatcher.statistics().busy());assertEquals(0,a.dispatcher.statistics().nothingReleasable());
    }

    // ---- 手放し（T9・T10・T12b） ----

    /** a が candidate から握手を始めた YES の相手 n を作る。 */
    static Rig connected(Net net,Rig a,int n) {
        Rig c=net.rig(DhtIdTest.id(n));offer(a,n);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        handshake(net,a,c);a.dispatcher.poll();
        assertTrue(a.dispatcher.peers().isYes(c.id));assertFalse(a.node.candidates().isActive(c.id));
        return c;
    }
    static final long GRACE=31*SECOND;

    @Test void aFullSlotReleasesAYesPeerOutsideTheTableBeforeOneInTheTableAndOnlyOnePeer() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);var c4=connected(net,a,4);var c5=connected(net,a,5);
        net.advance(GRACE);
        assertTrue(a.node.routing().contains(c3.id));assertTrue(a.node.routing().contains(c4.id));assertTrue(a.node.routing().contains(c5.id));
        a.node.routing().remove(c4.id);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(List.of(c4.id),a.released);
        assertEquals(1,a.dispatcher.statistics().releasedOutsideTable());assertEquals(0,a.dispatcher.statistics().releasedCrowdedBucket());
        assertEquals(DhtPeers.State.UNKNOWN,a.dispatcher.peers().state(c4.id));
    }
    @Test void whenAllAreInTheTableOneOfThemIsReleasedAndTheOthersStay() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);var c4=connected(net,a,4);
        net.advance(GRACE);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(1,a.released.size());assertEquals(1,a.dispatcher.statistics().releasedCrowdedBucket());
        Rig kept=a.released.contains(c3.id)?c4:c3;
        assertTrue(a.dispatcher.peers().isYes(kept.id));assertTrue(a.node.routing().contains(kept.id));
    }
    @Test void aPeerWithinThirtySecondsOfItsSessionIsNotReleased() {
        var net=new Net();var a=base(net);connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        net.advance(29*SECOND);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());
        net.advance(2*SECOND);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(1,a.released.size());
    }
    @Test void aPeerUsedAsAPublishDestinationIsNotReleased() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.dispatcher.setPublishInUse(id->id.equals(c3.id));
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());
        a.dispatcher.setPublishInUse(id->false);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(List.of(c3.id),a.released);
    }
    @Test void aPeerThatMovedToAStoredPeerIsNotReleasedAndIsForgottenFromTheTable() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.storedPeers.add(c3.id);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());assertTrue(a.dispatcher.peers().isYes(c3.id));
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
    }
    @Test void aPeerWeDidNotStartIsNeverReleased() {
        var net=new Net();var a=base(net);var p=net.rig(DhtIdTest.id(3));handshake(net,a,p);
        assertTrue(a.dispatcher.peers().isYes(p.id));
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());
    }
    @Test void aPeerThatReconnectedByItselfIsNotReleased() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.dispatcher.sessionStarted(c3.id.bytes(),SESSION);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());
    }
    @Test void aReleasedPeerCanBeStartedAgainOnlyThroughItsCandidate() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);net.advance(GRACE);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(List.of(c3.id),a.released);assertFalse(a.node.routing().contains(c3.id));
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(c3.contact()));
        a.slotFree=true;offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c3.contact()));
    }
    @Test void aSilentPeerIsReleasedAtOnceEvenWhenTheSlotIsNotFull() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);net.dropTo.add(c.id);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        a.dispatcher.sessionStarted(c.id.bytes(),SESSION);net.pump();net.advance(3*SECOND);
        assertEquals(List.of(c.id),a.released);assertEquals(1,a.dispatcher.statistics().releasedNo());
    }
    @Test void theStartedTableKeepsAtMostThirtyTwoPeersAndCountsTheOnesItDropped() {
        var net=new Net();var a=base(net);
        // 1 台ごとに 11 秒あける（32 台で約 6 分。5 分 64 件の窓には当たらない）。
        for(int n=3;n<35;n++){connected(net,a,n);net.advance(11*SECOND);}
        assertEquals(0,a.dispatcher.statistics().droppedStarted());
        net.rig(DhtIdTest.id(40));offer(a,40);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(40))));
        assertEquals(1,a.dispatcher.statistics().droppedStarted());
    }

    // ---- pin（招待した相手を待つ間）・BUSY の開始の数・同じ相手を欲しがる 2 つの探索（答え 182 の 8・185） ----
    @Test void whileAPinRemainsNothingIsStartedAndThePeerIsUnavailable() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);
        a.startAllowed=false;
        assertEquals(DhtTransport.Readiness.UNAVAILABLE,a.dispatcher.prepare(c.contact()));
        assertFalse(a.node.candidates().isActive(c.id));assertEquals(0,a.node.candidates().startsInWindow());
        assertTrue(net.sent.isEmpty());assertTrue(a.released.isEmpty());
        // pin が外れたら、同じ候補で握手を始められる（候補は捨てていない）。
        a.startAllowed=true;
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        assertEquals(1,a.node.candidates().startsInWindow());
    }
    @Test void aPinDoesNotHideAPeerThatIsAlreadyReadyOrBeingConnected() {
        var net=new Net();var a=base(net);var c=connected(net,a,3);var d=net.rig(DhtIdTest.id(4));offer(a,4);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(d.contact()));
        a.startAllowed=false;
        assertEquals(DhtTransport.Readiness.READY,a.dispatcher.prepare(c.contact()));
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(d.contact()));
    }
    @Test void aBusyAnswerKeepsTheCandidateAndAskingEveryPollCountsOneStartOnlyWhenItStarts() {
        var net=new Net();var a=base(net);
        for(int n=3;n<11;n++){
            net.rig(DhtIdTest.id(n));offer(a,n);assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(n))));
            // 外側が 1 通目を出したことにする（出さない試みは 30 秒の諦めの数え始めがないため閉じない）。
            a.node.candidates().attemptFor(DhtIdTest.id(n)).ifPresent(a.node.candidates()::firstSent);
        }
        var w=net.rig(DhtIdTest.id(12));offer(a,12);
        for(int i=0;i<5;i++)assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(w.contact()));
        assertEquals(8,a.node.candidates().startsInWindow());assertEquals(5,a.dispatcher.statistics().busy());
        // 試みの 1 つが閉じたら、残しておいた候補から始められ、開始の数はちょうど 1 つ増える。
        net.advance(31*SECOND);a.dispatcher.poll();
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(w.contact()));
        assertEquals(1,a.node.candidates().startsInWindow()-8);
    }
    @Test void twoAsksForTheSamePeerStartOneHandshakeAndBothSeeItReady() {
        var net=new Net();var a=base(net);var c=net.rig(DhtIdTest.id(3));offer(a,3);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(c.contact()));
        assertEquals(1,a.node.candidates().startsInWindow());assertEquals(1,a.node.candidates().active());
        handshake(net,a,c);a.dispatcher.poll();
        assertEquals(DhtTransport.Readiness.READY,a.dispatcher.prepare(c.contact()));
        assertEquals(DhtTransport.Readiness.READY,a.dispatcher.prepare(c.contact()));
    }

    // ---- 直近 30 秒の動き（答え 187 の必修 2）: 握手の開始からではなく、最後のやり取りから数える ----
    @Test void aPeerThatAnsweredWithinThirtySecondsIsNotReleasedEvenWhenItsSessionIsOld() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        net.advance(25*SECOND);
        assertTrue(a.dispatcher.send(c3.contact(),ping(1)));net.pump(); // 返事を受ける（開始から 25 秒）
        net.advance(10*SECOND); // 開始から 35 秒・返事から 10 秒
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());
        net.advance(21*SECOND); // 返事から 31 秒
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(List.of(c3.id),a.released);
    }
    @Test void aPeerWhoseRequestWeAnsweredWithinThirtySecondsIsNotReleased() {
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        net.advance(25*SECOND);
        assertTrue(c3.dispatcher.send(a.contact(),ping(1)));net.pump(); // a が c3 の要求に答える
        net.advance(10*SECOND);
        assertEquals(DhtTransport.Readiness.BUSY,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertTrue(a.released.isEmpty());
        net.advance(21*SECOND);
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(List.of(c3.id),a.released);
    }
    @Test void aRefusalWithoutAReplyFromTheResponderDoesNotKeepThePeerAlive() {
        // 決めた細目: 要求に答えたと数えるのは、返事を実際に作った分岐だけ。鍵違いの断り（INVALID の返事）は数えない。
        var net=new Net();var a=base(net);var c3=connected(net,a,3);
        a.slotFree=false;net.rig(DhtIdTest.id(6));offer(a,6);
        net.advance(25*SECOND);
        byte[] wire=DhtWire.store(GROUP,filled(16,5),DhtIdTest.id(77),record(1,1,NOW).encode());
        a.dispatcher.receive(c3.id.bytes(),SESSION,wire);net.pump();
        net.advance(6*SECOND); // 開始から 31 秒
        assertEquals(DhtTransport.Readiness.CONNECTING,a.dispatcher.prepare(new Contact(DhtIdTest.id(6))));
        assertEquals(List.of(c3.id),a.released);
    }
}
