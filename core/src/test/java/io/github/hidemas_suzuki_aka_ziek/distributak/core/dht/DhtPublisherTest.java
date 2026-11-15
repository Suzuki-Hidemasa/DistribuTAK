// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 D（T15・T16・T17）: 自分の発見の記録を、鍵に近い最大 20 台（自分を含む）へ預ける。
 * 送り先の数・送れた数・ACK の数は別に数える。置き直すのは発行者だけ。試験の失敗の文に番地・番号・鍵は出さない。
 */
class DhtPublisherTest {
    static final long HOUR=DhtPublisher.INTERVAL_NANOS;

    /** a（発行者）に others 台をつなぐ。a の番号は record(1,…) の nodeId。 */
    static final class Setup {
        final Net net=new Net();
        final Rig a=net.rig(record(1,1,NOW).nodeId());
        final List<Rig> others=new ArrayList<>();
        final DhtPublisher publisher;
        final byte[] wire=record(1,1,NOW).encode();
        Setup(int others) {
            for(int n=2;n<2+others;n++){Rig r=net.rig(DhtIdTest.id(n));this.others.add(r);net.connect(a,r);net.advance(11*SECOND);net.pump();}
            // 探りは全体で毎分 30 通までなので、時計を進めて全員を YES にしてから公開する。
            for(Rig r:this.others)assertTrue(a.dispatcher.peers().isYes(r.id),"Every peer must be YES before publishing");
            publisher=new DhtPublisher(a.node,a.dispatcher,a.store);
        }
        long now(){return net.nanos.get();}
        /** 1 歩: 探索を進め、公開を進め、待ち行列を流し、時計を進める。 */
        void step() {
            a.node.poll();publisher.poll(now());net.pump();net.advance(SECOND/10);
        }
        void runUntilIdle(int maxSteps) {
            for(int i=0;i<maxSteps&&publisher.active();i++)step();
        }
        int storesSentBy(Rig from) {
            int n=0;
            for(Packet p:net.sent)if(p.from()==from&&p.message().op()==DhtWire.Op.STORE)n++;
            return n;
        }
        int holders() {
            int n=0;
            for(Rig r:others)if(r.store.size()>0)n++;
            return n;
        }
        boolean anyInUse() {
            for(Rig r:others)if(publisher.inUse(r.id))return true;
            return false;
        }
        /** 探索が終わって STORE を送り始めるところまで進める（返事はまだ流さない）。 */
        void runUntilSending(int maxSteps) {
            for(int i=0;i<maxSteps&&!anyInUse();i++){a.node.poll();publisher.poll(now());if(anyInUse())return;net.pump();net.advance(SECOND/10);}
        }
    }

    // ---- T15 公開 ----

    @Test void publishesToTheTwentyClosestIncludingSelfWhenThereAreMoreThanTwenty() {
        var s=new Setup(25);
        assertTrue(s.publisher.publishDue(s.now()));
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        assertFalse(s.publisher.active());
        var report=s.publisher.lastReport();
        assertNotNull(report);
        // 自分も数に入れて、鍵に近い 20 台。自分がその中に入るかどうかは鍵と番号の距離で決まる。
        DhtId key=record(1,1,NOW).key(),self=s.a.id;
        List<DhtId> ranked=new ArrayList<>();ranked.add(self);
        for(Rig r:s.others)ranked.add(r.id);
        ranked.sort((x,y)->key.compareDistance(x,y));
        List<DhtId> chosen=ranked.subList(0,DhtLimits.K);
        boolean selfIn=chosen.contains(self);
        int others=DhtLimits.K-(selfIn?1:0);
        assertEquals(others,report.destinations());assertEquals(others,report.sent());assertEquals(others,report.acked());
        assertEquals(0,report.refused());assertEquals(0,report.expired());
        assertEquals(selfIn,report.selfStored());assertEquals(selfIn?1:0,s.a.store.size());
        assertEquals(others,s.holders());
        for(Rig r:s.others)assertEquals(chosen.contains(r.id)?1:0,r.store.size(),"Only the twenty closest hold the record");
    }
    @Test void selfIsStoredLocallyWhenItIsAmongTheClosest() {
        // 近い 20 台に自分が入る形を作る: 相手が少なければ必ず入る。
        var s=new Setup(3);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        assertTrue(s.publisher.lastReport().selfStored());assertEquals(1,s.a.store.size());
        assertEquals(1,s.a.store.counts().ownAccepted(),"自分の記録の受け入れとして数える");assertEquals(0,s.a.store.counts().ownRejected());
        assertEquals(0,s.a.store.counts().screenRejected(),"他の相手から受けた拒否には混ぜない");
    }
    @Test void publishesToEveryPeerWhenThereAreFewerThanTwenty() {
        var s=new Setup(5);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        var report=s.publisher.lastReport();
        assertEquals(5,report.destinations());assertEquals(5,report.sent());assertEquals(5,report.acked());
        assertTrue(report.selfStored());assertEquals(5,s.holders());
    }
    @Test void destinationsSentAndAckedAreCountedSeparately() {
        var s=new Setup(6);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilSending(600);
        assertTrue(s.anyInUse());
        // 1 台だけ、STORE が届かない（返事が来ない）ようにする。
        Rig lost=s.others.get(2);s.net.queue.removeIf(p->p.to()==lost);
        s.runUntilIdle(600);
        var report=s.publisher.lastReport();
        assertEquals(6,report.destinations());assertEquals(6,report.sent());
        assertEquals(5,report.acked());assertEquals(1,report.expired());assertEquals(0,report.refused());
        assertEquals(0,lost.store.size());assertEquals(5,s.holders());
    }
    @Test void aStoreThatCannotBeStartedDoesNotMarkThePeerInUseAndIsNotSentAgainRightAway() {
        var s=new Setup(4);
        // 探索のあいだは送れるが、STORE を送るときだけ送れない。送り始めの直前に切り替える。
        assertTrue(s.publisher.publish(s.wire,s.now()));
        for(int i=0;i<600&&s.publisher.active();i++) {
            s.a.node.poll();
            // 探索が終わったら publisher.poll が STORE を送る。その前に送れなくする。
            if(s.a.dispatcher.pendingCount()==0)s.a.sendOk=false;
            s.publisher.poll(s.now());s.net.pump();s.net.advance(SECOND/10);
        }
        s.a.sendOk=true;
        assertFalse(s.publisher.active());
        var report=s.publisher.lastReport();
        assertEquals(4,report.destinations());assertEquals(0,report.sent());assertEquals(0,report.acked());
        assertEquals(0,s.storesSentBy(s.a));
        for(Rig r:s.others)assertFalse(s.publisher.inUse(r.id));
        // すぐには置き直さない。次の置き直し（1 時間後）まで待つ。
        for(int i=0;i<200;i++)s.step();
        assertEquals(0,s.storesSentBy(s.a));
        assertFalse(s.publisher.publishDue(s.now()));
    }
    @Test void aPeerWithAStoreInFlightIsInUseUntilTheResultArrives() {
        var s=new Setup(5);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilSending(600);
        for(Rig r:s.others)assertTrue(s.publisher.inUse(r.id),"Every destination is in use while its STORE is in flight");
        s.runUntilIdle(600);
        for(Rig r:s.others)assertFalse(s.publisher.inUse(r.id));
    }
    @Test void aStoreResultOfAnotherGenerationEndsTheMarkAndTheCountsItAsExpired() {
        var s=new Setup(3);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilSending(600);
        assertTrue(s.anyInUse());
        // 返事を別の世代へ結び付ける。dispatcher は返事を捨て、使用中の印を外す。
        s.a.peerGeneration=5;
        s.runUntilIdle(600);
        assertFalse(s.publisher.active());assertFalse(s.anyInUse());
        var report=s.publisher.lastReport();
        assertEquals(3,report.sent());assertEquals(0,report.acked());assertEquals(3,report.expired());
    }
    @Test void aStoreWithNoAnswerAndNoNoticeIsEndedBySafetyValveAfterTenSeconds() {
        var s=new Setup(3);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilSending(600);
        assertTrue(s.anyInUse());
        // dispatcher の期限切れの知らせも来ない形: 公開側だけを時間で進める（dispatcher の poll は呼ばない）。
        long t=s.now();
        s.publisher.poll(t+DhtPublisher.SENDING_LIMIT_NANOS-1);
        assertTrue(s.publisher.active());assertTrue(s.anyInUse());
        s.publisher.poll(t+DhtPublisher.SENDING_LIMIT_NANOS);
        assertFalse(s.publisher.active());assertFalse(s.anyInUse());
        var report=s.publisher.lastReport();
        assertEquals(3,report.sent());assertEquals(3,report.expired());assertEquals(0,report.acked());
    }
    @Test void aPeerThatSessionClosedWhileItsStoreWasInFlightIsCountedAsExpiredNotAcked() {
        var s=new Setup(3);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilSending(600);
        Rig gone=s.others.get(0);
        s.a.dispatcher.volatilePeerForgotten(gone.id.bytes());
        s.runUntilIdle(600);
        var report=s.publisher.lastReport();
        assertEquals(2,report.acked());assertEquals(1,report.expired());
        assertFalse(s.publisher.inUse(gone.id));
    }
    @Test void aPublishIsDueAfterOneHourAndNotBefore() {
        var s=new Setup(3);
        long t0=s.now();
        assertTrue(s.publisher.publish(s.wire,t0));
        s.runUntilIdle(600);
        assertFalse(s.publisher.publishDue(t0+HOUR-1));
        assertTrue(s.publisher.publishDue(t0+HOUR));
    }
    @Test void aNewPublishIsNotStartedWhileOneIsInProgress() {
        var s=new Setup(3);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        assertTrue(s.publisher.active());
        assertFalse(s.publisher.publishDue(s.now()+2*HOUR));
        assertFalse(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        assertTrue(s.publisher.publish(s.wire,s.now()));
    }
    /** 推奨 2: 探索が同時 4 件のあいだは例外を外へ出さず false。状態は変えず、公開は期限のままになり、枠が空いたら始まる。 */
    @Test void aPublishWhileFourLookupsAreRunningReturnsFalseWithoutThrowingAndStartsWhenASlotIsFree() {
        var s=new Setup(3);
        List<DhtNode.Lookup> busy=new ArrayList<>();
        for(int i=0;i<DhtLimits.MAX_LOOKUPS;i++)busy.add(s.a.node.findNode(DhtIdTest.id(100+i)));
        assertEquals(DhtLimits.MAX_LOOKUPS,s.a.node.activeLookups());
        assertFalse(s.a.node.canStartLookup());
        assertTrue(s.publisher.publishDue(s.now()));
        assertDoesNotThrow(()->assertFalse(s.publisher.publish(s.wire,s.now())));
        assertFalse(s.publisher.active(),"A refused start must not leave the publisher in a running state");
        assertTrue(s.publisher.publishDue(s.now()),"A publish that could not start must stay due");
        // 探索が終わるまで進める。
        for(int i=0;i<2000&&!s.a.node.canStartLookup();i++){s.a.node.poll();s.net.pump();s.net.advance(SECOND/10);}
        assertTrue(s.a.node.canStartLookup());
        for(DhtNode.Lookup l:busy)assertTrue(l.done());
        assertTrue(s.publisher.publish(s.wire,s.now()));
        assertTrue(s.publisher.active());
        s.runUntilIdle(600);
        assertFalse(s.publisher.active());
        assertNotNull(s.publisher.lastReport());
    }
    @Test void thePublisherPutsTheRecordAgainAfterOneHourAndOnlyThePublisherDoes() {
        var s=new Setup(4);
        long t0=s.now();
        assertTrue(s.publisher.publish(s.wire,t0));
        s.runUntilIdle(600);
        int first=s.storesSentBy(s.a);
        assertEquals(4,first);
        // 1 時間のあいだ、預かった側は何も置き直さない。
        s.net.advance(HOUR+SECOND);
        for(Rig r:s.others)assertEquals(0,s.storesSentBy(r));
        assertTrue(s.publisher.publishDue(s.now()));
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        assertEquals(2*first,s.storesSentBy(s.a));
        for(Rig r:s.others)assertEquals(0,s.storesSentBy(r));
        // 2 回目は同じ版なので、預かった側は DUPLICATE と答える。送った数と ACK の数は同じになる。
        var report=s.publisher.lastReport();
        assertEquals(4,report.sent());assertEquals(4,report.acked());
    }
    @Test void aChangedRecordIsDueRightAway() {
        var s=new Setup(3);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        assertFalse(s.publisher.publishDue(s.now()));
        s.publisher.recordChanged();
        assertTrue(s.publisher.publishDue(s.now()));
    }
    @Test void aMalformedRecordIsNotPublished() {
        var s=new Setup(3);
        assertFalse(s.publisher.publish(new byte[]{1,2,3},s.now()));
        assertFalse(s.publisher.active());
        assertEquals(0,s.storesSentBy(s.a));
    }
    @Test void withNoPeersOnlyTheOwnStoreIsFilled() {
        var s=new Setup(0);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        var report=s.publisher.lastReport();
        assertEquals(0,report.destinations());assertEquals(0,report.sent());
        assertTrue(report.selfStored());assertEquals(1,s.a.store.size());
    }

    // ---- T15 時計の戻り ----

    @Test void aClockThatGoesBackDropsTheInFlightMarksAndMakesAPublishDue() {
        var s=new Setup(4);
        long t0=s.now();
        assertTrue(s.publisher.publish(s.wire,t0));
        s.runUntilSending(600);
        assertTrue(s.anyInUse());
        assertTrue(s.publisher.publishDue(t0-SECOND));
        assertFalse(s.publisher.active());
        for(Rig r:s.others)assertFalse(s.publisher.inUse(r.id));
        assertTrue(s.publisher.publishDue(t0));
    }

    // ---- T16 ネットワーク変更 ----

    @Test void aNetworkChangeDropsTheInProgressPublishAndMakesANewOneDue() {
        var s=new Setup(4);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilSending(600);
        assertTrue(s.anyInUse());
        s.a.network();s.publisher.networkChanged();
        assertFalse(s.publisher.active());
        for(Rig r:s.others)assertFalse(s.publisher.inUse(r.id));
        assertTrue(s.publisher.publishDue(s.now()));
        // 流れてきた古い世代の返事は、数え方にも使用中の印にも影響しない。
        var before=s.publisher.lastReport();
        s.net.pump();
        assertSame(before,s.publisher.lastReport());
    }
    @Test void aNetworkChangeDuringTheLookupDropsItToo() {
        var s=new Setup(4);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        assertTrue(s.publisher.active());
        s.publisher.networkChanged();
        assertFalse(s.publisher.active());
        assertTrue(s.publisher.publishDue(s.now()));
        assertEquals(0,s.storesSentBy(s.a));
    }

    // ---- T17 ログに出さない ----

    static String hex(byte[] bytes){StringBuilder b=new StringBuilder();for(byte x:bytes)b.append(String.format("%02x",x));return b.toString();}

    @Test void textsOfThePublisherAndTheReportDoNotContainIdsKeysOrAddresses() {
        var s=new Setup(5);
        assertTrue(s.publisher.publish(s.wire,s.now()));
        s.runUntilIdle(600);
        var record=record(1,1,NOW);
        Set<String> secrets=new HashSet<>();
        secrets.add(hex(record.nodeId().bytes()));secrets.add(hex(record.key().bytes()));
        for(Rig r:s.others)secrets.add(hex(r.id.bytes()));
        secrets.add("192.168");secrets.add("50000");
        String[] texts={s.publisher.toString(),String.valueOf(s.publisher.lastReport())};
        for(String text:texts)for(String secret:secrets)assertFalse(text.contains(secret),"A text must not contain an id, a key or an address");
    }
}
