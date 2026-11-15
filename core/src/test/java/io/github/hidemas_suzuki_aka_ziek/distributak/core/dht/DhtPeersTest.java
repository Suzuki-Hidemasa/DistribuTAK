// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C2: 相手が DHT を話せるかの探り。r19 の相手の拒否の数を増やし続けないための上限を確かめる。 */
class DhtPeersTest {
    static final long SECOND=1_000_000_000L,MINUTE=60*SECOND,HOUR=60*MINUTE,DAY=24*HOUR;
    static final class Fixture {
        final AtomicLong nanos=new AtomicLong(1_000*SECOND);
        final List<DhtId> sent=new ArrayList<>();
        boolean accept=true;
        final DhtPeers peers=new DhtPeers(nanos::get,(peer,session)->{if(accept)sent.add(peer);return accept;});
        int sentTo(DhtId peer){int n=0;for(DhtId p:sent)if(p.equals(peer))n++;return n;}
        void advance(long nanosToAdd){nanos.addAndGet(nanosToAdd);peers.tick();}
    }
    static DhtId id(int n){return DhtIdTest.id(n);}
    static byte[] session(int n){byte[] b=new byte[16];b[0]=(byte)n;b[1]=(byte)(n>>8);return b;}

    @Test void aNewSessionProbesOnceAndAPongMakesThePeerYes() {
        var f=new Fixture();
        f.peers.sessionStarted(id(1),session(1));
        assertEquals(1,f.sentTo(id(1)));assertEquals(DhtPeers.State.PROBING,f.peers.state(id(1)));
        assertFalse(f.peers.isYes(id(1)));
        assertTrue(f.peers.probeAnswered(id(1),session(1)));
        assertTrue(f.peers.isYes(id(1)));assertEquals(1,f.peers.yesCount());
        // 同じ相手の 2 回目の PONG は新しい証拠にしない。
        assertFalse(f.peers.probeAnswered(id(1),session(1)));
    }
    @Test void aPongForAnotherSessionIsIgnored() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));
        assertFalse(f.peers.probeAnswered(id(1),session(2)));assertFalse(f.peers.probeAnswered(id(2),session(1)));
        assertFalse(f.peers.isYes(id(1)));
    }
    @Test void noPongForThreeSecondsMakesThePeerNo() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));
        f.advance(2*SECOND);assertEquals(DhtPeers.State.PROBING,f.peers.state(id(1)));
        f.advance(SECOND);assertEquals(DhtPeers.State.NO,f.peers.state(id(1)));assertEquals(1,f.peers.noCount());
    }
    @Test void theScheduleIsSixProbesAtCumulativeTimesAndThenItStops() {
        var f=new Fixture();long start=f.nanos.get();f.peers.sessionStarted(id(1),session(1));
        long[] expected={0,60,180,420,900,1860};
        for(int i=1;i<expected.length;i++) {
            // 次の探りの 1 秒前にはまだ送らない。
            f.nanos.set(start+expected[i]*SECOND-SECOND);f.peers.tick();assertEquals(i,f.sentTo(id(1)),"before probe "+(i+1));
            f.nanos.set(start+expected[i]*SECOND);f.peers.tick();assertEquals(i+1,f.sentTo(id(1)),"at probe "+(i+1));
        }
        f.advance(10*HOUR);assertEquals(6,f.sentTo(id(1)));assertEquals(DhtPeers.State.NO,f.peers.state(id(1)));
    }
    @Test void aPeerGetsAtMostTwelveProbesInADayWhateverTheTrigger() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));
        for(int i=0;i<200;i++) {
            f.advance(2*MINUTE);
            if(i%4==0)f.peers.retryAll();else if(i%4==1)f.peers.hint(id(1),session(1));
            else if(i%4==2)f.peers.sessionStarted(id(1),session(100+i));else f.peers.networkChanged();
        }
        // 200 回 × 2 分 = 約 6.7 時間。24 時間の窓の中は 12 通まで。
        assertTrue(f.sentTo(id(1))<=12,"sent "+f.sentTo(id(1)));
        assertTrue(f.sentTo(id(1))>=6);
    }
    @Test void theDailyBudgetRefillsAfterTwentyFourHours() {
        var f=new Fixture();
        for(int i=0;i<30;i++){f.peers.sessionStarted(id(1),session(i+1));f.advance(2*MINUTE);}
        assertEquals(12,f.sentTo(id(1)));
        f.advance(DAY);f.peers.sessionStarted(id(1),session(999));
        assertEquals(13,f.sentTo(id(1)));
    }
    @Test void atMostThirtyProbesGoOutInOneMinuteForTheWholeDevice() {
        var f=new Fixture();
        for(int n=1;n<=40;n++)f.peers.sessionStarted(id(n),session(n));
        assertEquals(DhtPeers.GLOBAL_PER_MINUTE,f.sent.size());
        assertEquals(30,DhtPeers.GLOBAL_PER_MINUTE);
        // 残りの 10 台の 1 通目は次の分に送る（予定の再送より先）。その分も 30 通まで。
        f.advance(MINUTE);
        for(int n=1;n<=40;n++){assertTrue(f.sentTo(id(n))>=1,"peer "+n);}
        assertEquals(2*DhtPeers.GLOBAL_PER_MINUTE,f.sent.size());
    }
    @Test void tenPeersAllGetTheirFirstProbeInTheFirstMinuteNowThatTheLimitIsThirty() {
        var f=new Fixture();
        for(int n=1;n<=10;n++)f.peers.sessionStarted(id(n),session(n));
        assertEquals(10,f.sent.size());
        for(int n=1;n<=10;n++){assertEquals(1,f.sentTo(id(n)),"peer "+n);}
    }
    @Test void groupKeyRenewalWhereEverySessionChangesAtOnceStaysInsideTheGlobalLimit() {
        var f=new Fixture();
        for(int n=1;n<=100;n++)f.peers.sessionStarted(id(n),session(n));
        assertEquals(DhtPeers.GLOBAL_PER_MINUTE,f.sent.size());
        for(int minute=1;minute<=3;minute++){f.advance(MINUTE);assertTrue(f.sent.size()<=DhtPeers.GLOBAL_PER_MINUTE*(minute+1),"minute "+minute);}
    }
    @Test void forgettingAVolatilePeerAndRejoiningOneHundredTimesStaysInsideTwelveProbes() {
        var f=new Fixture();
        for(int i=0;i<100;i++){f.peers.forget(id(1));f.peers.sessionStarted(id(1),session(i+1));f.advance(MINUTE);}
        assertTrue(f.sentTo(id(1))<=12,"sent "+f.sentTo(id(1)));
        assertTrue(f.sentTo(id(1))>=6,"sent "+f.sentTo(id(1))); // 実際に探りを送ったと分かる下限
    }
    @Test void aNetworkChangeWhileTheVolatilePeerStaysOneHundredTimesStaysInsideTwelveProbes() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));
        for(int i=0;i<100;i++){f.peers.networkChanged();f.peers.sessionStarted(id(1),session(i+2));f.advance(MINUTE);}
        assertTrue(f.sentTo(id(1))<=12,"sent "+f.sentTo(id(1)));
        assertTrue(f.sentTo(id(1))>=6,"sent "+f.sentTo(id(1))); // 実際に探りを送ったと分かる下限
    }
    @Test void beingEvictedFromTheStateTableAndComingBackDoesNotResetTheBudget() {
        var f=new Fixture();
        for(int round=0;round<30;round++) {
            f.peers.sessionStarted(id(1),session(round+1));
            // 256 台を入れて、id(1) を状態の覚えから追い出す。
            for(int n=0;n<DhtPeers.MAX_STATES;n++){f.peers.sessionStarted(id(1000+round*300+n),session(1));}
            f.advance(2*MINUTE);
        }
        assertTrue(f.sentTo(id(1))<=12,"sent "+f.sentTo(id(1)));
        // 他の 256 台が全体の毎分 30 通の枠を使うので、id(1) に回る探りは少ない。0 通でない（実際に送った）ことだけ確かめる。
        assertTrue(f.sentTo(id(1))>=1,"sent "+f.sentTo(id(1)));
        assertTrue(f.peers.stateCount()<=DhtPeers.MAX_STATES);
    }
    @Test void whenTheBudgetTableIsFullANewPeerIsNotProbedAndIsTreatedAsNo() {
        var f=new Fixture();
        // 返事が来た相手は再送の予定が消えるので、通数の記録の表だけが育つ。6 台ごとに 1 分進める。
        for(int n=1;n<=DhtPeers.MAX_BUDGETS;n++) {
            f.peers.sessionStarted(id(n),session(1));f.peers.probeAnswered(id(n),session(1));
            if(n%6==0){f.advance(MINUTE);}
        }
        assertEquals(DhtPeers.MAX_BUDGETS,f.peers.budgetCount());
        long before=f.sent.size();
        f.peers.sessionStarted(id(5000),session(1));
        assertEquals(before,f.sent.size());assertEquals(DhtPeers.State.NO,f.peers.state(id(5000)));
        assertFalse(f.peers.isYes(id(5000)));
        assertTrue(f.peers.budgetBlocked()>=1);
        assertTrue(f.peers.budgetCount()<=DhtPeers.MAX_BUDGETS);
    }
    @Test void aYesPeerKeepsYesWhenOnlyTheSessionRenewsAndSendsNoNewProbe() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.peers.probeAnswered(id(1),session(1));
        f.peers.sessionStarted(id(1),session(2));
        assertEquals(1,f.sentTo(id(1)));assertTrue(f.peers.isYes(id(1)));assertArrayEquals(session(2),f.peers.sessionOf(id(1)));
    }
    @Test void threeRequestExpiriesInARowMakeAYesPeerUnknownAndProbeAgainButAnAnswerCountsFromZero() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.peers.probeAnswered(id(1),session(1));
        f.peers.requestExpired(id(1),session(1));f.peers.requestExpired(id(1),session(1));
        assertTrue(f.peers.isYes(id(1)));
        f.peers.requestAnswered(id(1),session(1)); // 数え直す
        f.peers.requestExpired(id(1),session(1));f.peers.requestExpired(id(1),session(1));
        assertTrue(f.peers.isYes(id(1)));assertEquals(1,f.sentTo(id(1)));
        f.peers.requestExpired(id(1),session(1));
        assertFalse(f.peers.isYes(id(1)));assertEquals(DhtPeers.State.PROBING,f.peers.state(id(1)));assertEquals(2,f.sentTo(id(1)));
        f.advance(3*SECOND);assertEquals(DhtPeers.State.NO,f.peers.state(id(1)));
    }
    @Test void anExpiryForAnotherSessionOrANonYesPeerIsNotCounted() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.peers.probeAnswered(id(1),session(1));
        for(int i=0;i<10;i++){f.peers.requestExpired(id(1),session(2));f.peers.requestExpired(id(9),session(1));}
        assertTrue(f.peers.isYes(id(1)));assertEquals(1,f.sentTo(id(1)));assertEquals(DhtPeers.State.UNKNOWN,f.peers.state(id(9)));
        f.peers.sessionStarted(id(1),session(3)); // YES のままセッションだけ変わる。数え直す
        f.peers.requestExpired(id(1),session(3));f.peers.requestExpired(id(1),session(3));
        assertTrue(f.peers.isYes(id(1)));
    }
    @Test void aHintThatRenewsTheSessionOfAYesPeerCountsTheExpiriesFromZero() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.peers.probeAnswered(id(1),session(1));
        f.peers.requestExpired(id(1),session(1));f.peers.requestExpired(id(1),session(1));
        f.peers.hint(id(1),session(2)); // YES のままセッションだけ変わる（相手から要求が届いた）。数え直す
        f.peers.requestExpired(id(1),session(2));f.peers.requestExpired(id(1),session(2));
        assertTrue(f.peers.isYes(id(1)));assertEquals(1,f.sentTo(id(1)));
        f.peers.requestExpired(id(1),session(2));
        assertEquals(DhtPeers.State.PROBING,f.peers.state(id(1)));assertEquals(2,f.sentTo(id(1)));
    }
    @Test void aPeerThatStopsAnsweringIsProbedWithinTheDailyLimitOverThreeDays() {
        var times=new ArrayList<Long>();var nanos=new AtomicLong(1_000*SECOND);
        DhtPeers[] holder=new DhtPeers[1];
        holder[0]=new DhtPeers(nanos::get,(peer,session)->{times.add(nanos.get());return true;});
        var peers=holder[0];
        peers.sessionStarted(id(1),session(1));peers.probeAnswered(id(1),session(1)); // 最初だけ答える。そのあと古い版に入れ替わる
        for(int minute=1;minute<=3*24*60;minute++) {
            nanos.addAndGet(MINUTE);peers.tick();
            if(peers.isYes(id(1))){for(int i=0;i<DhtPeers.YES_EXPIRIES;i++)peers.requestExpired(id(1),session(1));}
            if(minute%7==0)peers.hint(id(1),session(1));
        }
        assertFalse(peers.isYes(id(1)));
        assertTrue(times.size()>=DhtPeers.PEER_PER_DAY,"probes: "+times.size());
        for(int i=0;i<times.size();i++) {
            int n=0;
            for(int j=i;j<times.size()&&times.get(j)-times.get(i)<DAY;j++)n++;
            assertTrue(n<=DhtPeers.PEER_PER_DAY,"probes in one day: "+n);
        }
    }
    @Test void aNetworkChangeMakesAYesPeerUnknownAndTheNextSessionProbesOnce() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.peers.probeAnswered(id(1),session(1));
        f.peers.networkChanged();assertFalse(f.peers.isYes(id(1)));assertNull(f.peers.sessionOf(id(1)));
        f.peers.sessionStarted(id(1),session(2));
        assertEquals(2,f.sentTo(id(1)));
    }
    @Test void aValidRequestFromANoPeerStartsANewEpisodeButNotFromAYesPeer() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.advance(3*SECOND);
        assertEquals(DhtPeers.State.NO,f.peers.state(id(1)));
        f.peers.hint(id(1),session(1));assertEquals(2,f.sentTo(id(1)));
        f.peers.probeAnswered(id(1),session(1));
        f.peers.hint(id(1),session(1));assertEquals(2,f.sentTo(id(1)));
    }
    @Test void aProbeThatCouldNotBeSentIsNotCountedAndTheStateIsNo() {
        var f=new Fixture();f.accept=false;f.peers.sessionStarted(id(1),session(1));
        assertEquals(DhtPeers.State.NO,f.peers.state(id(1)));assertEquals(0,f.peers.probesSent());assertEquals(0,f.peers.budgetCount());
        f.accept=true;f.peers.sessionStarted(id(1),session(2));assertEquals(1,f.sentTo(id(1)));
    }
    @Test void forgetRemovesTheStateAndKeepsTheBudget() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));
        f.peers.forget(id(1));assertEquals(DhtPeers.State.UNKNOWN,f.peers.state(id(1)));assertNull(f.peers.sessionOf(id(1)));
        assertEquals(1,f.peers.budgetCount());
    }
    @Test void budgetEntriesDisappearTwentyFourHoursAfterTheLastProbe() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));f.peers.probeAnswered(id(1),session(1));
        f.advance(DAY-SECOND);assertEquals(1,f.peers.budgetCount());
        f.advance(2*SECOND);assertEquals(0,f.peers.budgetCount());
    }
    @Test void aStringFormNeverShowsTheIdentifiers() {
        var f=new Fixture();f.peers.sessionStarted(id(1),session(1));
        assertEquals("DHT peers",f.peers.toString());
    }
}
