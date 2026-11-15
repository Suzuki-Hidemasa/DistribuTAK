// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.LocalNetworkTest.ip;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C1: 確かめていない候補の上限（答え 181 の 3・(e)）。 */
class DhtCandidatesTest {
    static final long SECOND=1_000_000_000L,MINUTE=60*SECOND;
    final AtomicLong nanos=new AtomicLong(1_000);
    final DhtCandidates table=new DhtCandidates(DhtIdTest.id(0),nanos::get);
    DhtCandidatesTest(){table.setNetwork(new LocalNetwork(ip(192,168,10,5),24));}
    static DhtCandidates.Candidate candidate(int node,int host,int port) {
        return new DhtCandidates.Candidate(DhtIdTest.id(node),ip(192,168,10,host),port,new byte[32]);
    }
    /** 入れた順に番号を覚える。指名の形（startFor）になったあとも、古い順に 1 台ずつ始める既存の試験の書き方を保つための補助。 */
    final Deque<DhtId> offered=new ArrayDeque<>();
    boolean offer(int source,int node,int host,int port){return track(DhtIdTest.id(source),candidate(node,host,port));}
    boolean track(DhtId source,DhtCandidates.Candidate candidate) {
        boolean accepted=table.offer(source,candidate);if(accepted)offered.addLast(candidate.node());return accepted;
    }
    /** 旧 start() と同じ約束: 古い候補から 1 台。上限で止まるときは空（候補は残す）。 */
    Optional<DhtCandidates.Attempt> start() {
        while(!offered.isEmpty()) {
            DhtId node=offered.peekFirst();
            switch(table.startFor(node)) {
                case STARTED->{offered.removeFirst();return table.attemptFor(node);}
                case BUSY->{return Optional.empty();}
                default->offered.removeFirst();
            }
        }
        return Optional.empty();
    }
    void advance(long amount){nanos.addAndGet(amount);}
    /** 第12段: 候補の上限を 64 から 128 に上げた（答え 192 (3)・193 の限度の表）。紹介元ごとの 8 は変えない。 */
    @Test void theTableKeepsAtMost128CandidatesAndEightPerIntroducer() {
        for(int i=0;i<8;i++)assertTrue(offer(1,100+i,10+i,4000));
        assertFalse(offer(1,108,18,4000));assertEquals(8,table.size());
        int next=20;for(int source=2;source<=16;source++)for(int i=0;i<8;i++)assertTrue(offer(source,200+next,next++,4000));
        assertEquals(128,table.size());assertFalse(offer(17,400,200,4000));assertEquals(128,table.size());
    }
    @Test void aCandidateExpiresAfterThreeMinutesAndFreesItsSlot() {
        assertTrue(offer(1,100,10,4000));advance(3*MINUTE-1);assertEquals(1,table.size());
        advance(1);assertEquals(0,table.size());assertTrue(start().isEmpty());
        for(int i=0;i<8;i++)assertTrue(offer(1,100+i,10+i,4000));
    }
    @Test void aSameAddressAndPortOrNodeEntersOnlyOnce() {
        assertTrue(offer(1,100,10,4000));assertFalse(offer(2,101,10,4000));assertFalse(offer(2,100,11,4000));
        assertTrue(offer(2,101,10,4001));assertEquals(2,table.size());
    }
    @Test void addressesOutsideTheLocalNetworkAndTheNodeItselfAreNotKept() {
        assertFalse(table.offer(DhtIdTest.id(1),new DhtCandidates.Candidate(DhtIdTest.id(100),ip(10,0,0,6),4000,new byte[32])));
        assertFalse(table.offer(DhtIdTest.id(1),new DhtCandidates.Candidate(DhtIdTest.id(100),ip(192,168,10,5),4000,new byte[32])));
        assertFalse(table.offer(DhtIdTest.id(1),new DhtCandidates.Candidate(DhtIdTest.id(0),ip(192,168,10,9),4000,new byte[32])));
        assertFalse(offer(1,100,10,0));assertEquals(0,table.size());
    }
    @Test void aCandidateThatStartsLeavesTheTableAndTheSameAddressCannotRunTwice() {
        assertTrue(offer(1,100,10,4000));var attempt=start().orElseThrow();assertEquals(0,table.size());
        assertEquals(1,table.active());assertFalse(offer(2,101,10,4000));assertFalse(offer(2,100,11,4000));
        table.finish(attempt,true);assertEquals(0,table.active());assertTrue(offer(2,101,10,4000));
    }
    @Test void atMostEightAttemptsRunAtTheSameTimeAndEachIsDroppedAfter90Seconds() {
        for(int i=0;i<10;i++)assertTrue(offer(1+i/8,100+i,10+i,4000));
        List<DhtCandidates.Attempt> running=new ArrayList<>();
        for(int i=0;i<8;i++)running.add(start().orElseThrow());
        assertTrue(start().isEmpty());assertEquals(8,table.active());
        advance(90*SECOND-1);table.poll();assertEquals(8,table.active());
        advance(1);table.poll();assertEquals(0,table.active());
        assertTrue(start().isPresent());
    }
    @Test void aNewStartIsRefusedWhenSixtyFourStartedInTheLastFiveMinutesAndComesBackWithTime() {
        for(int i=0;i<64;i++) {
            assertTrue(offer(1+i/8,100+i,10+i,4000));var attempt=start().orElseThrow();table.finish(attempt,true);advance(SECOND);
        }
        assertEquals(64,table.startsInWindow());assertTrue(offer(9,200,100,4000));assertTrue(start().isEmpty());
        // 候補の寿命（3 分）とは別に、窓だけで止まることを確かめるため、最後の瞬間に新しい候補を入れる。
        advance(5*MINUTE-64*SECOND-1);assertTrue(offer(9,201,101,4000));assertTrue(start().isEmpty());
        advance(1);assertTrue(start().isPresent());assertEquals(64,table.startsInWindow());
    }
    @Test void theStartLimitIsCountedAcrossLookupsNotPerSource() {
        // 紹介元が別でも、端末全体で 64 件。
        for(int i=0;i<64;i++){assertTrue(offer(1+i,100+i,10+i%200,4000+i));table.finish(start().orElseThrow(),true);}
        assertTrue(offer(77,300,150,5000));assertTrue(start().isEmpty());
    }
    @Test void theFirstPacketGoesEveryTenSecondsUpToThreeTimesAndGivesUpAt30Seconds() {
        assertTrue(offer(1,100,10,4000));var attempt=start().orElseThrow();
        assertTrue(table.firstDue(attempt));table.firstSent(attempt);assertFalse(table.firstDue(attempt));
        advance(10*SECOND-1);assertFalse(table.firstDue(attempt));advance(1);assertTrue(table.firstDue(attempt));table.firstSent(attempt);
        advance(10*SECOND);assertTrue(table.firstDue(attempt));table.firstSent(attempt);
        advance(10*SECOND);assertFalse(table.firstDue(attempt));assertEquals(3,attempt.firstsSent());
        advance(SECOND);table.poll();assertEquals(0,table.active());
    }
    @Test void anAnsweredAttemptStopsSendingButKeepsItsSlotUntilFinishedOr90Seconds() {
        assertTrue(offer(1,100,10,4000));var attempt=start().orElseThrow();table.firstSent(attempt);
        table.answered(attempt);advance(15*SECOND);assertFalse(table.firstDue(attempt));table.poll();assertEquals(1,table.active());
        advance(75*SECOND);table.poll();assertEquals(0,table.active());
    }
    @Test void aFailedAddressWaitsTwoMinutesThenDoublesUpToThirtyMinutes() {
        assertTrue(offer(1,100,10,4000));table.finish(start().orElseThrow(),false);
        for(long minutes:new long[]{2,4,8,16,30,30}) {
            assertFalse(offer(1,100,10,4000));advance(minutes*MINUTE-1);assertFalse(offer(1,100,10,4000));
            advance(1);assertTrue(offer(1,100,10,4000));table.finish(start().orElseThrow(),false);
        }
    }
    @Test void aSuccessClearsTheFailureOfThatAddress() {
        assertTrue(offer(1,100,10,4000));table.finish(start().orElseThrow(),false);advance(2*MINUTE);
        assertTrue(offer(1,100,10,4000));table.finish(start().orElseThrow(),true);
        assertEquals(0,table.failures());assertTrue(offer(1,100,10,4000));
    }
    @Test void theFailureRecordKeeps128AddressesAndDropsTheOldestFirst() {
        for(int i=0;i<130;i++) {
            int host=10+i%200;
            assertTrue(track(DhtIdTest.id(1+i%8),new DhtCandidates.Candidate(DhtIdTest.id(100+i),ip(192,168,10,host),5000+i,new byte[32])));
            table.finish(start().orElseThrow(),false);advance(10*SECOND);
        }
        assertEquals(128,table.failures());
    }
    @Test void aNetworkChangeDropsCandidatesAttemptsAndFailuresButNotTheStartWindow() {
        assertTrue(offer(1,100,10,4000));table.finish(start().orElseThrow(),false);
        assertTrue(offer(1,101,11,4000));start();assertTrue(offer(1,102,12,4000));
        table.setNetwork(new LocalNetwork(ip(192,168,10,5),24));assertEquals(1,table.size());
        table.setNetwork(new LocalNetwork(ip(172,16,0,9),16));
        assertEquals(0,table.size());assertEquals(0,table.active());assertEquals(0,table.failures());
        assertTrue(table.offer(DhtIdTest.id(1),new DhtCandidates.Candidate(DhtIdTest.id(100),ip(172,16,0,10),4000,new byte[32])));
        assertEquals(2,table.startsInWindow());
    }
    @Test void aBackwardClockClearsEverythingToStayOnTheSafeSide() {
        assertTrue(offer(1,100,10,4000));start();assertTrue(offer(1,101,11,4000));
        nanos.set(1);table.poll();assertEquals(0,table.size());assertEquals(0,table.active());
    }
    @Test void noNetworkMeansNoCandidatesAndTextNeverShowsAddressesOrIds() {
        var closed=new DhtCandidates(DhtIdTest.id(0),nanos::get);
        assertFalse(closed.offer(DhtIdTest.id(1),candidate(100,10,4000)));assertEquals(0,closed.size());
        var c=candidate(100,10,4000);assertEquals("DHT candidate",c.toString());assertEquals("DHT candidates",table.toString());
        assertTrue(offer(1,100,10,4000));assertEquals("DHT candidate attempt",start().orElseThrow().toString());
    }
    /** 番地の型は固定の文だけを出す（番地・ポートをログや例外に出さない。答え 166 (5)）。 */
    @Test void theAddressKeyNeverPrintsTheAddressOrThePort() throws Exception {
        Class<?> address=null;for(var type:DhtCandidates.class.getDeclaredClasses())if(type.getSimpleName().equals("Address"))address=type;
        assertNotNull(address);var constructor=address.getDeclaredConstructors()[0];constructor.setAccessible(true);
        Object value=constructor.newInstance(0xC0A80102,40123);
        assertEquals("DHT candidate address",value.toString());
        assertFalse(value.toString().contains("40123"));assertFalse(value.toString().contains("192"));
    }

    // ---- 核 D: 指名（startFor）・isActive・失敗の待ちに入れない閉じ方 ----
    @Test void startForStartsTheNamedCandidateAndNotTheOldest() {
        assertTrue(offer(1,100,10,4000));assertTrue(offer(1,101,11,4000));assertTrue(offer(1,102,12,4000));
        assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(101)));
        assertEquals(2,table.size());assertTrue(table.isActive(DhtIdTest.id(101)));
        assertFalse(table.isActive(DhtIdTest.id(100)));assertEquals(1,table.active());
        assertEquals(DhtIdTest.id(101),table.attemptFor(DhtIdTest.id(101)).orElseThrow().candidate().node());
        assertTrue(table.attemptFor(DhtIdTest.id(100)).isEmpty());
    }
    @Test void startForRefusesANodeThatIsNotInTheTableOrWasExpired() {
        assertEquals(DhtCandidates.Start.REFUSED,table.startFor(DhtIdTest.id(100)));
        assertTrue(offer(1,100,10,4000));advance(3*MINUTE-1);
        assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        table.finish(table.attemptFor(DhtIdTest.id(100)).orElseThrow(),true);
        assertTrue(offer(1,101,11,4000));advance(3*MINUTE);
        assertEquals(DhtCandidates.Start.REFUSED,table.startFor(DhtIdTest.id(101)));
        assertEquals(1,table.startsInWindow());
    }
    @Test void startForOnARunningNodeDoesNothingNewAndCountsOneStartOnly() {
        assertTrue(offer(1,100,10,4000));
        assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        for(int i=0;i<5;i++)assertEquals(DhtCandidates.Start.ACTIVE,table.startFor(DhtIdTest.id(100)));
        assertEquals(1,table.active());assertEquals(1,table.startsInWindow());
    }
    @Test void startForIsBusyAtEightAttemptsAndKeepsTheCandidateForLater() {
        for(int i=0;i<9;i++)assertTrue(offer(1+i/8,100+i,10+i,4000));
        for(int i=0;i<8;i++)assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100+i)));
        for(int i=0;i<3;i++)assertEquals(DhtCandidates.Start.BUSY,table.startFor(DhtIdTest.id(108)));
        assertEquals(1,table.size());assertEquals(8,table.startsInWindow());
        advance(90*SECOND);
        assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(108)));
        assertEquals(9,table.startsInWindow());
    }
    @Test void startForIsBusyAtSixtyFourStartsInFiveMinutesAndStartsAgainAfterTheWindow() {
        for(int i=0;i<64;i++) {
            assertTrue(offer(1+i/8,100+i,10+i,4000));
            assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100+i)));
            table.finish(table.attemptFor(DhtIdTest.id(100+i)).orElseThrow(),true);advance(SECOND);
        }
        assertTrue(offer(9,200,100,4000));
        for(int i=0;i<4;i++)assertEquals(DhtCandidates.Start.BUSY,table.startFor(DhtIdTest.id(200)));
        assertEquals(64,table.startsInWindow());assertEquals(1,table.size());
        advance(5*MINUTE-64*SECOND-1);assertTrue(offer(9,201,101,4000));
        assertEquals(DhtCandidates.Start.BUSY,table.startFor(DhtIdTest.id(201)));
        advance(1);assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(201)));
    }
    /** 失敗の待ちの中の番地は、指名でも始まらず、候補にも入らない。 */
    @Test void anAddressInItsFailureWaitIsNotStartedByNameEither() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        table.finish(table.attemptFor(DhtIdTest.id(100)).orElseThrow(),false);
        assertFalse(offer(2,100,10,4000));assertFalse(offer(2,101,10,4000));
        assertEquals(DhtCandidates.Start.REFUSED,table.startFor(DhtIdTest.id(100)));
        assertEquals(DhtCandidates.Start.REFUSED,table.startFor(DhtIdTest.id(101)));
        assertEquals(0,table.active());assertEquals(1,table.startsInWindow());
        advance(2*MINUTE);assertTrue(offer(2,101,10,4000));
        assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(101)));
    }
    @Test void aNetworkChangeOrAClearMakesStartForRefuseEverything() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        assertTrue(offer(1,101,11,4000));
        table.setNetwork(new LocalNetwork(ip(172,16,0,9),16));
        assertFalse(table.isActive(DhtIdTest.id(100)));
        assertEquals(DhtCandidates.Start.REFUSED,table.startFor(DhtIdTest.id(101)));
        assertTrue(table.offer(DhtIdTest.id(1),new DhtCandidates.Candidate(DhtIdTest.id(102),ip(172,16,0,10),4000,new byte[32])));
        table.clear();assertEquals(DhtCandidates.Start.REFUSED,table.startFor(DhtIdTest.id(102)));
    }
    @Test void releasingAnAttemptDoesNotEnterTheFailureWaitAndKeepsTheStartCount() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        var attempt=table.attemptFor(DhtIdTest.id(100)).orElseThrow();
        advance(20*SECOND);table.release(attempt);
        assertEquals(0,table.active());assertEquals(0,table.failures());assertEquals(1,table.startsInWindow());
        assertFalse(table.isActive(DhtIdTest.id(100)));
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        assertEquals(2,table.startsInWindow());
    }
    /** ちょうど 90 秒でも、purge が先に失敗の待ちへ入れてしまわない（release は purge より先に試みを外す）。 */
    @Test void releaseAtExactly90SecondsIsNotTurnedIntoAFailureByPurge() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        var attempt=table.attemptFor(DhtIdTest.id(100)).orElseThrow();
        advance(90*SECOND);table.release(attempt);
        assertEquals(0,table.failures());assertEquals(0,table.active());
        assertTrue(offer(1,100,10,4000));
    }
    @Test void releasingAnAttemptThatIsAlreadyGoneDoesNothing() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        var attempt=table.attemptFor(DhtIdTest.id(100)).orElseThrow();
        table.finish(attempt,false);table.release(attempt);
        assertEquals(1,table.failures());assertEquals(1,table.startsInWindow());
    }
    /** 握手が済んで、探りを 1 通も送れないまま 90 秒になったら、自分の枠の都合なので失敗の待ちに入れない。 */
    @Test void anAnsweredAttemptThatNeverSentAProbeIsDroppedAt90SecondsWithoutAFailure() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        var attempt=table.attemptFor(DhtIdTest.id(100)).orElseThrow();table.firstSent(attempt);table.answered(attempt);
        advance(90*SECOND-1);assertEquals(1,table.active());
        advance(1);assertEquals(0,table.active());assertEquals(0,table.failures());assertEquals(1,table.startsInWindow());
    }
    @Test void anAnsweredAttemptThatSentAProbeStillFailsAt90SecondsAndWaits() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        var attempt=table.attemptFor(DhtIdTest.id(100)).orElseThrow();table.firstSent(attempt);table.answered(attempt);table.probeSent(attempt);
        advance(90*SECOND);assertEquals(0,table.active());assertEquals(1,table.failures());
        assertFalse(offer(1,100,10,4000));
    }
    @Test void anUnansweredAttemptStillFailsAt90SecondsAndWaits() {
        assertTrue(offer(1,100,10,4000));assertEquals(DhtCandidates.Start.STARTED,table.startFor(DhtIdTest.id(100)));
        advance(90*SECOND);assertEquals(0,table.active());assertEquals(1,table.failures());
    }
    @Test void startForNeverPrintsAddressesOrIds() {
        assertEquals("STARTED",DhtCandidates.Start.STARTED.toString());
        assertTrue(offer(1,100,10,4000));table.startFor(DhtIdTest.id(100));
        assertEquals("DHT candidate attempt",table.attemptFor(DhtIdTest.id(100)).orElseThrow().toString());
    }
}
