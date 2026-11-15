// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 核 D（T1・T3・T5・T6・T7・T8b・T8c・T13）: 紹介されただけの相手（握手前）がいる網で、探索が近い相手に届くか。
 * 握手そのもの（UDP・Noise）は外側が駆動するので、試験の World が「握手を始めた相手へ、決めた秒数のあとに握手を通す」ことで真似る。
 * 上限を緩めずに、上限の中でどこまで届くかを数える。試験の失敗の文に番地・番号・鍵は出さない。
 */
class DhtColdLookupTest {
    /** a（探索する側）と、a の知らない相手 2..n。相手どうしは互いを知っていて、紹介できる。 */
    static final class World {
        final Net net=new Net();
        final Rig a;
        final List<Rig> peers=new ArrayList<>();
        /** 握手を始めてから通すまでの秒数。通さない相手（満杯の端末）は handshakeSkipped に入れる。 */
        long handshakeNanos=SECOND;
        final java.util.Set<DhtId> handshakeSkipped=new java.util.HashSet<>();
        private final Map<DhtId,Long> activeSince=new HashMap<>();
        int handshakes;
        final Map<DhtId,Integer> handshakesOf=new HashMap<>();

        World(int total,int yes) {
            a=net.rig(record(1,1,NOW).nodeId());a.network();a.usePrepare=true;
            for(int n=2;n<2+total;n++)peers.add(net.rig(DhtIdTest.id(n)));
            for(Rig r:peers) {
                for(Rig o:peers) {
                    if(o==r)continue;
                    r.node.observe(DhtResponderTest.peer(indexOf(o)));
                    r.directory.put(o.id,nodeContact(indexOf(o)));
                }
            }
            for(int i=0;i<yes;i++)connect(peers.get(i));
        }
        int indexOf(Rig r){return 2+peers.indexOf(r);}
        /** 最初から握手の済んだ相手にする。探りの上限に数えないよう、探りの答えまで流す。 */
        void connect(Rig r){net.connect(a,r);net.advance(11*SECOND);net.pump();}

        /** 1 歩（0.1 秒）。探索を進め、待ち行列を流し、握手を始めた相手へ握手を通し、時計を進める。 */
        void step(DhtNode<Integer>.Lookup... lookups) {
            a.node.poll();net.pump();
            for(Rig r:peers) {
                // 握手が済んだ相手（探りの返事待ちを含む）には、握手を通し直さない。
                if(a.dispatcher.peers().isYes(r.id)||a.dispatcher.peers().sessionOf(r.id)!=null)continue;
                if(a.node.candidates().isActive(r.id)) {
                    long since=activeSince.computeIfAbsent(r.id,k->net.nanos.get());
                    if(!handshakeSkipped.contains(r.id)&&net.nanos.get()-since>=handshakeNanos) {
                        a.dispatcher.sessionStarted(r.id.bytes(),SESSION);r.dispatcher.sessionStarted(a.id.bytes(),SESSION);
                        handshakes++;handshakesOf.merge(r.id,1,Integer::sum);net.pump();activeSince.remove(r.id);
                    }
                } else activeSince.remove(r.id);
            }
            net.advance(SECOND/10);
        }
        void run(long seconds,DhtNode<Integer>.Lookup... lookups) {
            long end=net.nanos.get()+seconds*SECOND;
            while(net.nanos.get()<end) {
                step();
                boolean allDone=lookups.length>0;
                for(var l:lookups)if(!l.done())allDone=false;
                if(allDone)return;
            }
        }
        int yesCount() {
            int n=0;
            for(Rig r:peers)if(a.dispatcher.peers().isYes(r.id))n++;
            return n;
        }
        int probesTo(Rig r){return net.count(a,r,DhtWire.Op.PING);}
        int totalProbes(){return (int)a.dispatcher.statistics().probesSent();}
        List<DhtId> nearest(DhtId key,int count) {
            List<DhtId> all=new ArrayList<>();
            for(Rig r:peers)all.add(r.id);
            all.sort((x,y)->key.compareDistance(x,y));
            return all.subList(0,Math.min(count,all.size()));
        }
    }

    static DhtId key(){return record(1,1,NOW).key();}

    // ---- T1 紹介された相手への照会で、近い相手に届く ----

    @Test void aLookupReachesAllNearPeersWhenThereAreEightPeersAndOnlyTwoStartConnected() {
        var w=new World(8,2);
        var lookup=w.a.node.findNode(key());
        w.run(120,lookup);
        assertTrue(lookup.done(),"The lookup must end within its 120 second deadline");
        var result=lookup.result();
        assertEquals(DhtNode.Stop.COMPLETE,result.stop());
        // 8 台しか居ないので、返事をくれた近い相手の一覧は 8 台全部になる。
        assertEquals(8,result.closest().size());
        assertTrue(w.handshakes>=6,"The six unconnected peers must have been handshaken, got "+w.handshakes);
    }
    @Test void anIntroducedPeerThatIsAskedGetsItsProbeBeforeTheRequestAndTheRequestIsSentOnlyAfterItIsYes() {
        var w=new World(4,1);
        var lookup=w.a.node.findNode(key());
        w.run(120,lookup);
        assertTrue(lookup.done());
        int asked=0;
        for(Rig r:w.peers) {
            int finds=w.net.count(w.a,r,DhtWire.Op.FIND_NODE);
            assertTrue(finds<=2,"At most one request and one retry per peer");
            if(finds==0)continue;
            asked++;
            // 送った順の記録: 照会より前に、その相手から探りの返事（PONG）が来ている。返事の前に要求は 0 通。
            int firstPong=-1,firstFind=-1;
            for(int i=0;i<w.net.sent.size();i++) {
                var p=w.net.sent.get(i);
                if(firstPong<0&&p.from()==r&&p.to()==w.a&&p.message().op()==DhtWire.Op.PONG)firstPong=i;
                if(firstFind<0&&p.from()==w.a&&p.to()==r&&p.message().op()==DhtWire.Op.FIND_NODE)firstFind=i;
            }
            assertTrue(firstPong>=0,"A peer is asked only after its probe was answered");
            assertTrue(firstPong<firstFind,"The request goes out only after the probe answer, not before");
            assertTrue(w.a.dispatcher.peers().isYes(r.id),"A peer that was asked is YES");
        }
        assertTrue(asked>=2,"More than the first peer was asked, got "+asked);
    }
    @Test void aSixteenPeerColdLookupStaysInsideTheProbeBudgetAndStillReachesTheNearestPeersByTheDeadline() {
        var w=new World(16,2);
        var lookup=w.a.node.findNode(key());
        w.run(130,lookup);
        assertTrue(lookup.done(),"The deadline is 120 seconds");
        // 探りは全体で毎分 30 通まで。16 台なら 1 分の枠に収まるので、探りの数は台数を超えない（各台に 1 通ずつ）。
        long probes=w.totalProbes();
        assertTrue(probes<=16+2,"Probes stay at about one per peer inside thirty per minute, got "+probes);
        assertTrue(w.yesCount()>=4,"The lookup must have reached more than the first peers, got "+w.yesCount());
        // 近い順に届いている: 返事をくれた近い相手は、鍵に近い順の先頭から欠けずに並ぶ。
        var closest=lookup.result().closest();
        assertFalse(closest.isEmpty());
        // 鍵に一番近い 3 台は、必ず返事をくれた近い相手の一覧に入る（名指しで確かめる）。
        java.util.Set<DhtId> answered=new java.util.HashSet<>();
        for(var c:closest)answered.add(c.id());
        for(DhtId near:w.nearest(key(),3))assertTrue(answered.contains(near),"One of the three nearest peers is missing from the answered peers");
    }

    // ---- T3 締切 ----

    @Test void aLookupStopsAtItsDeadlineWhenHandshakesAreSlowAndTheLatePeersStillBecomeOrdinaryVolatilePeersAfterwards() {
        var w=new World(8,1);
        w.handshakeNanos=80*SECOND;
        var lookup=w.a.node.findNode(key());
        w.run(125,lookup);
        assertTrue(lookup.done());
        assertEquals(DhtNode.Stop.DEADLINE,lookup.result().stop(),"Two rounds of 80 second handshakes cannot fit in 120 seconds");
        int before=w.yesCount();
        w.run(300);
        assertTrue(w.yesCount()>before,"Peers whose handshake finishes after the deadline still become ordinary peers, "+before+" -> "+w.yesCount());
    }

    // ---- T5 上限 ----

    @Test void fourLookupsThatWantTheSamePeersStartEachHandshakeOnceAndStayInsideTheQueryLimit() {
        var w=new World(8,2);
        List<DhtNode<Integer>.Lookup> lookups=new ArrayList<>();
        for(int i=0;i<DhtLimits.MAX_LOOKUPS;i++)lookups.add(w.a.node.findNode(key()));
        assertThrows(IllegalStateException.class,()->w.a.node.findNode(key()),"A fifth lookup is refused");
        w.run(125,lookups.toArray(new DhtNode.Lookup[0]));
        for(var l:lookups) {
            assertTrue(l.done());
            assertTrue(l.result().queried()<=DhtLimits.MAX_QUERIES);
            assertTrue(l.result().queried()>=2,"The lookup must actually have asked peers");
        }
        // 6 台は握手前。どの探索が何度欲しがっても、1 台につき握手はちょうど 1 回。
        assertEquals(6,w.handshakes,"One handshake per unconnected peer");
        for(int i=2;i<w.peers.size();i++)assertEquals(1,w.handshakesOf.getOrDefault(w.peers.get(i).id,0),"Exactly one handshake for peer "+i);
        for(var l:lookups)assertFalse(l.result().closest().isEmpty(),"Every lookup ended with a result");
        assertTrue(w.a.node.candidates().startsInWindow()<=6);
        assertTrue(w.a.node.candidates().startsInWindow()<=DhtCandidates.MAX_STARTS);
    }

    // ---- T6 4 探索が 3 台の枠を取り合う ----

    @Test void fourLookupsCompetingForThreeHandshakeSlotsAllEndBeforeTheirDeadline() {
        var w=new World(12,2);
        w.handshakeNanos=20*SECOND;
        List<DhtNode<Integer>.Lookup> lookups=new ArrayList<>();
        for(int i=0;i<DhtLimits.MAX_LOOKUPS;i++)lookups.add(w.a.node.findNode(key()));
        w.run(125,lookups.toArray(new DhtNode.Lookup[0]));
        for(var l:lookups) {
            assertTrue(l.done(),"Every lookup ends by its 120 second deadline");
            assertFalse(l.result().closest().isEmpty(),"Every lookup ends with a result, not empty-handed");
            assertTrue(l.result().responded()>=2,"Every lookup got answers from more than the first peers");
        }
        for(var e:w.handshakesOf.entrySet())assertEquals(1,e.getValue(),"One handshake per peer");
        assertTrue(w.a.node.candidates().active()<=DhtCandidates.MAX_ACTIVE);
    }

    // ---- T7 r19（DHT を話さない相手）に何度探索しても探りは上限の中 ----

    @Test void repeatedLookupsAmongPeersThatDoNotSpeakDhtStayInsideTheDailyAndPerMinuteProbeLimits() {
        var w=new World(6,1);
        for(int i=1;i<w.peers.size();i++)w.net.dropTo.add(w.peers.get(i).id);
        long start=w.net.nanos.get();
        for(int i=0;i<100;i++) {
            var lookup=w.a.node.findNode(key());
            w.run(130,lookup);
            assertTrue(lookup.done());
            w.run(480);
        }
        long minutes=(w.net.nanos.get()-start)/(60*SECOND)+1;
        long probes=w.totalProbes();
        assertTrue(probes<=DhtPeers.GLOBAL_PER_MINUTE*minutes,"At most thirty probes per minute, got "+probes+" in "+minutes+" minutes");
        assertTrue(probes<=5L*DhtPeers.PEER_PER_DAY+2*DhtPeers.EPISODE_PROBES,"At most twelve probes per peer per day, got "+probes);
        assertTrue(probes>=1,"Probes were sent at all");
        // 相手ごとの通数も 1 日 12 通の中（数だけを見る。番地・番号は出さない）。
        int maxPerPeer=0;
        for(Rig r:w.peers)maxPerPeer=Math.max(maxPerPeer,w.probesTo(r));
        assertTrue(maxPerPeer>=1,"Some peer was probed");
        assertTrue(maxPerPeer<=DhtPeers.PEER_PER_DAY,"At most twelve probes to one peer, got "+maxPerPeer);
        assertTrue(w.a.dispatcher.peers().noCount()>=1,"Peers that do not answer the probe become NO");
        assertTrue(w.a.dispatcher.peers().isYes(w.peers.get(0).id),"The connected peer stays YES");
    }

    // ---- T8 毎分 30 通の上限 ----

    @Test void whenTheProbeLimitHoldsBackPeersTheirAttemptWaitsForTheProbeAndAPeerNeverProbedFailsOnlyThatCandidate() {
        var w=new World(14,1);
        var lookup=w.a.node.findNode(key());
        // 毎分 30 通の枠は、14 台ほどでは自然に使い切れない。端末全体の枠を、始めと 61 秒後に別の相手の探りで使い切って、
        // この 120 秒の探索の間、世界の相手へは探りが出ない状態にする（探りが枠で止まった相手の扱いを見る試験）。
        int[] filler={0};
        exhaustProbeBudget(w,filler);
        w.run(61,lookup);
        exhaustProbeBudget(w,filler);
        w.run(64,lookup);
        assertTrue(lookup.done(),"The lookup still ends by the deadline");
        // 上の式は 3 回分と緩い（探索の間に枠を 2 回使い切らせるので、ここでは 60 通＋世界の数通）。ぴったりの上限は DhtPeersTest（毎分 30 通）と上の 210 行目の試験が見る。
        assertTrue(w.totalProbes()<=1+DhtPeers.GLOBAL_PER_MINUTE*3,"Probes stay inside thirty per minute, got "+w.totalProbes());
        // 締切の時点で、探りが 0 通の相手（枠で止まった）だけが失敗し、探りを送った相手は照会に答えている。
        java.util.Set<DhtId> answered=new java.util.HashSet<>();
        for(var c:lookup.result().closest())answered.add(c.id());
        int held=0;
        for(Rig r:w.peers) {
            boolean probed=w.probesTo(r)>=1;
            if(!probed){held++;assertFalse(answered.contains(r.id),"A peer that never got a probe is not among the answered peers");}
            else assertTrue(answered.contains(r.id)||w.net.count(w.a,r,DhtWire.Op.FIND_NODE)==0,"A probed and asked peer answered");
        }
        assertTrue(held>=1,"The probe limit held some peers back");
        assertEquals(answered.size(),lookup.result().responded(),"Every answered peer is counted once");
        assertTrue(lookup.result().queried()>lookup.result().responded(),"The held back peers are the failed ones");
        w.run(300);
        // 全員が探りに答える網なので、探りを送った相手は失敗の待ちに入らない。
        assertEquals(0,w.a.node.candidates().failures(),"Only candidates that never got a probe fail, and they are not put in the backoff");
        assertTrue(w.yesCount()>=2);
    }

    /** 端末全体の探りの枠（毎分 GLOBAL_PER_MINUTE 通）を、世界の外の相手の探りで使い切る。 */
    private static void exhaustProbeBudget(World w,int[] filler) {
        var peers=w.a.dispatcher.peers();
        for(int i=0;i<DhtPeers.GLOBAL_PER_MINUTE;i++) {
            DhtId f=DhtIdTest.id(7000+filler[0]++);
            peers.sessionStarted(f,SESSION);peers.probeAnswered(f,SESSION);
        }
    }

    // ---- T8b 候補の表が満杯でも近い相手に届く ----

    @Test void aLookupStillReachesTheNearestPeersWhenTheCandidateTableIsAlmostFull() {
        var w=new World(30,2);
        // 紹介元ごと 8・全体 128 のうち 112 を、遠い見知らぬ相手で先に埋める。
        for(int s=0;s<14;s++)for(int k=0;k<8;k++) {
            int n=100+s*8+k;
            w.a.node.candidates().offer(DhtIdTest.id(400+s),new DhtCandidates.Candidate(DhtIdTest.id(n),
                    new byte[]{(byte)192,(byte)168,1,(byte)(10+n)},50000,new byte[32]));
        }
        assertEquals(112,w.a.node.candidates().size());
        var lookup=w.a.node.findNode(key());
        w.run(125,lookup);
        assertTrue(lookup.done());
        assertTrue(w.a.node.candidates().size()<=DhtCandidates.MAX_CANDIDATES);
        var closest=lookup.result().closest();
        assertTrue(closest.size()>=4,"More than the first peers answered, got "+closest.size());
        var want=w.nearest(key(),30);
        for(int i=0;i<3;i++)assertTrue(want.subList(0,10).contains(closest.get(i).id()),"The nearest answered peers are among the nearest ten");
    }

    // ---- T8c 通数の表が満杯 ----

    @Test void whenTheProbeBudgetTableIsFullANewPeerIsNotProbedAndTheLookupStillEnds() {
        var w=new World(6,1);
        var peers=w.a.dispatcher.peers();
        for(int n=0;peers.budgetCount()<DhtPeers.MAX_BUDGETS;n++) {
            DhtId filler=DhtIdTest.id(5000+n);
            peers.sessionStarted(filler,SESSION);peers.probeAnswered(filler,SESSION);
            if(n%DhtPeers.GLOBAL_PER_MINUTE==DhtPeers.GLOBAL_PER_MINUTE-1)w.net.advance(60*SECOND);
        }
        assertEquals(DhtPeers.MAX_BUDGETS,peers.budgetCount());
        long before=w.totalProbes();
        var lookup=w.a.node.findNode(key());
        w.run(125,lookup);
        assertTrue(lookup.done());
        assertEquals(before,w.totalProbes(),"No probe goes to a new peer while the budget table is full");
        assertTrue(peers.budgetBlocked()>=1);
        assertTrue(peers.noCount()>=1,"The new peers are treated as NO");
        assertTrue(lookup.result().closest().size()<=2,"Only the already connected peer answers");
    }

    // ---- T13 満杯の端末への握手 ----

    @Test void aPeerThatNeverCompletesTheHandshakeFailsAfterNinetySecondsAndIsNotStartedAgainDuringTheBackoff() {
        var w=new World(4,1);
        for(int i=1;i<w.peers.size();i++)w.handshakeSkipped.add(w.peers.get(i).id);
        var lookup=w.a.node.findNode(key());
        w.run(125,lookup);
        assertTrue(lookup.done());
        w.run(100);
        assertEquals(0,w.handshakes,"The skipped peers never complete");
        assertEquals(3,w.a.node.candidates().failures(),"Each of the three peers is in its first backoff");
        // 失敗の待ちの 2 分の間は、同じ番地へ握手を始め直さない。
        assertEquals(3,w.a.node.candidates().startsInWindow(),"No second start during the backoff");
    }

    // ---- 推-1（答え 195）: 値の印で手放したつなぎ中の数が、公開の統計に出る。配送の手放しの数とは混ぜない ----

    @Test void theValueMarkReleaseOfConnectingPeersShowsInTheDispatcherStatisticsAndNotInTheDeliveryReleaseCounts() {
        var w=new World(4,0);w.handshakeNanos=30*SECOND;
        var r=record(1,1,NOW);
        // 値を持つ相手は、鍵にいちばん近い 1 台。これだけ握手を済ませ、近い 3 台のうち残る 2 台はつなぎ中のままにする。
        Rig holder=w.peers.stream().filter(x->x.id.equals(w.nearest(r.key(),1).get(0))).findFirst().orElseThrow();
        w.connect(holder);
        // a の経路表に、握手のまだ済まない相手も入れる（候補にして、探索が prepare でつなぎ中にする）。
        for(Rig o:w.peers) {
            if(o==holder)continue;
            int n=w.indexOf(o);
            w.a.node.observe(DhtResponderTest.peer(n));w.a.directory.put(o.id,nodeContact(n));
            DhtDispatcherPrepareTest.offer(w.a,n);
        }
        assertEquals(DiscoveryStatus.ACCEPTED,holder.store.put(DiscoveryStoreTest.publisher(r),r.encode()));
        var lookup=w.a.node.findValue(r.key());
        w.run(120,lookup);
        assertTrue(lookup.done());assertTrue(lookup.result().value().isPresent());
        var s=w.a.dispatcher.statistics();
        assertTrue(w.a.node.connectingReleased()>0,"値の印のとき、つなぎ中の相手が手放される");
        assertEquals(w.a.node.connectingReleased(),s.connectingReleased(),"公開の統計は核の数をそのまま出す");
        assertEquals(0,s.releasedNotYes());assertEquals(0,s.releasedOutsideTable());assertEquals(0,s.releasedCrowdedBucket());assertEquals(0,s.releasedNo());
        assertEquals(0,s.connectingTimedOut(),"手放しは時間切れに入れない");
    }
}
