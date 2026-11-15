// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * 認証済みの相手がDHTを話せるかの探り（核C2）。DHTを知らない旧版（r19）の相手へ送り続けると、相手の
 * 「拒否」の数が増え続けるので、通数を二重に絞る。1相手24時間で12通、端末全体で毎分6通。
 * 通数の記録は状態の覚えとは別の表に持ち、状態を消しても、ネットワークが変わっても、追い出されても消さない。
 * 状態は同じスレッドから呼ぶ（DhtNodeと同じ1本。別スレッドからは待ち行列を通す）。
 * 相手の番号・セッションの番号はログにも文字列にも出さない。
 */
public final class DhtPeers {
    public enum State { UNKNOWN,PROBING,YES,NO }
    /** 探りのPINGを送る口。送り始められたときだけtrue。 */
    @FunctionalInterface public interface Prober { boolean send(DhtId peer,byte[] sessionId); }

    public static final int MAX_STATES=256;
    public static final int MAX_BUDGETS=1024;
    public static final int PEER_PER_DAY=12;
    public static final int GLOBAL_PER_MINUTE=30;
    public static final int EPISODE_PROBES=6;
    /** YES の相手への要求が続けてこの回数だけ期限切れになったら、未確認に戻して探り直す。 */
    public static final int YES_EXPIRIES=3;
    private static final long SECOND=1_000_000_000L;
    private static final long PROBE_NANOS=3*SECOND;
    private static final long MINUTE_NANOS=60*SECOND;
    private static final long DAY_NANOS=24L*60*MINUTE_NANOS;
    /** 一巡の中で、1通目からの積み上げ時刻（秒）。0・60・180・420・900・1860。 */
    private static final long[] OFFSETS={0,60*SECOND,180*SECOND,420*SECOND,900*SECOND,1860*SECOND};
    private static final long NEVER=Long.MAX_VALUE;

    private static final class Entry {
        State state=State.UNKNOWN;
        byte[] session;
        long episodeStart;
        int probes;
        /** 次に送る時刻。NEVERなら一巡は終わり（きっかけ待ち）。 */
        long nextDue=NEVER;
        long probingSince;
        /** YES の間、要求が続けて期限切れになった回数。返事が届いたら 0 に戻す。 */
        int expiredRun;
    }
    private static final class Budget {
        final ArrayDeque<Long> times=new ArrayDeque<>();
    }

    private final LongSupplier ticker;
    private final Prober prober;
    private final LinkedHashMap<DhtId,Entry> states=new LinkedHashMap<>();
    private final LinkedHashMap<DhtId,Budget> budgets=new LinkedHashMap<>();
    private final ArrayDeque<Long> globalTimes=new ArrayDeque<>();
    private long probesSent;
    private long budgetBlocked;

    public DhtPeers(LongSupplier ticker,Prober prober) {
        this.ticker=Objects.requireNonNull(ticker);this.prober=Objects.requireNonNull(prober);
    }

    /** 認証済みのセッションができた。同じセッションなら何もしない。YESの相手は番号を直すだけ。 */
    public void sessionStarted(DhtId peer,byte[] sessionId) {
        Objects.requireNonNull(peer);Objects.requireNonNull(sessionId);
        Entry e=states.get(peer);
        if(e!=null&&e.session!=null&&Arrays.equals(e.session,sessionId)) {
            return;
        }
        if(e!=null&&e.state==State.YES) {
            e.session=sessionId.clone();e.expiredRun=0;touch(peer,e);return;
        }
        e=entryFor(peer);e.session=sessionId.clone();
        startEpisode(peer,e);
    }

    /** ネットワークが変わった。覚えを未確認に戻し、セッションも忘れる。通数の記録は残す。 */
    public void networkChanged() {
        for(Entry e:states.values()) {
            e.state=State.UNKNOWN;e.session=null;e.probes=0;e.nextDue=NEVER;
        }
    }

    /** 揮発の相手を消した。状態だけ消す。通数の記録は残す。 */
    public void forget(DhtId peer) {
        states.remove(Objects.requireNonNull(peer));
    }

    /** 探りへの正しいPONGが届いた。その探りが今のセッション宛てで、まだ待っているときだけtrue。 */
    public boolean probeAnswered(DhtId peer,byte[] sessionId) {
        Entry e=states.get(Objects.requireNonNull(peer));
        if(e==null||e.state!=State.PROBING||e.session==null||!Arrays.equals(e.session,Objects.requireNonNull(sessionId))) {
            return false;
        }
        e.state=State.YES;e.nextDue=NEVER;e.expiredRun=0;
        touch(peer,e);
        return true;
    }

    /** YES の相手の今のセッション宛ての要求に、正しい返事が届いた。続けて期限切れになった数を数え直す。 */
    public void requestAnswered(DhtId peer,byte[] sessionId) {
        Entry e=states.get(Objects.requireNonNull(peer));
        if(e!=null&&e.state==State.YES&&e.session!=null&&Arrays.equals(e.session,Objects.requireNonNull(sessionId))) {
            e.expiredRun=0;
        }
    }

    /**
     * YES の相手の今のセッション宛ての要求が期限切れになった。続けて YES_EXPIRIES 回になったら未確認に戻し、
     * 新しい一巡を始める。探りは通数の上限（相手ごと・全体）の中でだけ送る。
     */
    public void requestExpired(DhtId peer,byte[] sessionId) {
        Entry e=states.get(Objects.requireNonNull(peer));
        if(e==null||e.state!=State.YES||e.session==null||!Arrays.equals(e.session,Objects.requireNonNull(sessionId))) {
            return;
        }
        e.expiredRun++;
        if(e.expiredRun>=YES_EXPIRIES) {
            e.expiredRun=0;
            startEpisode(peer,e);
        }
    }

    /** 相手から正しいDHT要求が届いた。経路表には入れない。YESでなく待ってもいなければ、新しい一巡を始める。 */
    public void hint(DhtId peer,byte[] sessionId) {
        Objects.requireNonNull(peer);Objects.requireNonNull(sessionId);
        Entry e=states.get(peer);
        if(e!=null&&e.state==State.YES) {
            if(e.session==null||!Arrays.equals(e.session,sessionId)) {
                e.session=sessionId.clone();e.expiredRun=0;
            }
            return;
        }
        if(e!=null&&(e.state==State.PROBING||e.state==State.UNKNOWN&&e.nextDue!=NEVER)) {
            return;
        }
        e=entryFor(peer);e.session=sessionId.clone();
        startEpisode(peer,e);
    }

    /** 手動の再試行。一巡が終わっていてセッションのある相手に新しい一巡を始める。 */
    public void retryAll() {
        for(Map.Entry<DhtId,Entry> m:new ArrayDeque<>(states.entrySet())) {
            Entry e=m.getValue();
            if(e.state!=State.YES&&e.state!=State.PROBING&&e.session!=null&&e.nextDue==NEVER) {
                startEpisode(m.getKey(),e);
            }
        }
    }

    /** 周期の処理。通数の記録の期限切れ・3秒の無応答・予定時刻の探り。 */
    public void tick() {
        long now=ticker.getAsLong();
        purgeBudgets(now);
        for(Entry e:states.values()) {
            if(e.state==State.PROBING&&now-e.probingSince>=PROBE_NANOS) {
                e.state=State.NO;
            }
        }
        // 1通目をまだ送れていない相手を先に、予定の再送はあと。
        for(int pass=0;pass<2;pass++) {
            for(Map.Entry<DhtId,Entry> m:new ArrayDeque<>(states.entrySet())) {
                Entry e=m.getValue();
                if(e.state==State.YES||e.state==State.PROBING||e.session==null||e.nextDue==NEVER||now-e.nextDue<0) {
                    continue;
                }
                if((pass==0)==(e.probes==0)) {
                    tryProbe(m.getKey(),e,now);
                }
            }
        }
    }

    public boolean isYes(DhtId peer){Entry e=states.get(peer);return e!=null&&e.state==State.YES;}
    public State state(DhtId peer){Entry e=states.get(peer);return e==null?State.UNKNOWN:e.state;}
    public byte[] sessionOf(DhtId peer){Entry e=states.get(peer);return e==null||e.session==null?null:e.session.clone();}
    public int stateCount(){return states.size();}
    public int yesCount(){return count(State.YES);}
    public int noCount(){return count(State.NO);}
    public int budgetCount(){return budgets.size();}
    public long probesSent(){return probesSent;}
    public long budgetBlocked(){return budgetBlocked;}

    private int count(State s) {
        int n=0;
        for(Entry e:states.values()) {
            if(e.state==s) {
                n++;
            }
        }
        return n;
    }

    private static long inc(long value){return value==Long.MAX_VALUE?value:value+1;}

    private void touch(DhtId peer,Entry e) {
        states.remove(peer);states.put(peer,e);
    }

    private Entry entryFor(DhtId peer) {
        Entry e=states.remove(peer);
        if(e==null) {
            while(states.size()>=MAX_STATES) {
                Iterator<DhtId> it=states.keySet().iterator();it.next();it.remove();
            }
            e=new Entry();
        }
        states.put(peer,e);
        return e;
    }

    private void startEpisode(DhtId peer,Entry e) {
        long now=ticker.getAsLong();
        e.state=State.UNKNOWN;e.probes=0;e.episodeStart=now;e.nextDue=now;
        tryProbe(peer,e,now);
    }

    private void endEpisode(Entry e,State state) {
        e.state=state;e.nextDue=NEVER;
    }

    private void tryProbe(DhtId peer,Entry e,long now) {
        purgeBudgets(now);
        Budget b=budgets.get(peer);
        if(b==null?budgets.size()>=MAX_BUDGETS:b.times.size()>=PEER_PER_DAY) {
            budgetBlocked=inc(budgetBlocked);endEpisode(e,State.NO);return;
        }
        while(!globalTimes.isEmpty()&&now-globalTimes.peekFirst()>=MINUTE_NANOS) {
            globalTimes.pollFirst();
        }
        if(globalTimes.size()>=GLOBAL_PER_MINUTE) {
            return; // 次のtickに延ばす。状態はそのまま。
        }
        boolean sent;
        try {
            sent=prober.send(peer,e.session.clone());
        } catch(RuntimeException ex) {
            sent=false;
        }
        if(!sent) {
            endEpisode(e,State.NO);return;
        }
        if(b==null) {
            b=new Budget();budgets.put(peer,b);
        }
        b.times.addLast(now);globalTimes.addLast(now);probesSent++;
        e.probes++;e.state=State.PROBING;e.probingSince=now;
        e.nextDue=e.probes<EPISODE_PROBES?e.episodeStart+OFFSETS[e.probes]:NEVER;
    }

    private void purgeBudgets(long now) {
        Iterator<Budget> it=budgets.values().iterator();
        while(it.hasNext()) {
            Budget b=it.next();
            while(!b.times.isEmpty()&&now-b.times.peekFirst()>=DAY_NANOS) {
                b.times.pollFirst();
            }
            if(b.times.isEmpty()) {
                it.remove();
            }
        }
    }

    @Override public String toString(){return "DHT peers";}
}
