// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 自分の発見の記録を、鍵に近い最大 20 台（自分を含む）へ預ける（核D。ADR 0030 答え 186 の Q6）。
 * 置き直すのは記録を出した端末（発行者）だけ。預かった側は置き直さない。
 * 呼ぶのは DhtNode と同じ 1 本のスレッドだけ。時計は呼ぶ側が now（ナノ秒）で渡す。
 * 失敗した相手へすぐ送り直さない（次の置き直しまで待つ）。
 * 番地・端末の番号・鍵・記録の鍵は、ログにも例外の文にも件数にも出さない。数えるのは台数だけ。
 */
public final class DhtPublisher {
    /** 置き直しの間隔（1 時間）。 */
    public static final long INTERVAL_NANOS=3600L*1_000_000_000L;
    /** 送り始めてから使用中の印を外すまでの内部の安全弁（10 秒）。STORE の待ち（3 秒）より十分長く、通常は届かない。 */
    static final long SENDING_LIMIT_NANOS=10L*1_000_000_000L;

    /** 1 回の公開の数え方。送り先の数・送れた数・ACK の数は別。 */
    public static final class Report {
        private final int destinations,sent,acked,refused,expired;
        private final boolean selfStored;
        private final DhtNode.Stop lookupStop;
        private Report(int destinations,int sent,int acked,int refused,int expired,boolean selfStored,DhtNode.Stop lookupStop) {
            this.destinations=destinations;this.sent=sent;this.acked=acked;this.refused=refused;this.expired=expired;
            this.selfStored=selfStored;this.lookupStop=lookupStop;
        }
        /** 送り先に決めた他の端末の数（自分は含めない。最大 20。自分が距離の上位 20 に入るときは最大 19）。 */
        public int destinations(){return destinations;}
        /** 実際に STORE を送り始められた数。 */
        public int sent(){return sent;}
        /** 相手が受け取った（ACCEPTED・DUPLICATE）と答えた数。 */
        public int acked(){return acked;}
        /** 相手が受け取らないと答えた数（古い版・満杯など）。 */
        public int refused(){return refused;}
        /** 返事がなく切れた、または途中で捨てられた数。 */
        public int expired(){return expired;}
        /** 自分の手元の預かりに入れたか。 */
        public boolean selfStored(){return selfStored;}
        /** 探索の終わり方。 */
        public DhtNode.Stop lookupStop(){return lookupStop;}
        @Override public String toString(){return "DHT publish report";}
    }

    private enum State { IDLE,LOOKING,SENDING }

    private final DhtNode<?> node;
    private final DhtDispatcher dispatcher;
    private final DiscoveryStore store;
    private State state=State.IDLE;
    private boolean everPublished,dirty;
    private long lastPublished,sendingSince;
    private byte[] record;
    private DhtNode<?>.Lookup lookup;
    private final Set<DhtId> inFlight=new HashSet<>();
    private int destinations,sent,acked,refused,expired;
    private boolean selfStored;
    private DhtNode.Stop stop;
    private Report last;

    public DhtPublisher(DhtNode<?> node,DhtDispatcher dispatcher,DiscoveryStore store) {
        this.node=Objects.requireNonNull(node);this.dispatcher=Objects.requireNonNull(dispatcher);this.store=Objects.requireNonNull(store);
        dispatcher.setPublishInUse(this::inUse);
        dispatcher.setStoreListener(this::storeEnded);
    }

    /** 送り先に決めて、STORE がまだ終わっていない相手か。手放しの対象から外すために DhtDispatcher が聞く。 */
    boolean inUse(DhtId peer){return inFlight.contains(peer);}

    public boolean active(){return state!=State.IDLE;}

    /** 直前に終わった公開の数え方。まだ 1 回も終わっていないときは null。 */
    public Report lastReport(){return last;}

    /** 記録の版が変わった。次の publishDue で置き直す。 */
    public void recordChanged(){dirty=true;}

    /** ネットワークが変わった。公開の途中を捨て、次の publishDue で置き直す。 */
    public void networkChanged(){
        abandon();
        dirty=true;
    }

    /**
     * いま置き直すべきか。1 時間たった・版が変わった・ネットワークが変わった・まだ公開していない、のどれかで true。
     * 公開の途中は常に false（重ねて始めない）。時計が戻っていたら使用中を外して true にする。
     */
    public boolean publishDue(long now) {
        if(everPublished&&now-lastPublished<0) {
            // 時計が戻った。途中の公開を捨てて、すぐ置き直せるようにする。
            abandon();
            dirty=true;
            lastPublished=now;
        }
        if(state!=State.IDLE)return false;
        return !everPublished||dirty||now-lastPublished>=INTERVAL_NANOS;
    }

    /** 記録の鍵に近い相手を探して預け始める。公開の途中なら何もせず false。記録が壊れていても false。 */
    public boolean publish(byte[] signedRecord,long now) {
        Objects.requireNonNull(signedRecord);
        if(state!=State.IDLE)return false;
        DiscoveryRecord parsed;
        try {
            parsed=DiscoveryRecord.parse(signedRecord);
        } catch(RuntimeException malformed) {
            return false;
        }
        // 探索の枠が空いていなければ、何も変えずに false（次の周期でまた始める。publishDue は true のまま）。
        if(!node.canStartLookup())return false;
        lookup=node.findNode(parsed.key());
        record=signedRecord.clone();
        state=State.LOOKING;
        everPublished=true;dirty=false;lastPublished=now;
        destinations=0;sent=0;acked=0;refused=0;expired=0;selfStored=false;stop=null;
        return true;
    }

    /** 周期の処理から呼ぶ。探索が終わったら送り、全部終わったら数え方をまとめる。 */
    public void poll(long now) {
        if(everPublished&&now-lastPublished<0){publishDue(now);return;}
        if(state==State.LOOKING&&lookup.done())send(now);
        if(state==State.SENDING&&inFlight.isEmpty())finish();
        // 内部の安全弁: 返事も期限切れの知らせも来ないまま残ったときは、使用中を外して終える。
        if(state==State.SENDING&&now-sendingSince>=SENDING_LIMIT_NANOS) {
            expired+=inFlight.size();
            inFlight.clear();
            finish();
        }
    }

    private void send(long now) {
        DhtNode.Result<?> result=lookup.result();
        stop=result.stop();
        DiscoveryRecord parsed=DiscoveryRecord.parse(record);
        DhtId key=parsed.key(),self=parsed.nodeId();
        // 返事をくれた近い相手に自分を足し、鍵に近い順に最大 20 を選ぶ。自分は手元の表へ、ほかは STORE で送る。
        List<Contact> chosen=new ArrayList<>(result.closest());
        boolean selfIncluded=false;
        for(Contact c:chosen)if(c.id().equals(self))selfIncluded=true;
        if(!selfIncluded)chosen.add(new Contact(self));
        chosen.sort((a,b)->key.compareDistance(a.id(),b.id()));
        if(chosen.size()>DhtLimits.K)chosen=new ArrayList<>(chosen.subList(0,DhtLimits.K));
        state=State.SENDING;
        for(Contact c:chosen) {
            if(c.id().equals(self)){storeSelf(self);continue;}
            destinations++;
            boolean started;
            // 送る前に使用中へ入れる。送信の中から同期で終わりが知らされても、取りこぼさないため。
            inFlight.add(c.id());
            try {
                started=dispatcher.store(c,record);
            } catch(RuntimeException failed) {
                started=false;
            }
            if(started)sent++;
            else inFlight.remove(c.id());
        }
        sendingSince=now;
        lookup=null;
    }

    private void storeSelf(DhtId self) {
        try {
            DiscoveryStatus status=store.putOwn(self,record);
            selfStored=status==DiscoveryStatus.ACCEPTED||status==DiscoveryStatus.DUPLICATE;
        } catch(RuntimeException failed) {
            selfStored=false;
        }
    }

    /** DhtDispatcher から。STORE の返事（status）か、返事なく終わった（null）ことを知らされる。 */
    void storeEnded(DhtId peer,DhtWire.StoreStatus status) {
        if(!inFlight.remove(peer))return;
        if(status==null)expired++;
        else if(status==DhtWire.StoreStatus.ACCEPTED||status==DhtWire.StoreStatus.DUPLICATE)acked++;
        else refused++;
    }

    private void finish() {
        last=new Report(destinations,sent,acked,refused,expired,selfStored,stop);
        state=State.IDLE;
        record=null;
    }

    /** 公開の途中を捨てて、使用中の印を全部外す。 */
    private void abandon() {
        if(state!=State.IDLE)expired+=inFlight.size();
        inFlight.clear();
        lookup=null;
        if(state!=State.IDLE)finish();
    }

    @Override public String toString(){return "DHT publisher";}
}
