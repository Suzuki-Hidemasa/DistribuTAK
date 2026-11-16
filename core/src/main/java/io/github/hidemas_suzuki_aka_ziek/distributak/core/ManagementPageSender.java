// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 管理ページの送り手。通信・時刻・予算は注入し、製品の通信口にはまだ接続しない。
 * 同じスレッドから呼び、送信口は受信処理を同期で呼び戻さずキューへ渡す。
 * <p>
 * A management page sender with injected transport, time and budget, not yet connected to product transport entry points.
 * Call on one thread; the transport queues frames rather than calling receive processing back synchronously.
 */
public final class ManagementPageSender {
    @FunctionalInterface public interface Sender {boolean send(byte[] peer,byte[] session,byte[] plaintext);}
    public enum Offer {ACCEPTED,FULL,BUSY,PEER_BUSY,INVALID,DHT_TRANSFER_OR_INVITATION}
    public static final long MAX_HELD_BYTES=8L*1024*1024;
    private static final long TOTAL_MS=240000,PROGRESS_MS=30000;
    private static final long[] ROUNDS={0,5000,15000};
    private static final class Out {
        final DhtId peer;final byte[] session;final long generation,offered;
        final List<ManagementPage> pages;final boolean notice;
        final boolean[] acked,sent,ever;final int[] retries;final long[] sentAt;
        long started,progress;int round,ackCount;
        Out(byte[] peer,byte[] session,long generation,List<ManagementPage> pages,boolean notice,long now){
            this.peer=new DhtId(peer);this.session=session.clone();this.generation=generation;this.pages=pages;this.notice=notice;offered=now;
            int n=pages.size();acked=new boolean[n];sent=new boolean[n];ever=new boolean[n];retries=new int[n];sentAt=new long[n];
        }
        int rank(){return switch(pages.get(0).kind()){case REVOCATION->0;case ANNOUNCEMENT->1;default->2;};}
        int bytes(){return pages.get(0).totalBytes();}
        boolean blocked(boolean rotating){return rotating&&rank()==2&&pages.size()>1;}
        void activate(long now){started=now;progress=now;}
    }
    private final byte[] group;
    private final Clock clock;
    private final ManagementSendBudget budget;
    private final Sender sender;
    private final List<Out> pending=new ArrayList<>(),active=new ArrayList<>();
    private boolean rotating;
    private long held,completed,failed,last=Long.MIN_VALUE;
    public ManagementPageSender(byte[] group,Clock clock,ManagementSendBudget budget,Sender sender){
        Crypto.length(group,32);this.group=group.clone();this.clock=Objects.requireNonNull(clock);
        this.budget=Objects.requireNonNull(budget);this.sender=Objects.requireNonNull(sender);
    }
    public static Offer deliveryPlan(int pages){
        if(pages<1||pages>ManagementPage.MAX_PAGES)return Offer.INVALID;
        return pages<=480?Offer.ACCEPTED:Offer.DHT_TRANSFER_OR_INVITATION;
    }
    public Offer offer(byte[] peer,byte[] session,long generation,ManagementPage.Kind kind,byte[] operation,byte[] data,int entries,boolean notice){
        Crypto.length(peer,32);Crypto.length(session,16);Crypto.length(operation,16);Objects.requireNonNull(kind);
        if(data==null||data.length<1||data.length>ManagementPage.MAX_TOTAL_BYTES||entries<0||entries>ManagementPage.MAX_ENTRIES)return Offer.INVALID;
        var plan=deliveryPlan((data.length+1023)/1024);if(plan!=Offer.ACCEPTED)return plan;
        if((kind==ManagementPage.Kind.ROSTER||kind==ManagementPage.Kind.ROSTER_SUMMARY)&&(entries>32||data.length>65536))return Offer.INVALID;
        DhtId key=new DhtId(peer);
        if(all().stream().anyMatch(o->o.peer.equals(key)&&o.pages.get(0).kind()==kind))return Offer.PEER_BUSY;
        Set<DhtId> queued=queuedPeers();
        if(!isActive(key)&&!queued.contains(key)&&queued.size()>=32)return queued.size()>32?Offer.BUSY:Offer.FULL;
        if(held+data.length>MAX_HELD_BYTES)return Offer.BUSY;
        var pages=ManagementPage.split(kind,operation,group,data,entries);
        pending.add(new Out(peer,session,generation,pages,notice,clock.millis()));held+=data.length;return Offer.ACCEPTED;
    }
    private List<Out> all(){var result=new ArrayList<>(pending);result.addAll(active);return result;}
    private boolean isActive(DhtId peer){return active.stream().anyMatch(o->o.peer.equals(peer));}
    private Set<DhtId> queuedPeers(){
        var peers=new HashSet<DhtId>();for(var o:pending)if(!isActive(o.peer))peers.add(o.peer);return peers;
    }
    private void remove(Out o,boolean success){
        active.remove(o);pending.remove(o);held-=o.bytes();if(success)completed++;else failed++;
    }
    private void promoteSamePeer(DhtId peer,long now){
        var next=pending.stream().filter(o->o.peer.equals(peer)&&!o.blocked(rotating)).min(Comparator.comparingInt(Out::rank)).orElse(null);
        if(next!=null){pending.remove(next);next.activate(now);active.add(next);}
    }
    public void poll(){
        long now=clock.millis();
        if(now<last){for(var o:all())remove(o,false);last=now;return;}last=now;
        for(var o:new ArrayList<>(pending))if(now-o.offered>=TOTAL_MS)remove(o,false);
        for(var o:new ArrayList<>(active)){
            if(now-o.offered>=TOTAL_MS||now-o.progress>=PROGRESS_MS){remove(o,false);promoteSamePeer(o.peer,now);}
        }
        while(active.size()<2){
            var next=pending.stream().filter(o->!isActive(o.peer)&&!o.blocked(rotating)).min(Comparator.comparingInt(Out::rank)).orElse(null);
            if(next==null)break;pending.remove(next);next.activate(now);active.add(next);
        }
        for(var o:new ArrayList<>(active)){
            if(o.blocked(rotating))continue;
            if(!advance(o,now)){remove(o,false);promoteSamePeer(o.peer,now);}
        }
    }
    private boolean advance(Out o,long now){
        if(o.notice){
            int round=now-o.started>=ROUNDS[2]?2:now-o.started>=ROUNDS[1]?1:0;
            if(round>o.round){
                o.round=round;Arrays.fill(o.sent,false);Arrays.fill(o.retries,0);
            }
        }
        int inFlight=0;
        for(int i=0;i<o.pages.size();i++)if(o.sent[i]&&!o.acked[i])inFlight++;
        for(int i=0;i<o.pages.size();i++){
            if(o.acked[i]||!o.sent[i]||now-o.sentAt[i]<1000)continue;
            if(o.retries[i]>=3){if(!o.notice||o.round==2)return false;continue;}
            if(!transmit(o,i,now))return true;o.retries[i]++;
        }
        for(int i=0;i<o.pages.size()&&inFlight<4;i++){
            if(o.acked[i]||o.sent[i])continue;
            if(!transmit(o,i,now))break;inFlight++;
        }
        return true;
    }
    private boolean transmit(Out o,int index,long now){
        if(!budget.tryTake(o.peer.bytes(),1))return false;
        // 送信口の失敗も試行として数え、無限の送り直しを避ける。
        // Count transport failures as attempts as well, avoiding unbounded retries.
        o.sent[index]=true;o.ever[index]=true;o.sentAt[index]=now;
        try{sender.send(o.peer.bytes(),o.session.clone(),o.pages.get(index).envelope());}catch(RuntimeException ignored){}
        return true;
    }
    public void acknowledge(byte[] peer,byte[] session,long generation,ManagementPageAck ack){
        Objects.requireNonNull(ack);var key=new DhtId(peer);long now=clock.millis();
        var out=active.stream().filter(o->o.peer.equals(key)).findFirst().orElse(null);
        if(out==null||out.generation!=generation||!Arrays.equals(out.session,session)||!Arrays.equals(group,ack.group()))return;
        var first=out.pages.get(0);
        if(!Arrays.equals(first.operationId(),ack.operationId())||!Arrays.equals(first.objectDigest(),ack.objectDigest()))return;
        if(now<last||now-out.offered>=TOTAL_MS||now-out.progress>=PROGRESS_MS)return;
        for(int i:ack.pageIndices())if(i>=out.pages.size())return;
        for(int i:ack.pageIndices())if(out.ever[i]&&!out.acked[i]){out.acked[i]=true;out.ackCount++;out.progress=now;}
        if(out.ackCount==out.pages.size()){remove(out,true);promoteSamePeer(out.peer,now);}
    }
    public boolean sendAck(byte[] peer,byte[] session,ManagementPageAck ack){
        Crypto.length(session,16);if(!Arrays.equals(group,ack.group())||!budget.tryTake(peer,1))return false;
        try{return sender.send(peer.clone(),session.clone(),ack.envelope());}catch(RuntimeException failed){return false;}
    }
    public void rotating(boolean value){
        rotating=value;
        for(var o:new ArrayList<>(active))if(o.blocked(rotating)){active.remove(o);pending.add(o);}
    }
    public int active(){return active.size();}
    public int pendingPeers(){return queuedPeers().size();}
    public long completed(){return completed;}
    public long failed(){return failed;}
    public long heldBytes(){return held;}
}
