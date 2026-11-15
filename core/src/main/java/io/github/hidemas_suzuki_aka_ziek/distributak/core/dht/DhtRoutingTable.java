// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

/** 呼び出し元の一つのスレッドで使う。認証済みDHT受信だけがLRUを更新する。 */
public final class DhtRoutingTable {
    static final class Probe {
        private final AuthenticatedPeer incumbent,replacement;
        private Probe(AuthenticatedPeer incumbent,AuthenticatedPeer replacement){this.incumbent=incumbent;this.replacement=replacement;}
        AuthenticatedPeer incumbent(){return incumbent;}
        @Override public String toString(){return "DHT bucket probe";}
    }
    private static final class Bucket {
        final LinkedHashMap<DhtId,AuthenticatedPeer> peers=new LinkedHashMap<>();
        Probe probe;
    }
    private final DhtId local;
    private final Bucket[] buckets=new Bucket[DhtLimits.BUCKETS];
    public DhtRoutingTable(DhtId local){this.local=Objects.requireNonNull(local);}
    public void observe(AuthenticatedPeer peer) {
        Objects.requireNonNull(peer);int index=local.bucketIndex(peer.id());if(index<0)return;
        Bucket bucket=buckets[index];if(bucket==null)buckets[index]=bucket=new Bucket();
        if(bucket.peers.remove(peer.id())!=null) {
            bucket.peers.put(peer.id(),peer);
            if(bucket.probe!=null&&bucket.probe.incumbent.id().equals(peer.id()))bucket.probe=null;
        } else if(bucket.peers.size()<DhtLimits.K)bucket.peers.put(peer.id(),peer);
        else if(bucket.probe==null)bucket.probe=new Probe(bucket.peers.values().iterator().next(),peer);
    }
    /** 手放した相手を表から外す。桶の交換待ちが、その相手を古い側・新しい側のどちらで含んでいても片付ける。 */
    public boolean remove(DhtId id) {
        Objects.requireNonNull(id);int index=local.bucketIndex(id);if(index<0||buckets[index]==null)return false;
        Bucket bucket=buckets[index];boolean removed=bucket.peers.remove(id)!=null;
        if(bucket.probe!=null&&(bucket.probe.incumbent.id().equals(id)||bucket.probe.replacement.id().equals(id)))bucket.probe=null;
        return removed;
    }
    /** その相手が表に入っているか。観察も順序の更新もしない。 */
    public boolean contains(DhtId id) {
        Objects.requireNonNull(id);int index=local.bucketIndex(id);
        return index>=0&&buckets[index]!=null&&buckets[index].peers.containsKey(id);
    }
    /** その相手が入っている桶の台数（入っていなければ 0）。手放す順位で「一番詰まった桶」を選ぶのに使う。 */
    int bucketLoadOf(DhtId id) {
        Objects.requireNonNull(id);int index=local.bucketIndex(id);
        return index<0||buckets[index]==null||!buckets[index].peers.containsKey(id)?0:buckets[index].peers.size();
    }
    /** 桶の中でその相手が古い方から何番目か（0 が一番古い。入っていなければ -1）。 */
    int ageRankOf(DhtId id) {
        Objects.requireNonNull(id);int index=local.bucketIndex(id);
        if(index<0||buckets[index]==null)return -1;
        int n=0;for(DhtId key:buckets[index].peers.keySet()){if(key.equals(id))return n;n++;}
        return -1;
    }
    public int size(){int size=0;for(Bucket bucket:buckets)if(bucket!=null)size+=bucket.peers.size();return size;}
    public int allocatedBuckets(){int size=0;for(Bucket bucket:buckets)if(bucket!=null)size++;return size;}
    public int pendingCount(){int size=0;for(Bucket bucket:buckets)if(bucket!=null&&bucket.probe!=null)size++;return size;}
    public List<AuthenticatedPeer> bucket(int index) {
        if(index<0||index>=buckets.length)throw new IllegalArgumentException("DHTバケットの範囲が違います");
        return buckets[index]==null?List.of():List.copyOf(buckets[index].peers.values());
    }
    public List<AuthenticatedPeer> nearest(DhtId target,int maximum) {
        Objects.requireNonNull(target);if(maximum<0)throw new IllegalArgumentException("DHTの台数が範囲外です");
        List<AuthenticatedPeer> peers=new ArrayList<>();for(Bucket bucket:buckets)if(bucket!=null)peers.addAll(bucket.peers.values());
        peers.sort((a,b)->target.compareDistance(a.id(),b.id()));
        return List.copyOf(peers.subList(0,Math.min(maximum,peers.size())));
    }
    List<Probe> probes() {
        List<Probe> result=new ArrayList<>();for(Bucket bucket:buckets)if(bucket!=null&&bucket.probe!=null)result.add(bucket.probe);
        return result;
    }
    boolean isPending(Probe probe) {
        int index=local.bucketIndex(probe.incumbent.id());
        return index>=0&&buckets[index]!=null&&buckets[index].probe==probe;
    }
    void resolve(Probe probe,boolean alive) {
        if(!isPending(probe))return;Bucket bucket=buckets[local.bucketIndex(probe.incumbent.id())];
        var previous=bucket.peers.remove(probe.incumbent.id());
        var selected=alive?previous:probe.replacement;
        bucket.peers.put(selected.id(),selected);bucket.probe=null;
    }
    /** 手元の配送失敗では、生存の確認もLRUの更新もしない。交換待ちだけを捨てる。 */
    void discard(Probe probe) {
        if(isPending(probe))buckets[local.bucketIndex(probe.incumbent.id())].probe=null;
    }
    void clearPending(){for(Bucket bucket:buckets)if(bucket!=null)bucket.probe=null;}
    void clear(){java.util.Arrays.fill(buckets,null);}
    @Override public String toString(){return "DHT routing table";}
}
