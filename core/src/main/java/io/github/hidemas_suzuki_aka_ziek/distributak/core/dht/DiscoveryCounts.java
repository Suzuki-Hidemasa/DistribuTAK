// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/** 理由ごとの件数だけ。画面の拒否はINVALIDとREVOKEDの合計（回答7546）。 */
public final class DiscoveryCounts {
    private final long[] counts=new long[DiscoveryStatus.values().length];
    private long ownAccepted,ownRejected;
    void rejected(DiscoveryStatus status) {
        if(status!=DiscoveryStatus.ACCEPTED&&status!=DiscoveryStatus.DUPLICATE&&counts[status.ordinal()]!=Long.MAX_VALUE)counts[status.ordinal()]++;
    }
    /** 自分の記録を自分の表へ入れた結果。ACCEPTED と DUPLICATE は受け入れ、ほかは拒否。他の相手から受けた拒否の件数とは混ぜない。 */
    void own(DiscoveryStatus status) {
        boolean ok=status==DiscoveryStatus.ACCEPTED||status==DiscoveryStatus.DUPLICATE;
        if(ok){if(ownAccepted!=Long.MAX_VALUE)ownAccepted++;}
        else if(ownRejected!=Long.MAX_VALUE)ownRejected++;
    }
    public long ownAccepted(){return ownAccepted;}
    public long ownRejected(){return ownRejected;}
    /** 一探索ぶんの件数を足す。桁あふれはしない。 */
    void add(DiscoveryCounts other) {
        for(int n=0;n<counts.length;n++)counts[n]=counts[n]>Long.MAX_VALUE-other.counts[n]?Long.MAX_VALUE:counts[n]+other.counts[n];
        ownAccepted=ownAccepted>Long.MAX_VALUE-other.ownAccepted?Long.MAX_VALUE:ownAccepted+other.ownAccepted;
        ownRejected=ownRejected>Long.MAX_VALUE-other.ownRejected?Long.MAX_VALUE:ownRejected+other.ownRejected;
    }
    public long count(DiscoveryStatus status){return counts[status.ordinal()];}
    public long screenRejected() {
        long a=count(DiscoveryStatus.INVALID),b=count(DiscoveryStatus.REVOKED);return a>Long.MAX_VALUE-b?Long.MAX_VALUE:a+b;
    }
    @Override public String toString(){return "DHT discovery counters";}
}
