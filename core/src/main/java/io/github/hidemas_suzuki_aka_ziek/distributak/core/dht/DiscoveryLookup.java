// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.time.Clock;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryStatus.*;

/** 一探索だけで使う検査器。未知の発行者のVALUEでSTOREの枠を埋めない（回答7546）。 */
public final class DiscoveryLookup implements DhtNode.Verifier<DiscoveryRecord>,Comparator<DiscoveryRecord> {
    private record Version(DhtId key,long version){}
    private final DiscoveryStore store;
    private final Map<Version,byte[]> firstPayloads=new LinkedHashMap<>();
    private final DiscoveryCounts counts=new DiscoveryCounts();
    private boolean reported;
    DiscoveryLookup(DiscoveryStore store){this.store=store;}
    @Override public DiscoveryRecord verify(DhtId key,byte[] encoded,Clock clock) {
        try {
            DiscoveryRecord record=store.verify(encoded,clock);
            if(!record.key().equals(key))throw DiscoveryRecord.rejected(INVALID);
            DiscoveryStatus order=store.checkMaximum(record);
            if(order!=ACCEPTED&&order!=DUPLICATE)throw DiscoveryRecord.rejected(order);
            var version=new Version(record.key(),record.version());byte[] previous=firstPayloads.get(version);
            if(previous!=null&&!Arrays.equals(previous,record.payload()))throw DiscoveryRecord.rejected(CONFLICT);
            if(previous==null) {
                if(firstPayloads.size()>=DhtLimits.MAX_QUERIES)throw DiscoveryRecord.rejected(CAPACITY);
                firstPayloads.put(version,record.payload());
            }
            return record;
        }catch(DiscoveryRejected rejected){counts.rejected(rejected.status());throw rejected;}
    }
    @Override public int compare(DiscoveryRecord left,DiscoveryRecord right) {
        try {
            if(!left.key().equals(right.key()))throw DiscoveryRecord.rejected(INVALID);
            int order=Long.compare(left.version(),right.version());if(order!=0)return order;
            if(!Arrays.equals(left.payload(),right.payload()))throw DiscoveryRecord.rejected(CONFLICT);
            return 0;
        }catch(DiscoveryRejected rejected){counts.rejected(rejected.status());throw rejected;}
    }
    /** 探索が終わったとき 1 回だけ、この探索の件数を預かりの表へ足す。二度目以降は何もしない。 */
    @Override public void finished(){if(!reported){reported=true;store.counts().add(counts);}}
    public DiscoveryCounts counts(){return counts;}
    @Override public String toString(){return "DHT discovery lookup verifier";}
}
