// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 第12段 模擬の JUnit（256 台の 4 本）。4096 台・65536 台は手で動かし、ここには入れない。
 * 合格線はまず目標ファイルの仮の値。値は合わせ込まない。失敗の文にも番号・鍵・番地は出さない。
 */
class DhtSimTest {
    static final long LIMIT=3_000_000L;
    static int log2Ceil(int n){return 32-Integer.numberOfLeadingZeros(n-1);}

    static void commonLines(DhtSim.Result r,int nodes) {
        assertFalse(r.eventLimitHit,"The event limit was hit");
        assertEquals(nodes,r.nodesJoined,"Not every node joined");
        assertEquals(0,r.badAdopted,"A bad record was adopted");
        assertEquals(0,r.queryOverruns,"A lookup passed the query budget");
        assertEquals(0,r.abnormalStops,"A lookup ended abnormally");
        assertTrue(r.depthP95<=2*log2Ceil(nodes),"Lookup depth p95 is over 2*ceil(log2 N)");
        endKeysAddUp(r);
    }

    /** 試験 L（答え 191 (4)(6)）。終わり方の集計名は、探索の結果の組（stop と値の有無）で決まる。 */
    @Test void lStopKeysCountAValueOnlyWhenTheLookupReturnedOne() {
        assertEquals("DEADLINE_WITH_VALUE",DhtSim.endKey(DhtNode.Stop.DEADLINE,true));
        assertEquals("DEADLINE_NOVALUE",DhtSim.endKey(DhtNode.Stop.DEADLINE,false));
        assertEquals("QUERY_LIMIT_WITH_VALUE",DhtSim.endKey(DhtNode.Stop.QUERY_LIMIT,true));
        assertEquals("QUERY_LIMIT_NOVALUE",DhtSim.endKey(DhtNode.Stop.QUERY_LIMIT,false));
        assertEquals("COMPLETE",DhtSim.endKey(DhtNode.Stop.COMPLETE,true));
        assertEquals("COMPLETE_NOVALUE",DhtSim.endKey(DhtNode.Stop.COMPLETE,false));
        assertEquals("CLOCK_RESET",DhtSim.endKey(DhtNode.Stop.CLOCK_RESET,false));
        assertEquals("NETWORK_CHANGED",DhtSim.endKey(DhtNode.Stop.NETWORK_CHANGED,false));
    }

    /** 試験 L の模擬側。全探索の終わり方が、核が返した stop と値の有無の数と食い違わない。 */
    static void endKeysAddUp(DhtSim.Result r) {
        long deadline=r.counts.getOrDefault("end.DEADLINE_WITH_VALUE",0L)+r.counts.getOrDefault("end.DEADLINE_NOVALUE",0L);
        long limit=r.counts.getOrDefault("end.QUERY_LIMIT_WITH_VALUE",0L)+r.counts.getOrDefault("end.QUERY_LIMIT_NOVALUE",0L);
        long complete=r.counts.getOrDefault("end.COMPLETE",0L)+r.counts.getOrDefault("end.COMPLETE_NOVALUE",0L);
        assertEquals(r.counts.getOrDefault("lookupStopDeadline",0L),deadline,"The deadline keys do not add up");
        assertEquals(r.counts.getOrDefault("lookupStopQueryLimit",0L),limit,"The query limit keys do not add up");
        assertEquals(r.counts.getOrDefault("lookupStopComplete",0L),complete,"The complete keys do not add up");
        long withValue=r.counts.getOrDefault("end.COMPLETE",0L)+r.counts.getOrDefault("end.DEADLINE_WITH_VALUE",0L)
                +r.counts.getOrDefault("end.QUERY_LIMIT_WITH_VALUE",0L);
        assertEquals(r.counts.getOrDefault("lookupsWithValue",0L),withValue,"A value was counted under a stop without one");
    }

    /** 試験 m4（答え 191 (6) (3)）。案 B は値の印で新しい問い合わせを出さないので、上限で値を返す数は 0。 */
    @Test void m4PlanBNeverReturnsAValueAtTheQueryLimit() {
        DhtSim.Result r=DhtSim.run(new DhtSim.Config(256,1,25,4,1,0,0,0,0,false,false,LIMIT));
        commonLines(r,256);
        assertEquals(0L,r.counts.getOrDefault("end.QUERY_LIMIT_WITH_VALUE",0L),"A value was returned at the query limit");
        assertEquals(0L,r.counts.getOrDefault("ek.QUERY_LIMIT_WITH_VALUE",0L),"A value was returned at the query limit");
        assertTrue(r.counts.getOrDefault("lookupsWithValue",0L)>0,"No lookup returned a value");
        long wv=r.counts.getOrDefault("lookupsWithValue",0L);
        // 値の印のあとは新しい問い合わせを出さないので、値を返した探索の問い合わせは少ない（基準は平均 3.5 件。印が働かないと 25 件ほど）。
        assertTrue(r.counts.getOrDefault("lookupQueriedWithValue",0L)<=8*wv,"Lookups that returned a value asked too many peers on average");
    }

    @Test void normalNetworkOf256NodesFindsEveryPublishedRecord() {
        DhtSim.Result r=DhtSim.run(new DhtSim.Config(256,1,25,4,1,0,0,0,0,false,false,LIMIT));
        commonLines(r,256);
        assertTrue(r.existingLookups>0,"No lookup of an existing key was made");
        assertEquals(r.existingLookups,r.existingFound,"An existing record was not found");
        assertEquals(0,r.missingFound,"A missing key returned a record");
    }

    @Test void lookupsOfMissingKeysInNetworkOf256NodesFindNothingAndStopInTime() {
        DhtSim.Result r=DhtSim.run(new DhtSim.Config(256,2,25,0,5,0,0,0,0,false,false,LIMIT));
        commonLines(r,256);
        assertTrue(r.missingLookups>0,"No lookup of a missing key was made");
        assertEquals(0,r.missingFound,"A missing key returned a record");
    }

    @Test void faultyNetworkOf256NodesKeepsRecordsFindable() {
        DhtSim.Result r=DhtSim.run(new DhtSim.Config(256,3,25,4,1,10,10,10,2,true,false,LIMIT));
        commonLines(r,256);
        assertTrue(r.existingLookups>0,"No lookup of an existing key was made");
        // 目標ファイルの指針: 故障ありは 99% 以上（合わせ込まない）。
        assertTrue(r.existingFound*100>=r.existingLookups*99,"Under 99 percent of existing records were found");
        assertEquals(0,r.missingFound,"A missing key returned a record");
        assertEquals(0L,r.counts.getOrDefault("revokedAdopted",0L),"A revoked record was adopted");
    }

    @Test void recordsExpireAfter24HoursAndLiveOnesStayFindable() {
        DhtSim.Result r=DhtSim.run(new DhtSim.Config(256,4,25,2,1,0,0,10,0,false,true,LIMIT*4));
        commonLines(r,256);
        assertTrue(r.liveLookups>0,"No lookup of a live record was made");
        assertEquals(r.liveLookups,r.liveFound,"A live record was not found after 24 hours");
        assertTrue(r.expiredLookups>0,"No lookup of an expired record was made");
        assertEquals(0,r.expiredStillFound,"An expired record was still served");
    }
}
