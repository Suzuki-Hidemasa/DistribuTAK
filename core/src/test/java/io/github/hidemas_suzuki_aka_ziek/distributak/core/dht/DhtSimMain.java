// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.Map;

/**
 * 手で動かす入口（JUnit には数えない）。件数と統計だけを出す。端末の番号・鍵・座標は出さない。
 * 引数（key=value）: nodes seed noDht existing missing loss dup depart evil faulty expiry limit lookupers
 */
public final class DhtSimMain {
    private DhtSimMain(){}

    public static void main(String[] args) {
        Map<String,String> a=new java.util.HashMap<>();
        for(String s:args){int i=s.indexOf('=');if(i>0)a.put(s.substring(0,i),s.substring(i+1));}
        DhtSim.Config cfg=new DhtSim.Config(
                i(a,"nodes",256),l(a,"seed",1),i(a,"noDht",25),i(a,"existing",4),i(a,"missing",1),
                i(a,"loss",0),i(a,"dup",0),i(a,"depart",0),i(a,"evil",0),
                Boolean.parseBoolean(a.getOrDefault("faulty","false")),Boolean.parseBoolean(a.getOrDefault("expiry","false")),
                l(a,"limit",3_000_000_000L),Boolean.parseBoolean(a.getOrDefault("closeNotify","false")));
        long t0=System.nanoTime();
        DhtSim.Result r=DhtSim.run(cfg,i(a,"lookupers",Integer.MAX_VALUE));
        long ms=(System.nanoTime()-t0)/1_000_000L;
        Runtime rt=Runtime.getRuntime();
        System.out.println("config="+cfg);
        System.out.println("wallMillis="+ms+" usedHeapMiB="+(rt.totalMemory()-rt.freeMemory())/(1024*1024));
        System.out.println("nodesJoined="+r.nodesJoined+" eventLimitHit="+r.eventLimitHit);
        System.out.println("existing="+r.existingFound+"/"+r.existingLookups+" missing(found)="+r.missingFound+"/"+r.missingLookups
                +" revokedLookups="+r.revokedLookups+" live="+r.liveFound+"/"+r.liveLookups
                +" expired(stillFound)="+r.expiredStillFound+"/"+r.expiredLookups);
        System.out.println("badAdopted="+r.badAdopted+" queryOverruns="+r.queryOverruns+" abnormalStops="+r.abnormalStops
                +" depthP95="+r.depthP95+" depthMax="+r.depthMax);
        for(Map.Entry<String,Long> e:r.counts.entrySet())System.out.println("  "+e.getKey()+"="+e.getValue());
    }

    private static int i(Map<String,String> a,String k,int d){return a.containsKey(k)?Integer.parseInt(a.get(k)):d;}
    private static long l(Map<String,String> a,String k,long d){return a.containsKey(k)?Long.parseLong(a.get(k)):d;}
}
