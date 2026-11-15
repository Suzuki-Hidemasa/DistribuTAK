// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;

/** 待ちにはuid・出来事のビット・世代だけを持つ。MapItemやXMLは置かない。 */
final class CotMapSignals {
    private record Value(long generation,int kinds){}
    record Batch(Map<String,Integer> kinds,boolean overflow){}
    private final Map<String,Value> values=new LinkedHashMap<>();
    private boolean scheduled,overflow;
    synchronized boolean offer(String uid,long generation,int kind){
        Value previous=values.get(uid);
        if(previous==null&&values.size()>=CotCapturePolicy.MAX_REVIEW_UIDS)overflow=true;
        else values.put(uid,new Value(generation,(previous!=null&&previous.generation==generation?previous.kinds:0)|(1<<kind)));
        if(scheduled)return false;scheduled=true;return true;
    }
    synchronized Batch drain(long generation){
        var result=new LinkedHashMap<String,Integer>();for(var entry:values.entrySet())if(entry.getValue().generation==generation)result.put(entry.getKey(),entry.getValue().kinds);
        var batch=new Batch(result,overflow);clear();return batch;
    }
    synchronized void clear(){values.clear();scheduled=false;overflow=false;}
}
