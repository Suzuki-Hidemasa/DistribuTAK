// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.ArrayList;
import java.util.List;

/**
 * 発見記録と管理記録のメモリ上の預かりを合算する。永続状態は数えない。
 * <p>
 * Counts in-memory discovery and management copies together, excluding durable trusted state.
 */
public final class DhtRecordBudget {
    public static final int MAX_RECORDS=4096,MAX_BYTES=4*1024*1024;
    private final List<Runnable> purgers=new ArrayList<>();
    private int count,bytes;private boolean purging;
    void register(Runnable purge){purgers.add(purge);}
    void purge(){
        if(purging)return;purging=true;
        try{for(var purge:purgers)purge.run();}finally{purging=false;}
    }
    boolean replace(int previous,int next){
        if(previous<0||next<0||previous>bytes)return false;
        int nextCount=count+(previous==0?1:0)-(next==0?1:0);
        if(nextCount<0||nextCount>MAX_RECORDS||next>MAX_BYTES-(bytes-previous))return false;
        count=nextCount;bytes=bytes-previous+next;return true;
    }
    public int count(){return count;}
    public int bytes(){return bytes;}
}
