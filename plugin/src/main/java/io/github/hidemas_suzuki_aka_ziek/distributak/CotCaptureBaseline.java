// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;

/** workerが所有する保存済みの基準。候補の生成では基準を進めない。 */
final class CotCaptureBaseline {
    private record Value(byte[] full,byte[] content,byte[] withoutStale,long stale,boolean restored){}
    static final class Candidate implements AutoCloseable {
        final String uid;final byte[] xml;
        Candidate(String uid,byte[] xml){this.uid=uid;this.xml=xml;}
        public void close(){Crypto.wipe(xml);}
    }
    private final Map<String,Value> saved=new HashMap<>();
    private Value value(byte[] xml,boolean restored){return new Value(CotCaptureXml.fingerprint(xml,CotCaptureXml.EXCLUDED),CotCaptureXml.parts(xml,CotCaptureXml.CLOCK_FIELDS)[3],CotCaptureXml.fingerprint(xml,Set.of("stale")),CotXml.inspect(xml).stale(),restored);}
    void restore(SyncState state){
        saved.clear();for(CotRecord record:state.records()){
            var origin=state.origin(record.uid());if(record.deleted()||origin!=SyncState.Origin.LOCAL_POSITION&&origin!=SyncState.Origin.LOCAL_CREATED)continue;
            byte[] xml=record.xml();try{saved.put(record.uid(),value(xml,true));}finally{Crypto.wipe(xml);}
        }
    }
    Candidate candidate(String uid,byte[] xml,boolean position){
        if(saved.size()>=CotCapturePolicy.MAX_REVIEW_UIDS&&!saved.containsKey(uid))return null;
        if(!CotXml.inspect(xml).uid().equals(uid))throw new IllegalArgumentException("CoTの識別が違います");
        Value next=value(xml,false),old=saved.get(uid);
        if(old!=null){
            if(Arrays.equals(old.full,next.full))return null;
            if(position&&Arrays.equals(old.content,next.content))return null;
            // 短縮前の期限は保存から復元できない。同じ内容の期限延長を推測しない。
            if(old.restored&&Arrays.equals(old.withoutStale,next.withoutStale)&&next.stale>old.stale)return null;
        }
        byte[] output=position&&old!=null&&next.stale>old.stale?CotCaptureXml.stale(xml,old.stale):xml.clone();
        return new Candidate(uid,output);
    }
    void saved(CotRecord record){
        byte[] xml=record.xml();try{saved.put(record.uid(),value(xml,false));}finally{Crypto.wipe(xml);}
    }
    void clear(){saved.clear();}
}
