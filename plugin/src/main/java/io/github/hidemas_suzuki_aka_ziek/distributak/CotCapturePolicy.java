// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;

/** 照合の予約と削除の連続性。時刻は単調時計のミリ秒。XML・所有の証拠は保持しない。 */
final class CotCapturePolicy {
    // 試験用の初めの値。実機の負荷を測って見直す。
    static final int MAX_ITEMS=8192,MAX_GROUPS=1024,MAX_DEPTH=64,MAX_REVIEW_UIDS=4096;
    static final long EMPTY_MILLIS=10_000,SMALL_MILLIS=5_000,LARGE_MILLIS=20_000,POSITION_MILLIS=5_000;
    static final String LIMIT_TEXT="上限を超えたため、削除と新しい物の送信を止めています";
    enum Result { SUCCESS,LIMIT,INTERRUPTED,INCONSISTENT }
    private static final class Presence {
        boolean seen,deleted;int absent;
        void reset(){absent=0;}
    }
    private final Map<String,Presence> published=new HashMap<>();
    private boolean running,first=true,limited,periodic,timeBackoff;
    private long due,delay;
    boolean begin(long now,boolean signal){
        if(running||!first&&(now<due&&(!signal||limited)))return false;
        periodic=first||now>=due;running=true;first=false;return true;
    }
    void end(long now,int count,Result result,long elapsedNanos){
        running=false;limited=result==Result.LIMIT;timeBackoff=elapsedNanos>8_000_000;
        delay=result!=Result.SUCCESS||count>100||timeBackoff?LARGE_MILLIS:count==0?EMPTY_MILLIS:SMALL_MILLIS;
        if(periodic||result!=Result.SUCCESS)due=now+delay;
    }
    boolean timeBackoff(){return timeBackoff;}
    long delay(){return delay;}
    long due(){return due;}
    boolean periodic(){return periodic;}
    boolean limited(){return limited;}
    void saved(String uid,boolean deleted){
        Presence p=published.get(uid);
        if(p==null){if(published.size()>=MAX_REVIEW_UIDS)return;p=new Presence();published.put(uid,p);}
        p.deleted=deleted;p.reset();
    }
    void seen(Set<String> uids){for(String uid:uids){Presence p=published.get(uid);if(p!=null){p.seen=true;p.reset();}}}
    void absent(Set<String> uids,boolean periodic,Result result){
        if(result!=Result.SUCCESS){resetContinuity();return;}
        seen(uids);
        if(periodic)for(var entry:published.entrySet()){
            Presence p=entry.getValue();if(p.seen&&!p.deleted&&!uids.contains(entry.getKey())){
                p.absent=Math.min(3,p.absent+1);
            }
        }
    }
    boolean deletable(String uid,boolean stillAbsent,boolean ownershipValid){
        Presence p=published.get(uid);
        if(p!=null&&!stillAbsent){p.seen=true;p.reset();}
        boolean ready=p!=null&&p.seen&&!p.deleted&&p.absent>=3&&stillAbsent&&ownershipValid;
        return ready;
    }
    void resetContinuity(){for(Presence p:published.values())p.reset();}
}
