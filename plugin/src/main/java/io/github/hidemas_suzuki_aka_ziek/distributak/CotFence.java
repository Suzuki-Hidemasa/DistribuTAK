// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.Set;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState;

/** 登録の返事を待ち、保存済みの受信UIDだけを送信禁止にする。 */
final class CotFence {
    private enum State { NEW,WAITING,READY,FAILED,STOPPED }
    private State state=State.NEW;
    private long began,consumed;
    private Set<String> received=Set.of();
    synchronized void begin(long now){if(state!=State.NEW)throw new IllegalStateException("柵は登録済みです");began=now;state=State.WAITING;}
    synchronized void registered(boolean success,long now){
        if(state==State.STOPPED||state==State.FAILED||state==State.NEW)return;
        if(!success||state==State.WAITING&&now-began>=5_000_000_000L)state=State.FAILED;
        else if(state==State.WAITING)state=State.READY;
    }
    synchronized void failedEvent(long now,boolean blocked){registered(false,now);if(blocked&&consumed<Long.MAX_VALUE)consumed++;}
    synchronized void poll(long now){if(state==State.WAITING&&now-began>=5_000_000_000L)state=State.FAILED;}
    synchronized void saved(Set<String> uids){if(uids.size()>SyncState.MAX_UIDS)throw new IllegalArgumentException("柵の記録が上限です");received=Set.copyOf(uids);}
    synchronized boolean contains(String uid){return uid!=null&&received.contains(uid);}
    synchronized boolean consume(String uid,boolean deletion,Set<String> targets){
        if(state==State.STOPPED)return false;
        boolean block=uid!=null&&received.contains(uid);
        if(!block&&deletion)for(String target:targets)if(received.contains(target)){block=true;break;}
        if(block&&consumed<Long.MAX_VALUE)consumed++;return block;
    }
    synchronized boolean ready(){return state==State.READY;}
    synchronized boolean failed(){return state==State.FAILED;}
    synchronized long consumed(){return consumed;}
    synchronized void stop(){state=State.STOPPED;received=Set.of();}
}
