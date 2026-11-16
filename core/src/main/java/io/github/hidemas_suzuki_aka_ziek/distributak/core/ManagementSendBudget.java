// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 管理 DATA の送信だけに使う共通予算。DHT の速度予算とは分ける。
 * 相手4・全体32を直近1000msで数え、複数通の予約は一括で行う。同じスレッドから呼ぶ。
 * <p>
 * A shared budget only for outgoing management DATA, separate from DHT rate budgets.
 * Counts four per peer and 32 overall in the preceding 1000 ms and reserves multiple sends atomically. Call on one thread.
 */
public final class ManagementSendBudget {
    private final Clock clock;
    private final ArrayDeque<Long> total=new ArrayDeque<>();
    private final Map<DhtId,ArrayDeque<Long>> peers=new HashMap<>();
    private long last=Long.MIN_VALUE;
    public ManagementSendBudget(Clock clock){this.clock=Objects.requireNonNull(clock);}
    private static void expire(ArrayDeque<Long> times,long now){
        while(!times.isEmpty()&&now-times.peekFirst()>=1000)times.removeFirst();
    }
    private static void rebase(ArrayDeque<Long> times,long now){
        int count=times.size();times.clear();for(int i=0;i<count;i++)times.addLast(now);
    }
    public boolean tryTake(byte[] peer,int count){
        Crypto.length(peer,32);if(count<1||count>4)throw new IllegalArgumentException("Invalid management reservation");
        long now=clock.millis();
        if(now<last){
            rebase(total,now);
            peers.values().forEach(q->rebase(q,now));
        }
        last=now;
        expire(total,now);
        peers.values().forEach(q->expire(q,now));peers.values().removeIf(ArrayDeque::isEmpty);
        var key=new DhtId(peer);var mine=peers.get(key);
        if(total.size()+count>32||(mine!=null&&mine.size()+count>4))return false;
        if(mine==null){mine=new ArrayDeque<>();peers.put(key,mine);}
        for(int i=0;i<count;i++){mine.addLast(now);total.addLast(now);}return true;
    }
}
