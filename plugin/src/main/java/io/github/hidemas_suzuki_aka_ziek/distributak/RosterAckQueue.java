// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import java.time.Clock;
import java.util.*;

/**
 * 名簿ACKだけの有限な送信待ち。内容の平文は保持せず、元の期限を延ばさない。
 * <p>
 * Bounded send waiting for roster ACKs only, retaining no object plaintext and never extending original deadlines.
 */
final class RosterAckQueue implements AutoCloseable {
    interface Current {boolean test(byte[] peer,byte[] session,long generation);}
    interface Send {boolean send(byte[] peer,byte[] session,ManagementPageAck ack);}
    private static final class Pending {
        final byte[] session;final long generation,received,began;ManagementPageAck ack;
        Pending(byte[] session,long generation,ManagementPageAck ack,long received,long began){
            this.session=session.clone();this.generation=generation;this.ack=ack;this.received=received;this.began=began;
        }
    }
    private final Clock clock;
    private final Map<DhtId,Pending> entries=new LinkedHashMap<>();
    RosterAckQueue(Clock clock){this.clock=clock;}
    boolean offer(byte[] peer,byte[] session,long generation,ManagementPageAck ack,long received){return offer(peer,session,generation,ack,received,received);}
    boolean offer(byte[] peer,byte[] session,long generation,ManagementPageAck ack,long received,long began){
        var key=new DhtId(peer);var old=entries.get(key);
        if(old==null){if(entries.size()>=32)return false;entries.put(key,new Pending(session,generation,ack,received,began));return true;}
        if(old.generation!=generation||!Crypto.equal(old.session,session)||!Crypto.equal(old.ack.operationId(),ack.operationId())
                ||!Crypto.equal(old.ack.objectDigest(),ack.objectDigest()))return false;
        var indices=new TreeSet<Integer>();for(int i:old.ack.pageIndices())indices.add(i);for(int i:ack.pageIndices())indices.add(i);
        if(indices.size()>4)return false;
        old.ack=new ManagementPageAck(ack.group(),ack.operationId(),ack.objectDigest(),indices.stream().mapToInt(Integer::intValue).toArray(),old.ack.complete()||ack.complete());return true;
    }
    void poll(Current current,Send send){
        long now=clock.millis();var iterator=entries.entrySet().iterator();
        while(iterator.hasNext()){
            var entry=iterator.next();var p=entry.getValue();byte[] peer=entry.getKey().bytes();
            boolean discard=now<p.received||now-p.received>=30000||now-p.began>=240000||!current.test(peer,p.session,p.generation);
            if(discard||send.send(peer,p.session,p.ack)){Crypto.wipe(p.session);iterator.remove();}
        }
    }
    int size(){return entries.size();}
    public void close(){for(var pending:entries.values())Crypto.wipe(pending.session);entries.clear();}
}
