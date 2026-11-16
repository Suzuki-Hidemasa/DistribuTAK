// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 管理ページと DHT Transfer が共有する受信組立の予約。速度の予算は持たない（04 §4.5）。
 * <p>
 * Receive-assembly reservations shared by management pages and DHT Transfer, without rate budgets (04 §4.5).
 */
public final class TransferResources {
    public static final int MAX_ACTIVE=2;
    public static final long MAX_BYTES=8L*1024*1024;
    private final Map<DhtId,Lease> leases=new HashMap<>();
    private long reserved;
    /**
     * 予約の所有者だけが解放する。close を繰り返しても容量を二重に引かない。
     * <p>
     * Released only by its owner; repeated close calls never subtract capacity twice.
     */
    public static final class Lease implements AutoCloseable {
        private final TransferResources owner;private final DhtId peer;private final long bytes;
        private Lease(TransferResources owner,DhtId peer,long bytes){this.owner=owner;this.peer=peer;this.bytes=bytes;}
        @Override public void close(){owner.release(this);}
        @Override public String toString(){return "Transfer reservation";}
    }
    public synchronized Lease acquire(DhtId peer,long bytes){
        Objects.requireNonNull(peer);
        if(bytes<1||bytes>MAX_BYTES-reserved||leases.size()>=MAX_ACTIVE||leases.containsKey(peer))return null;
        var lease=new Lease(this,peer,bytes);leases.put(peer,lease);reserved+=bytes;return lease;
    }
    private synchronized void release(Lease lease){
        if(leases.remove(lease.peer,lease))reserved-=lease.bytes;
    }
    public synchronized int active(){return leases.size();}
    public synchronized long reservedBytes(){return reserved;}
    @Override public String toString(){return "Transfer resources";}
}
