// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.ArrayDeque;
import java.util.Arrays;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

/**
 * UDPの借り物の配列を、上限を確かめてからworkerへ渡す。
 * <p>
 * Passes borrowed UDP arrays to the worker after checking resource limits.
 */
final class SyncInbox {
    static final int PER_PEER=80,TOTAL=256,MAX_BYTES=1024*1024;
    static final class Packet implements AutoCloseable {
        final long epoch,receivedAt;final byte[] peer,session,wire;
        Packet(long epoch,byte[] peer,byte[] session,byte[] wire,long receivedAt){this.receivedAt=receivedAt;this.epoch=epoch;this.peer=peer.clone();this.session=session.clone();this.wire=wire.clone();}
        int bytes(){return peer.length+session.length+wire.length;}
        public void close(){Crypto.wipe(peer);Crypto.wipe(session);Crypto.wipe(wire);}
    }
    private final ArrayDeque<Packet> queue=new ArrayDeque<>();
    private int bytes;
    synchronized boolean offer(long epoch,byte[] peer,byte[] session,byte[] wire){
        return offer(epoch,peer,session,wire,0);
    }
    synchronized boolean offer(long epoch,byte[] peer,byte[] session,byte[] wire,long receivedAt){
        if(peer==null||peer.length!=32||session==null||session.length!=16||wire==null)return false;
        long size=(long)peer.length+session.length+wire.length;
        if(queue.size()>=TOTAL||size>MAX_BYTES-bytes)return false;
        int count=0;for(Packet packet:queue)if(Arrays.equals(peer,packet.peer)&&++count>=PER_PEER)return false;
        Packet packet=new Packet(epoch,peer,session,wire,receivedAt);queue.add(packet);bytes+=packet.bytes();return true;
    }
    synchronized Packet take(){Packet packet=queue.poll();if(packet!=null)bytes-=packet.bytes();return packet;}
    synchronized int size(){return queue.size();}
    synchronized int bytes(){return bytes;}
    synchronized void clear(){for(Packet packet:queue)packet.close();queue.clear();bytes=0;}
}
