// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.*;

/**
 * 試験の中間状態を観測する間だけ FIRST を保留する。製品の開始操作は変えない。
 * <p>
 * Holds FIRST only while tests observe intermediate state, leaving product start operations unchanged.
 */
final class FirstPacketGate implements UdpEndpoint.DatagramIo {
    private record Held(byte[] wire,InetSocketAddress target){}
    private final UdpEndpoint.DatagramIo original;
    private final List<Held> pending=new ArrayList<>();
    private boolean released;
    FirstPacketGate(UdpEndpoint.DatagramIo original){this.original=original;}
    static FirstPacketGate install(UdpEndpoint endpoint)throws Exception{
        var field=UdpEndpoint.class.getDeclaredField("io");field.setAccessible(true);
        var gate=new FirstPacketGate((UdpEndpoint.DatagramIo)field.get(endpoint));field.set(endpoint,gate);return gate;
    }
    public UdpEndpoint.Datagram receive()throws IOException{return original.receive();}
    public void send(byte[] wire,InetSocketAddress target)throws IOException{
        boolean first=false;try{first=SessionPacket.decode(wire).kind()==SessionPacket.FIRST;}catch(RuntimeException ignored){}
        synchronized(this){if(first&&!released){pending.add(new Held(wire.clone(),target));return;}}
        original.send(wire,target);
    }
    void release()throws IOException{
        final List<Held> ready;
        synchronized(this){if(released)return;released=true;ready=new ArrayList<>(pending);pending.clear();}
        try{for(var packet:ready)original.send(packet.wire,packet.target);}
        finally{for(var packet:ready)Crypto.wipe(packet.wire);}
    }
    public void close(){synchronized(this){released=true;for(var packet:pending)Crypto.wipe(packet.wire);pending.clear();}original.close();}
}
