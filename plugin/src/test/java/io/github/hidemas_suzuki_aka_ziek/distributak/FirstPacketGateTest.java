// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.net.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class FirstPacketGateTest {
    @Test public void firstIsHeldUntilReleaseAndLaterSendsPassThrough()throws Exception{
        var delivered=new ArrayList<byte[]>();
        var original=new UdpEndpoint.DatagramIo(){
            public UdpEndpoint.Datagram receive(){return null;}
            public void send(byte[] bytes,InetSocketAddress target){delivered.add(bytes.clone());}
            public void close(){}
        };
        var gate=new FirstPacketGate(original);byte[] wire=new SessionPacket(SessionPacket.FIRST,new byte[16],1,0,new byte[108]).encode();
        gate.send(wire,new InetSocketAddress("192.0.2.1",54321));assertTrue(delivered.isEmpty());
        gate.release();assertEquals(1,delivered.size());assertArrayEquals(wire,delivered.get(0));
        gate.release();assertEquals(1,delivered.size());gate.send(wire,new InetSocketAddress("192.0.2.1",54321));assertEquals(2,delivered.size());
    }
}
