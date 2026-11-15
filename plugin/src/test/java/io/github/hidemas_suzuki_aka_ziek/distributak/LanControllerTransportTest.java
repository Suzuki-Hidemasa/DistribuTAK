// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import java.net.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class LanControllerTransportTest {
    static Inet4Address address(int last)throws Exception{return (Inet4Address)InetAddress.getByAddress(new byte[]{(byte)192,0,2,(byte)last});}
    @Test public void packetsAreCopiedAndOnlyTheMatchingAddressAndPortReceives()throws Exception{
        try(var a=new LanControllerHarness.MemoryIo(62001,address(1),new AtomicInteger());var b=new LanControllerHarness.MemoryIo(62002,address(2),new AtomicInteger())){
            a.send(new byte[]{9},new InetSocketAddress(address(3),62002));a.send(new byte[]{8},new InetSocketAddress(address(2),62003));
            byte[] value={1,2,3};a.send(value,new InetSocketAddress(address(2),62002));java.util.Arrays.fill(value,(byte)0);
            var received=b.receive();assertArrayEquals(new byte[]{1,2,3},received.wire());assertEquals(new InetSocketAddress(address(1),62001),received.source());
        }
    }
    @Test public void closeWakesReceiverAndRebindingCannotBeRemovedByAnOldClose()throws Exception{
        var first=new LanControllerHarness.MemoryIo(62011,address(1),new AtomicInteger());var executor=Executors.newSingleThreadExecutor();
        try{
            var blocked=executor.submit(()->{try{first.receive();return false;}catch(SocketException expected){return true;}});
            assertTrue(first.receiveEntered.await(5,TimeUnit.SECONDS));first.close();assertTrue(blocked.get(5,TimeUnit.SECONDS));
            try(var next=new LanControllerHarness.MemoryIo(62011,address(1),new AtomicInteger());var sender=new LanControllerHarness.MemoryIo(62012,address(2),new AtomicInteger())){
                first.close();sender.send(new byte[]{7},new InetSocketAddress(address(1),62011));assertArrayEquals(new byte[]{7},next.receive().wire());
            }
        }finally{first.close();executor.shutdownNow();}
    }
    @Test public void duplicateBindingIsRejectedAndClosedSendFails()throws Exception{
        var first=new LanControllerHarness.MemoryIo(62021,address(1),new AtomicInteger());
        try{assertThrows(BindException.class,()->new LanControllerHarness.MemoryIo(62021,address(2),new AtomicInteger()));}
        finally{first.close();}
        assertThrows(SocketException.class,()->first.send(new byte[]{1},new InetSocketAddress(address(2),62022)));
    }
}
