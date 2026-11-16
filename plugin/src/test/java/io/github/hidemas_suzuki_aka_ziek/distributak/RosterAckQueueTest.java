// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import static org.junit.Assert.*;

public class RosterAckQueueTest {
    final AtomicLong time=new AtomicLong();
    final Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(time.get());}};
    ManagementPageAck ack(int index,boolean complete){return new ManagementPageAck(new byte[32],new byte[16],new byte[32],new int[]{index},complete);}
    @Test public void holdsAtMostThirtyTwoPeersAndFourIndicesWithoutExtendingDeadline(){
        var queue=new RosterAckQueue(clock);
        for(int n=0;n<32;n++)assertTrue(queue.offer(StoredUpdatesTest.key(n),new byte[16],0,ack(0,false),0));
        assertFalse(queue.offer(StoredUpdatesTest.key(40),new byte[16],0,ack(0,false),0));
        for(int i=1;i<4;i++)assertTrue(queue.offer(StoredUpdatesTest.key(0),new byte[16],0,ack(i,false),0));
        assertFalse(queue.offer(StoredUpdatesTest.key(0),new byte[16],0,ack(4,false),0));
        time.set(29999);assertTrue(queue.offer(StoredUpdatesTest.key(0),new byte[16],0,ack(3,true),29999));
        time.set(30000);queue.poll((p,s,g)->true,(p,s,a)->{fail();return true;});assertEquals(0,queue.size());
    }
    @Test public void retriesOnlyCurrentBindingAndRemovesAfterSendOrClose(){
        var queue=new RosterAckQueue(clock);queue.offer(new byte[32],new byte[16],0,ack(0,true),0);
        queue.poll((p,s,g)->true,(p,s,a)->false);assertEquals(1,queue.size());
        queue.poll((p,s,g)->false,(p,s,a)->{fail();return true;});assertEquals(0,queue.size());
        queue.offer(new byte[32],new byte[16],0,ack(0,true),0);
        queue.poll((p,s,g)->true,(p,s,a)->true);assertEquals(0,queue.size());
        queue.offer(new byte[32],new byte[16],0,ack(0,true),0);queue.close();assertEquals(0,queue.size());
    }
    @Test public void totalAssemblyDeadlineAlsoBoundsLateQueuedAck(){
        var queue=new RosterAckQueue(clock);time.set(239999);
        queue.offer(new byte[32],new byte[16],0,ack(0,true),239999,0);time.set(240000);
        queue.poll((p,s,g)->true,(p,s,a)->{fail();return true;});assertEquals(0,queue.size());
    }

}
