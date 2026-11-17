// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.*;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtDispatcherTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.GROUP;
import static org.junit.jupiter.api.Assertions.*;

class ManagedDhtRevisionTest {
    static final class Incoming {
        final ManagedDhtTransportTest.Pair p=new ManagedDhtTransportTest.Pair();
        final List<ManagedDhtRecord> values=new ArrayList<>();
        final byte[] data,id,digest;final int count;
        Incoming(int subjects){
            var record=p.left.rev(1,subjects);data=record.encode();digest=DhtTransfers.digestOf(data);
            assertTrue(p.a.dispatcher.findManagedFrom(p.b.contact(),record.key(),values::add));
            id=p.net.queue.remove().message().requestId();p.net.queue.clear();count=(data.length+DhtWire.PIECE_BYTES-1)/DhtWire.PIECE_BYTES;
        }
        void piece(int index){piece(index,data,digest);}
        void piece(int index,byte[] body,byte[] hash){
            int n=(body.length+DhtWire.PIECE_BYTES-1)/DhtWire.PIECE_BYTES;
            byte[] chunk=Arrays.copyOfRange(body,index*DhtWire.PIECE_BYTES,Math.min(body.length,(index+1)*DhtWire.PIECE_BYTES));
            p.a.dispatcher.receive(p.b.id.bytes(),SESSION,DhtWire.management(DhtWire.transfer(GROUP,DhtWire.TransferKind.VALUE,id,hash,body.length,index,n,chunk)));
        }
        void failedOnce(){assertEquals(1,values.size());assertNull(values.get(0));assertEquals(0,p.a.dispatcher.pendingCount());assertTrue(p.left.delivered.isEmpty());}
    }
    @Test void progressTimeoutEndsTheRequestAndCannotRestartTheSameId(){
        var in=new Incoming(100);in.piece(0);in.p.net.advance(30*SECOND);in.failedOnce();
        for(int i=0;i<in.count;i++)in.piece(i);
        in.p.net.advance(300*SECOND);in.failedOnce();
    }
    @Test void expiredProgressIsRejectedEvenBeforePoll(){
        var in=new Incoming(100);in.piece(0);in.p.net.nanos.addAndGet(30*SECOND);
        for(int i=0;i<in.count;i++)in.piece(i);
        in.failedOnce();
    }
    @Test void duplicatePiecesDoNotExtendTheProgressDeadline(){
        var in=new Incoming(100);in.piece(0);in.p.net.advance(29*SECOND);in.piece(0);
        in.p.net.advance(SECOND);in.failedOnce();
    }
    @Test void progressCannotMoveTheOriginalTotalDeadline(){
        var in=new Incoming(400);assertTrue(in.count>9);in.piece(0);
        for(int i=1;i<=8;i++){in.p.net.advance(29*SECOND);in.piece(i);}
        assertTrue(in.values.isEmpty());in.p.net.advance(8*SECOND);in.failedOnce();
        for(int i=0;i<in.count;i++)in.piece(i);in.failedOnce();
    }
    @Test void aRejectedFirstReservationKeepsTheRpcDeadline()throws Exception{
        var in=new Incoming(100);var resources=(TransferResources)field(in.p.a.dispatcher,"transferResources");
        try(var lease=resources.acquire(in.p.b.id,1)){
            assertNotNull(lease);in.piece(0);assertEquals(0,managed(in.p).activeIn());
            in.p.net.advance(DhtLimits.RPC_NANOS);in.failedOnce();
        }
        for(int i=0;i<in.count;i++)in.piece(i);in.failedOnce();
    }
    @Test void aRateLimitedFirstPieceKeepsTheRpcDeadline()throws Exception{
        var in=new Incoming(100);byte[] ack=DhtWire.management(DhtWire.transferAck(GROUP,new byte[16],new byte[32],1,new byte[]{1}));
        for(int i=0;i<400;i++)in.p.a.dispatcher.receive(in.p.b.id.bytes(),SESSION,ack);
        in.piece(0);assertEquals(0,managed(in.p).activeIn());assertEquals(1,managed(in.p).rateLimited());
        in.p.net.advance(DhtLimits.RPC_NANOS);in.failedOnce();
    }
    @Test void corruptionEndsTheRequestImmediatelyAndExactlyOnce(){
        var in=new Incoming(100);byte[] bad=in.data.clone();bad[0]^=1;
        for(int i=0;i<in.count;i++)in.piece(i,bad,in.digest);
        in.failedOnce();in.p.net.advance(31*SECOND);
        for(int i=0;i<in.count;i++)in.piece(i);in.failedOnce();
    }
    @Test void structurallyRejectedWholeRecordEndsTheRequestImmediately(){
        var in=new Incoming(100);byte[] bad=new byte[]{0};in.piece(0,bad,DhtTransfers.digestOf(bad));in.failedOnce();
    }
    @Test void aWrongTargetWholeRecordEndsTheRequestImmediately(){
        var in=new Incoming(100);var body=ManagedDhtRecordTest.revocations(1,ManagedDhtRecordTest.NOW,0);
        in.p.left.bodies.add(body);var wrong=in.p.left.announcement(body,2,8).encode();
        for(int i=0;i<(wrong.length+DhtWire.PIECE_BYTES-1)/DhtWire.PIECE_BYTES;i++)in.piece(i,wrong,DhtTransfers.digestOf(wrong));
        in.failedOnce();
    }
    @Test void mixedSchemasShareThePeerBurstAndRefill()throws Exception{
        var p=new ManagedDhtTransportTest.Pair();long before=processed(p);
        ackBoth(p,p.b.id,400);assertEquals(400,processed(p)-before);assertEquals(400,limited(p));
        p.net.nanos.addAndGet(SECOND);before=processed(p);ackBoth(p,p.b.id,200);
        assertEquals(200,processed(p)-before);assertEquals(600,limited(p));
    }
    @Test void mixedSchemasShareTheGlobalBurstAndRefill()throws Exception{
        var p=new ManagedDhtTransportTest.Pair();var c=new Rig(p.net,DhtIdTest.id(81),new Random(3),GROUP);
        var d=new Rig(p.net,DhtIdTest.id(82),new Random(4),GROUP);p.net.rigs.put(c.id,c);p.net.rigs.put(d.id,d);
        long before=processed(p);ackBoth(p,p.b.id,200);ackBoth(p,c.id,200);ackBoth(p,d.id,200);
        assertEquals(800,processed(p)-before);assertEquals(400,limited(p));
        p.net.nanos.addAndGet(SECOND);before=processed(p);
        ackBoth(p,p.b.id,100);ackBoth(p,c.id,100);ackBoth(p,d.id,100);
        assertEquals(400,processed(p)-before);assertEquals(600,limited(p));
    }
    static void ackBoth(ManagedDhtTransportTest.Pair p,DhtId peer,int count){
        byte[] legacy=DhtWire.transferAck(GROUP,new byte[16],new byte[32],1,new byte[]{1}),managed=DhtWire.management(legacy);
        for(int i=0;i<count;i++){p.a.dispatcher.receive(peer.bytes(),SESSION,legacy);p.a.dispatcher.receive(peer.bytes(),SESSION,managed);}
    }
    static Object field(Object target,String name)throws Exception{var f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    static DhtTransfers managed(ManagedDhtTransportTest.Pair p)throws Exception{return (DhtTransfers)field(p.a.dispatcher,"managedTransfers");}
    static long processed(ManagedDhtTransportTest.Pair p)throws Exception{return p.a.dispatcher.transfers().mismatched()+managed(p).mismatched();}
    static long limited(ManagedDhtTransportTest.Pair p)throws Exception{return p.a.dispatcher.transfers().rateLimited()+managed(p).rateLimited();}
}
