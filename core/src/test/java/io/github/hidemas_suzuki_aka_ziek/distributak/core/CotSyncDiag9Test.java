// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.security.SecureRandom;
import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncDiag9Test {
    static final class Catchup implements AutoCloseable {
        final AtomicLong nanos=new AtomicLong();final AtomicBoolean ready=new AtomicBoolean();
        final byte[] local,peer,session=SyncFragmentsTest.token(17);
        final List<byte[]> inventories=new ArrayList<>(),acks=new ArrayList<>();final List<CotRecord> emitted=new ArrayList<>();
        final SyncFragments receiver=new SyncFragments(nanos::get);final CotSync sync;final byte[] old;
        Catchup(boolean serve,boolean received)throws Exception{
            local=CotRecordTest.id(serve?1:2);peer=CotRecordTest.id(serve?2:1);
            Clock wall=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(CotRecordTest.NOW+nanos.get()/1_000_000);}};
            sync=new CotSync(local,new SyncState(new byte[32],local),wall,nanos::get,s->{},(p,s,w)->{
                if(SyncWire.parse(w).hasInventory()){inventories.add(w.clone());return true;}
                if(!ready.get())return false;
                try(var r=receiver.accept(local,session,w)){
                    if(r!=null&&r.message()!=null){var e=SyncWire.parse(r.message());if(e.hasRecord()||e.hasTombstone()){var item=SyncWire.decodeRecord(e);emitted.add(item);acks.add(SyncWire.ack(item));}}
                }
                return true;
            },r->{},new SecureRandom(),CotSyncDiag8Test.INTERVAL);
            old=xml("own",60000,10);
            if(received){sync.connected(peer,session);receive(old);sync.disconnected(peer);inventories.clear();}
            else{assertTrue(sync.publish("own",old,SyncState.Origin.LOCAL_CREATED));sync.flush();}
            sync.connected(peer,session);
            if(serve){var inv=SyncWire.parse(inventories.get(0)).getInventory();var request=SyncSchema.SyncRequest.newBuilder().setSnapshotId(inv.getSnapshotId()).setPage(inv.getPage()).addAllWanted(inv.getEntriesList());sync.receive(peer,session,SyncWire.envelope().setRequest(request).build().toByteArray());}
            else{var inv=SyncSchema.SyncInventory.newBuilder().setSnapshotId(ByteString.copyFrom(SyncFragmentsTest.token(23))).setPage(0).setLast(true);sync.receive(peer,session,SyncWire.envelope().setInventory(inv).build().toByteArray());}
        }
        byte[] xml(String uid,long stale,int size){return CotSyncDiag8Test.xml(uid,CotRecordTest.NOW+stale,size);}
        void receive(byte[] body){sync.receive(peer,session,SyncWire.encode(CotRecord.record("own",CotRecordTest.NOW+nanos.get()/1_000_000,peer,CotXml.inspect(body).stale(),body,1)));sync.flush();}
        void finish(){for(int i=0;i<16;i++){nanos.addAndGet(250_000_000);for(byte[] ack:new ArrayList<>(acks)){acks.remove(ack);sync.receive(peer,session,ack);}sync.poll();}}
        public void close(){sync.close();receiver.close();}
    }
    void catchup(boolean serve,boolean capacity,boolean received)throws Exception{
        try(var c=new Catchup(serve,received)){
            if(capacity)for(int i=0;i<16;i++){String uid="filler-"+i;assertTrue(c.sync.publish(uid,c.xml(uid,60000,63000),SyncState.Origin.LOCAL_CREATED));c.sync.flush();c.sync.poll();}
            c.nanos.set(1_000_000_000L);byte[] latest=c.xml("own",capacity?60000:5000,capacity?63000:20);
            if(received)c.receive(latest);else{assertTrue(c.sync.publish("own",latest,SyncState.Origin.LOCAL_CREATED));c.sync.flush();}
            c.sync.poll();if(capacity)assertTrue(c.sync.statistics().pendingBytes()>1_000_000);
            c.nanos.set(CotSyncDiag8Test.INTERVAL);c.ready.set(true);c.sync.poll();c.finish();
            assertEquals(0,c.emitted.stream().filter(r->r.uid().equals("own")&&Arrays.equals(c.old,r.xml())).count());
            if(capacity)assertEquals(1,c.emitted.stream().filter(r->r.uid().equals("own")&&Arrays.equals(latest,r.xml())).count());
            else assertTrue(c.emitted.stream().noneMatch(r->r.uid().equals("own")));
        }
    }
    static final class Three implements AutoCloseable {
        static final int A=3,SELF=2,B=1;
        record Packet(int from,int to,byte[] session,byte[] wire){}
        final AtomicLong nanos=new AtomicLong();final Map<Integer,CotSync> nodes=new LinkedHashMap<>();
        final Map<Integer,SyncState> saved=new HashMap<>();final ArrayDeque<Packet> packets=new ArrayDeque<>();
        final List<CotRecord> acceptedByB=new ArrayList<>();boolean release;long oldSends,capacityFreedAt=-1,latestAt=-1;
        final byte[] old=CotSyncDiag8Test.xml("own",CotRecordTest.NOW+60000,10),latest=CotSyncDiag8Test.xml("own",CotRecordTest.NOW+60000,63000);
        Three(){
            Clock wall=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(CotRecordTest.NOW+nanos.get()/1_000_000);}};
            for(int id:new int[]{A,SELF,B}){
                saved.put(id,new SyncState(new byte[32],CotRecordTest.id(id)));
                nodes.put(id,new CotSync(CotRecordTest.id(id),saved.get(id),wall,nanos::get,state->{
                    saved.put(id,state.copy());var item=state.get("own");if(id==B&&latestAt<0&&item!=null&&Arrays.equals(latest,item.xml()))latestAt=nanos.get();
                },(peer,session,wire)->{
                    int to=peer[0]&255;var envelope=SyncWire.parse(wire);
                    // BのInventoryはSELFへ届くが、SELFのInventoryはBへ届けずserveを使わせない。
                    if(id==SELF&&to==B&&envelope.hasInventory())return false;
                    if(id==SELF&&!release&&(envelope.hasRecord()||envelope.hasTombstone()||envelope.hasFragment()))return false;
                    if(id==SELF&&to==B&&envelope.hasRecord()&&Arrays.equals(old,SyncWire.decodeRecord(envelope).xml()))oldSends++;
                    packets.addLast(new Packet(id,to,session.clone(),wire.clone()));return true;
                },item->{if(id==B&&item.uid().equals("own"))acceptedByB.add(item);},new SecureRandom(),id==SELF?CotSyncDiag8Test.INTERVAL:0));
            }
        }
        void connect(int a,int b){byte[] session=SyncFragmentsTest.token(a*16+b);nodes.get(a).connected(CotRecordTest.id(b),session);nodes.get(b).connected(CotRecordTest.id(a),session);}
        void drain(){
            int count=0;while(!packets.isEmpty()){
                assertTrue(++count<100000);var packet=packets.removeFirst();var target=nodes.get(packet.to);int before=target.statistics().pendingBytes();
                target.receive(CotRecordTest.id(packet.from),packet.session,packet.wire);
                if(packet.to==SELF&&SyncWire.parse(packet.wire).hasAck()&&target.statistics().pendingBytes()<before&&capacityFreedAt<0)capacityFreedAt=nanos.get();
            }
        }
        void settle(){for(int i=0;i<16;i++){drain();for(var node:nodes.values())node.flush();for(var node:nodes.values())node.poll();}drain();}
        Object peerB(){return ((Map<?,?>)SyncOffloadTest.field(nodes.get(SELF),"peers")).values().stream().filter(p->((byte[])SyncOffloadTest.field(p,"id"))[0]==B).findFirst().orElseThrow();}
        public void close(){for(var node:nodes.values())node.close();packets.clear();}
    }
    @Test void receivedMissingCapacityThreePeersDeliversLatestOnAckAtCapacityReleaseWithoutAnotherPoll(){
        try(var t=new Three()){
            var source=t.nodes.get(Three.A);var self=t.nodes.get(Three.SELF);var b=t.nodes.get(Three.B);
            assertTrue(source.publish("own",t.old,SyncState.Origin.LOCAL_CREATED));source.flush();t.connect(Three.A,Three.SELF);t.settle();
            assertEquals(SyncState.Origin.DISTRIBUTAK,t.saved.get(Three.SELF).origin("own"));
            t.connect(Three.SELF,Three.B);t.settle();var peer=t.peerB();Object oldTask=((Map<?,?>)SyncOffloadTest.field(peer,"records")).get("own");assertNotNull(oldTask);
            assertEquals(false,SyncOffloadTest.field(oldTask,"normalUpdate"));assertEquals(false,SyncOffloadTest.field(oldTask,"sent"));assertEquals("own",SyncOffloadTest.field(peer,"missingCursor"));assertTrue(((Map<?,?>)SyncOffloadTest.field(peer,"serves")).isEmpty());
            for(int i=0;i<16;i++){String uid="filler-"+i;assertTrue(self.publish(uid,CotSyncDiag8Test.xml(uid,CotRecordTest.NOW+60000,63000),SyncState.Origin.LOCAL_CREATED));self.flush();self.poll();}
            assertTrue(self.statistics().pendingBytes()>1_000_000);t.nanos.set(1_000_000_000L);
            assertTrue(source.publish("own",t.latest,SyncState.Origin.LOCAL_CREATED));source.flush();source.poll();t.drain();self.flush();self.poll();
            assertArrayEquals(t.latest,t.saved.get(Three.SELF).get("own").xml());assertEquals(SyncState.Origin.DISTRIBUTAK,t.saved.get(Three.SELF).origin("own"));assertTrue(((Set<?>)SyncOffloadTest.field(peer,"deferred")).contains("own"));assertTrue(((Map<?,?>)SyncOffloadTest.field(peer,"serves")).isEmpty());assertNull(t.saved.get(Three.B).get("own"));assertTrue(self.statistics().pendingBytes()>1_000_000);
            // 最新受信1秒、容量の開放2秒。開放後に時計を進めず、追加pollもせずACK処理だけで届く。
            t.nanos.set(2_000_000_000L);t.release=true;self.poll();assertEquals(-1,t.latestAt);t.drain();
            assertEquals(0,t.oldSends);assertEquals(2_000_000_000L,t.capacityFreedAt);assertEquals(t.capacityFreedAt,t.latestAt);assertEquals(1,t.acceptedByB.size());assertArrayEquals(t.latest,t.saved.get(Three.B).get("own").xml());assertArrayEquals(CotRecordTest.id(Three.A),t.acceptedByB.get(0).author());assertEquals(SyncState.Origin.DISTRIBUTAK,b.snapshot().origin("own"));
        }
    }
    @Test void serveExpiredLatestNeverSendsOld()throws Exception{catchup(true,false,false);}
    @Test void missingExpiredLatestNeverSendsOld()throws Exception{catchup(false,false,false);}
    @Test void serveCapacityNeverSendsOldAndLatestArrivesOnceWhenRoomReturns()throws Exception{catchup(true,true,false);}
    @Test void missingCapacityNeverSendsOldAndLatestArrivesOnceWhenRoomReturns()throws Exception{catchup(false,true,false);}
    @Test void receivedRecordCatchupAlsoNeverFallsBackToOld()throws Exception{catchup(true,false,true);}
}
