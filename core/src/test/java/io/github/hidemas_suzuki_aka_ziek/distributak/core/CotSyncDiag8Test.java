// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncDiag8Test {
    static final long INTERVAL=10_000_000_000L;
    static byte[] xml(String uid,long stale,int size){return ("<event uid=\""+uid+"\" stale=\""+Instant.ofEpochMilli(stale)+"\"><detail>"+"x".repeat(size)+"</detail></event>").getBytes(StandardCharsets.UTF_8);}
    static final class Node implements AutoCloseable {
        final AtomicLong time=new AtomicLong();final AtomicBoolean ready=new AtomicBoolean();final List<CotRecord> emitted=new ArrayList<>();
        SyncState saved=new SyncState(new byte[32],CotRecordTest.id(1));final CotSync sync;long deletedEmitted;
        Node(){
            Clock wall=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(CotRecordTest.NOW+time.get()/1_000_000);}};
            sync=new CotSync(CotRecordTest.id(1),saved,wall,time::get,state->saved=state.copy(),(peer,session,wire)->{
                if(!ready.get())return false;var e=SyncWire.parse(wire);if(e.hasRecord())emitted.add(SyncWire.decodeRecord(e));if(e.hasTombstone())deletedEmitted++;return true;
            },record->{},new java.security.SecureRandom(),INTERVAL);
            sync.connected(CotRecordTest.id(2),SyncFragmentsTest.token(18));
        }
        void publish(String uid,byte[] xml){assertTrue(sync.publish(uid,xml,SyncState.Origin.LOCAL_CREATED));sync.flush();sync.poll();}
        public void close(){sync.close();}
    }
    @Test void expiredLatestAtBoundaryNeverEmitsOldAndClearsEveryDeferredUid()throws Exception {
        try(var n=new Node()){
            byte[] old=xml("own",CotRecordTest.NOW+60_000,10);n.publish("own",old);
            n.time.set(1_000_000_000L);n.publish("own",xml("own",CotRecordTest.NOW+5000,20));
            n.ready.set(true);n.time.set(INTERVAL);n.sync.poll();assertTrue(n.emitted.isEmpty(),"expired latest must not fall back to old");
            n.time.addAndGet(250_000_000);n.sync.poll();
            assertTrue(deferred(n.sync).isEmpty());assertTrue(localDeferred(n.sync).isEmpty());assertFalse(recordTasks(n.sync).containsKey("own"));
            assertTrue(n.emitted.isEmpty());
        }
    }
    @Test void capacityBlockedReplacementAtBoundaryNeverEmitsOld()throws Exception {
        try(var n=new Node()){
            byte[] old=xml("own",CotRecordTest.NOW+60_000,10);n.publish("own",old);
            for(int i=0;i<16;i++)n.publish("filler-"+i,xml("filler-"+i,CotRecordTest.NOW+60_000,63000));
            assertTrue(n.sync.statistics().pendingBytes()>1_000_000);
            n.time.set(1_000_000_000L);n.publish("own",xml("own",CotRecordTest.NOW+60_000,63000));
            n.ready.set(true);n.time.set(INTERVAL);n.sync.poll();n.sync.poll();
            assertTrue(n.emitted.stream().noneMatch(r->r.uid().equals("own")&&Arrays.equals(old,r.xml())));
        }
    }
    @Test void localPositionUsesSameInterval(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);var b=mesh.node(2);assertTrue(a.sync.protectPosition("self"));mesh.connect(1,2);mesh.settle();
            assertTrue(a.sync.publish("self",xml("self",CotRecordTest.NOW+60_000,10),SyncState.Origin.LOCAL_POSITION));a.sync.flush();a.sync.poll();mesh.drain();b.sync.flush();mesh.drain();
            long start=mesh.nanos.get();mesh.step(1000);
            byte[] latest=xml("self",CotRecordTest.NOW+60_000,20);assertTrue(a.sync.publish("self",latest,SyncState.Origin.LOCAL_POSITION));a.sync.flush();a.sync.poll();mesh.drain();assertEquals(1,mesh.recordsFrom(1));
            mesh.nanos.set(start+INTERVAL);a.sync.poll();mesh.drain();b.sync.flush();mesh.drain();assertEquals(2,mesh.recordsFrom(1));assertArrayEquals(latest,b.saved.get("self").xml());
        }
    }
    @Test void sameInstanceReconnectKeepsIntervalButRecreationAndRestartForgetIt()throws Exception {
        try(var n=new Node()){
            n.publish("own",xml("own",CotRecordTest.NOW+60000,10));n.time.set(1_000_000_000L);n.publish("own",xml("own",CotRecordTest.NOW+60000,20));
            var last=CotSync.class.getDeclaredField("lastLocal");last.setAccessible(true);Map<?,?> before=new HashMap<>((Map<?,?>)last.get(n.sync));
            n.sync.disconnected(CotRecordTest.id(2));n.sync.connected(CotRecordTest.id(2),SyncFragmentsTest.token(19));assertEquals(before,last.get(n.sync));assertTrue(localDeferred(n.sync).contains("own"));
            SyncState restored=SyncState.decode(n.saved.encode(),new byte[32],CotRecordTest.id(1));
            var recreatedSent=new ArrayList<CotRecord>();
            try(var recreated=new CotSync(CotRecordTest.id(1),restored,Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW+1000),ZoneOffset.UTC),n.time::get,state->{},(peer,session,wire)->{var e=SyncWire.parse(wire);if(e.hasRecord())recreatedSent.add(SyncWire.decodeRecord(e));return true;},record->{},new java.security.SecureRandom(),INTERVAL)){
                assertTrue(((Map<?,?>)last.get(recreated)).isEmpty());assertTrue(localDeferred(recreated).isEmpty());
                recreated.connected(CotRecordTest.id(2),SyncFragmentsTest.token(20));byte[] fresh=xml("new-after-restart",CotRecordTest.NOW+60000,30);
                assertTrue(recreated.publish("new-after-restart",fresh,SyncState.Origin.LOCAL_CREATED));recreated.flush();recreated.poll();assertEquals(1,recreatedSent.size());assertArrayEquals(fresh,recreatedSent.get(0).xml());
            }
        }
    }
    @Test void noPeerSaveIsCaughtUpWhenPeerAppears(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);byte[] first=xml("own",CotRecordTest.NOW+60000,10);assertTrue(a.sync.publish("own",first,SyncState.Origin.LOCAL_CREATED));a.sync.flush();
            mesh.step(1000);byte[] latest=xml("own",CotRecordTest.NOW+60000,20);assertTrue(a.sync.publish("own",latest,SyncState.Origin.LOCAL_CREATED));a.sync.flush();
            var b=mesh.node(2);mesh.connect(1,2);mesh.step(250);b.sync.flush();mesh.drain();assertArrayEquals(latest,b.saved.get("own").xml());
        }
    }
    @Test void inFlightLargeTaskMayFinishBeforeLatestAcrossBoundary(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            mesh.drop=p->p.from()==1&&SyncWire.parse(p.wire()).hasFragment();
            byte[] first=xml("own",CotRecordTest.NOW+60000,20000),latest=xml("own",CotRecordTest.NOW+60000,21000);
            assertTrue(a.sync.publish("own",first,SyncState.Origin.LOCAL_CREATED));a.sync.flush();a.sync.poll();mesh.drain();long start=mesh.nanos.get();
            mesh.step(1000);assertTrue(a.sync.publish("own",latest,SyncState.Origin.LOCAL_CREATED));a.sync.flush();
            mesh.nanos.set(start+INTERVAL);a.sync.poll();mesh.drain();assertNull(b.saved.get("own"));
            mesh.drop=p->false;mesh.step(1000);b.sync.flush();mesh.drain();a.sync.poll();mesh.drain();b.sync.flush();mesh.drain();
            assertTrue(a.sync.statistics().retries()>0);assertArrayEquals(latest,b.saved.get("own").xml());
        }
    }
    @Test void catchupPeerGetsSameLatestOneMoreTimeAfterBoundary(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);mesh.node(2);mesh.connect(1,2);mesh.settle();
            assertTrue(a.sync.publish("own",xml("own",CotRecordTest.NOW+60000,10),SyncState.Origin.LOCAL_CREATED));a.sync.flush();a.sync.poll();mesh.drain();for(var n:mesh.nodes.values())n.sync.flush();mesh.drain();long start=mesh.nanos.get();
            mesh.step(1000);byte[] latest=xml("own",CotRecordTest.NOW+60000,20);assertTrue(a.sync.publish("own",latest,SyncState.Origin.LOCAL_CREATED));a.sync.flush();
            var c=mesh.node(3);mesh.connect(1,3);mesh.step(250);c.sync.flush();mesh.drain();
            long before=mesh.sent.stream().filter(p->p.from()==1&&p.to()==3&&SyncWire.parse(p.wire()).hasRecord()).count();assertEquals(1,before);
            mesh.nanos.set(start+INTERVAL);a.sync.poll();mesh.drain();for(var n:mesh.nodes.values())n.sync.flush();mesh.drain();
            long after=mesh.sent.stream().filter(p->p.from()==1&&p.to()==3&&SyncWire.parse(p.wire()).hasRecord()).count();assertEquals(2,after);
            assertArrayEquals(latest,c.saved.get("own").xml());
            var records=mesh.sent.stream().filter(p->p.from()==1&&p.to()==3&&SyncWire.parse(p.wire()).hasRecord()).toList();assertArrayEquals(records.get(0).wire(),records.get(1).wire());
        }
    }
    @Test void unsentDeletionKeepsItsBypassWhenLaterNormalBodyIsWaiting(){
        try(var n=new Node()){
            n.publish("own",xml("own",CotRecordTest.NOW+60000,10));assertTrue(n.sync.remove("own"));n.sync.flush();n.sync.poll();
            n.time.set(1_000_000_000L);n.publish("own",xml("own",CotRecordTest.NOW+60000,20));n.ready.set(true);n.time.set(2_000_000_000L);n.sync.poll();
            assertEquals(1,n.deletedEmitted);assertTrue(n.emitted.isEmpty());
        }
    }
    @SuppressWarnings("unchecked") static Set<String> localDeferred(CotSync s)throws Exception {var f=CotSync.class.getDeclaredField("localDeferred");f.setAccessible(true);return (Set<String>)f.get(s);}
    @SuppressWarnings("unchecked") static Set<String> deferred(CotSync s)throws Exception {var f=CotSync.class.getDeclaredField("peers");f.setAccessible(true);Object peer=((Map<?,?>)f.get(s)).values().iterator().next();var d=peer.getClass().getDeclaredField("deferred");d.setAccessible(true);return (Set<String>)d.get(peer);}
    static Map<?,?> recordTasks(CotSync s)throws Exception {var f=CotSync.class.getDeclaredField("peers");f.setAccessible(true);Object peer=((Map<?,?>)f.get(s)).values().iterator().next();var r=peer.getClass().getDeclaredField("records");r.setAccessible(true);return (Map<?,?>)r.get(peer);}

}
