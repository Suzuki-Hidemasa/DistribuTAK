// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncIntervalTest {
    private static final long INTERVAL=10_000_000_000L;
    private static byte[] xml(String uid,int value){return ("<event uid=\""+uid+"\" stale=\""+Instant.ofEpochMilli(CotRecordTest.NOW+60000)+"\"><detail><value n=\""+value+"\"/></detail></event>").getBytes(StandardCharsets.UTF_8);}
    private static void send(CotSyncTest.Mesh mesh,CotSyncTest.Node node,String uid,int value){
        assertTrue(node.sync.publish(uid,xml(uid,value),SyncState.Origin.LOCAL_CREATED));node.sync.flush();node.sync.poll();mesh.drain();
        for(var peer:mesh.nodes.values())peer.sync.flush();mesh.drain();
    }
    @Test void tenSecondsSuppressesIntermediateVersionsAndSendsLatestOnceAtBoundary(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            send(mesh,a,"own",0);assertEquals(1,mesh.recordsFrom(1));
            mesh.step(1000);send(mesh,a,"own",1);mesh.step(1);send(mesh,a,"own",2);assertEquals(1,mesh.recordsFrom(1));
            mesh.step(8998);assertEquals(1,mesh.recordsFrom(1));mesh.step(1);b.sync.flush();mesh.drain();
            assertEquals(2,mesh.recordsFrom(1));assertArrayEquals(xml("own",2),b.saved.get("own").xml());
            mesh.step(250);assertEquals(2,mesh.recordsFrom(1));
        }
    }
    @Test void differentUidsDoNotWaitForEachOther(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);mesh.node(2);mesh.connect(1,2);mesh.settle();
            send(mesh,a,"one",0);mesh.step(1000);send(mesh,a,"one",1);send(mesh,a,"two",2);
            assertEquals(2,mesh.recordsFrom(1));assertEquals("two",SyncWire.decodeRecord(SyncWire.parse(mesh.sent.stream().filter(p->p.from()==1&&SyncWire.parse(p.wire()).hasRecord()).reduce((x,y)->y).orElseThrow().wire())).uid());
        }
    }
    @Test void deletionBypassesWaitAndStartsNextNormalUpdateInterval(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            send(mesh,a,"own",0);mesh.step(1000);send(mesh,a,"own",1);
            assertTrue(a.sync.remove("own"));a.sync.flush();a.sync.poll();mesh.drain();b.sync.flush();mesh.drain();
            assertTrue(b.saved.get("own").deleted());
            long sent=mesh.recordsFrom(1);mesh.step(1000);send(mesh,a,"own",2);assertEquals(sent,mesh.recordsFrom(1));
            mesh.step(8999);assertEquals(sent,mesh.recordsFrom(1));mesh.step(1);assertEquals(sent+1,mesh.recordsFrom(1));
            b.sync.flush();mesh.drain();assertFalse(b.saved.get("own").deleted());
        }
    }
    @Test void blockedNormalTaskNeverEmitsIntermediateBodyDuringInterval(){
        var nanos=new java.util.concurrent.atomic.AtomicLong();var ready=new java.util.concurrent.atomic.AtomicBoolean();
        var emitted=new java.util.ArrayList<CotRecord>();
        try(var sync=new CotSync(CotRecordTest.id(1),new SyncState(new byte[32],CotRecordTest.id(1)),java.time.Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW),java.time.ZoneOffset.UTC),nanos::get,state->{},(peer,session,wire)->{
            if(!ready.get())return false;var envelope=SyncWire.parse(wire);if(envelope.hasRecord())emitted.add(SyncWire.decodeRecord(envelope));return true;
        },record->{},new java.security.SecureRandom(),INTERVAL)){
            sync.connected(CotRecordTest.id(2),SyncFragmentsTest.token(18));
            assertTrue(sync.publish("own",xml("own",0),SyncState.Origin.LOCAL_CREATED));sync.flush();sync.poll();
            nanos.set(1_000_000_000L);assertTrue(sync.publish("own",xml("own",1),SyncState.Origin.LOCAL_CREATED));sync.flush();
            ready.set(true);nanos.set(2_000_000_000L);sync.poll();assertTrue(emitted.isEmpty());
            nanos.set(INTERVAL);sync.poll();assertEquals(1,emitted.size());assertArrayEquals(xml("own",1),emitted.get(0).xml());
        }
    }
    @Test void retransmissionOfSameTaskKeepsOneSecondRuleInsideNormalUpdateWait(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);mesh.node(2);mesh.connect(1,2);mesh.settle();
            mesh.drop=p->p.from()==2&&SyncWire.parse(p.wire()).hasAck();
            send(mesh,a,"own",0);assertEquals(1,mesh.recordsFrom(1));
            assertTrue(a.sync.publish("own",xml("own",1),SyncState.Origin.LOCAL_CREATED));a.sync.flush();
            mesh.step(1000);assertEquals(2,mesh.recordsFrom(1));assertEquals(1,a.sync.statistics().retries());
            for(var packet:mesh.sent)if(packet.from()==1&&SyncWire.parse(packet.wire()).hasRecord())assertArrayEquals(xml("own",0),SyncWire.decodeRecord(SyncWire.parse(packet.wire())).xml());
        }
    }
    @Test void catchupToNewPeerStillRunsDuringLocalNormalUpdateWait(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);mesh.node(2);mesh.connect(1,2);mesh.settle();
            send(mesh,a,"own",0);mesh.step(1000);send(mesh,a,"own",1);
            var c=mesh.node(3);mesh.connect(1,3);mesh.step(250);c.sync.flush();mesh.drain();
            assertNotNull(c.saved.get("own"));assertArrayEquals(xml("own",1),c.saved.get("own").xml());
        }
    }
    @Test void receivedRecordRelayDoesNotWaitBehindDeferredLocalUid(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);var b=mesh.node(2,INTERVAL);var c=mesh.node(3);mesh.connect(1,2);mesh.connect(2,3);mesh.settle();
            send(mesh,b,"local",0);mesh.step(1000);send(mesh,b,"local",1);send(mesh,a,"remote",0);
            b.sync.poll();mesh.drain();c.sync.flush();mesh.drain();
            assertNotNull(c.saved.get("remote"));assertArrayEquals(xml("remote",0),c.saved.get("remote").xml());
            assertArrayEquals(xml("local",0),c.saved.get("local").xml());
        }
    }
    @Test void externalObservationStopsDeferredOwnUpdate(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1,INTERVAL);mesh.node(2);mesh.connect(1,2);mesh.settle();
            send(mesh,a,"own",0);mesh.step(1000);send(mesh,a,"own",1);a.sync.external("own");a.sync.flush();
            mesh.step(10000);assertEquals(1,mesh.recordsFrom(1));
        }
    }
}
