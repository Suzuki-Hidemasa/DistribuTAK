// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncTest {
    @Test void oversizedKnownXmlInSeventyTwoFragmentsIsNotSavedOrAckedButValidMaximumIs(){
        try(var mesh=new Mesh()){
            mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();byte[] session=mesh.sent.get(0).session();mesh.sent.clear();
            String prefix="<event uid=\"maximum\" stale=\""+java.time.Instant.ofEpochMilli(CotRecordTest.NOW+60000)+"\"><detail>",suffix="</detail></event>";
            byte[] xml=(prefix+"x".repeat(65536-prefix.length()-suffix.length())+suffix).getBytes(StandardCharsets.UTF_8);
            var item=CotRecord.record("maximum",CotRecordTest.NOW,CotRecordTest.id(1),CotRecordTest.NOW+60000,xml,1);
            var known=SyncWire.parse(SyncWire.encode(item));byte[] bad=known.toBuilder().setRecord(known.getRecord().toBuilder().setXmlUtf8(com.google.protobuf.ByteString.copyFrom((prefix+"x".repeat(73000-prefix.length()-suffix.length())+suffix).getBytes(StandardCharsets.UTF_8)))).build().toByteArray();
            var pieces=SyncFragments.split(bad,SyncFragmentsTest.token(20));assertEquals(72,pieces.size());
            for(byte[] frame:pieces)b.sync.receive(CotRecordTest.id(1),session,frame);mesh.step(250);
            assertNull(b.saved.get("maximum"));assertTrue(mesh.sent.stream().noneMatch(p->SyncWire.parse(p.wire()).hasAck()));
            var valid=SyncFragments.split(SyncWire.encode(item),SyncFragmentsTest.token(21));assertEquals(65,valid.size());
            for(int n=0;n<valid.size()-1;n++)b.sync.receive(CotRecordTest.id(1),session,valid.get(n));
            assertNull(b.saved.get("maximum"));assertTrue(mesh.sent.stream().noneMatch(p->SyncWire.parse(p.wire()).hasAck()));
            b.sync.receive(CotRecordTest.id(1),session,valid.get(valid.size()-1));
            assertNotNull(b.saved.get("maximum"));assertTrue(mesh.sent.stream().anyMatch(p->SyncWire.parse(p.wire()).hasAck()));
        }
    }
    @Test void externalObservationCannotRemoveReceivedRegistryButUnknownCanBecomeExternal(){
        try(var mesh=new Mesh()){
            var node=mesh.node(1);assertTrue(node.sync.registerReceivedUid("received"));node.sync.flush();
            node.sync.external("received");node.sync.external("unknown");node.sync.flush();
            assertEquals(SyncState.Origin.DISTRIBUTAK,node.saved.origin("received"));
            assertTrue(node.saved.receivedUids().contains("received"));assertTrue(node.sync.externalSnapshot().contains("unknown"));assertEquals(SyncState.Origin.UNKNOWN,node.saved.origin("unknown"));
            assertTrue(SyncState.decode(node.saved.encode(),new byte[32],CotRecordTest.id(1)).receivedUids().contains("received"));
        }
    }
    @Test void importRegistryMustBeDurableBeforeCallerCanImportAndNeverCancelsOwnPosition(){
        try(var mesh=new Mesh()) {
            var node=mesh.node(1);assertTrue(node.sync.protectPosition("self"));
            assertFalse(node.sync.registerReceivedUid("self"));assertTrue(node.sync.registerReceivedUid("fixture"));
            assertFalse(node.saved.receivedUids().contains("fixture"));node.sync.flush();
            assertTrue(node.saved.receivedUids().contains("fixture"));assertFalse(node.publish("fixture"));
        }
    }
    record Packet(int from,int to,byte[] session,byte[] wire) {
        @Override public String toString(){return "Test packet";}
    }
    static final class Mesh implements AutoCloseable {
        final AtomicLong nanos=new AtomicLong();final Map<Integer,Node> nodes=new LinkedHashMap<>();
        final Deque<Packet> packets=new ArrayDeque<>();final List<Packet> sent=new ArrayList<>();
        final Map<String,Integer> generations=new HashMap<>();
        Predicate<Packet> drop=packet->false;
        final Clock clock=new Clock(){
            public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}
            public Instant instant(){return Instant.ofEpochMilli(CotRecordTest.NOW+nanos.get()/1_000_000L);}
        };
        Node node(int id){return node(id,0);}
        Node node(int id,long minimum){var node=new Node(this,id,minimum);nodes.put(id,node);return node;}
        void connect(int a,int b){
            byte[] session=SyncFragmentsTest.token(a*16+b);
            String pair=Math.min(a,b)+":"+Math.max(a,b);int generation=generations.getOrDefault(pair,0);generations.put(pair,generation+1);session[1]=(byte)generation;
            nodes.get(a).sync.connected(CotRecordTest.id(b),session);nodes.get(b).sync.connected(CotRecordTest.id(a),session);drain();
        }
        void drain(){
            int processed=0;
            while(!packets.isEmpty()){
                assertTrue(++processed<100000,"messages must converge");var packet=packets.removeFirst();
                if(!drop.test(packet))nodes.get(packet.to).sync.receive(CotRecordTest.id(packet.from),packet.session,packet.wire);
            }
        }
        void step(long millis){nanos.addAndGet(millis*1_000_000L);for(Node node:nodes.values())node.sync.poll();drain();}
        void settle(){for(int n=0;n<16;n++)step(250);}
        long recordsFrom(int id){return sent.stream().filter(p->p.from==id&&SyncWire.parse(p.wire).hasRecord()).count();}
        public void close(){for(Node node:nodes.values())node.sync.close();packets.clear();sent.clear();}
    }
    static final class Node {
        final int id;final CotSync sync;final List<CotRecord> received=new ArrayList<>();
        SyncState saved;int saves;boolean failSave;
        Node(Mesh mesh,int id,long minimum){
            this.id=id;saved=new SyncState(new byte[32],CotRecordTest.id(id));
            sync=new CotSync(CotRecordTest.id(id),saved,mesh.clock,mesh.nanos::get,state->{
                if(failSave)throw new java.io.IOException("fixture");
                saved=SyncState.decode(state.encode(),new byte[32],CotRecordTest.id(id));saves++;
            },(peer,session,wire)->{
                var packet=new Packet(id,peer[0]&255,session.clone(),wire.clone());mesh.sent.add(packet);mesh.packets.addLast(packet);return true;
            },received::add,new SecureRandom(),minimum);
        }
        boolean publish(String uid){return sync.publish(uid,CotRecordTest.xml(uid,CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED);}
    }
    @Test void threeNodeCycleRelaysOnceAndAcknowledgesReturningOwnDuplicates() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);var c=mesh.node(3);
            mesh.connect(1,2);mesh.connect(2,3);mesh.connect(1,3);mesh.settle();
            assertTrue(a.publish("owned"));mesh.settle();
            assertTrue(a.saved.get("owned").sameRecord(b.saved.get("owned")));
            assertTrue(b.saved.get("owned").sameRecord(c.saved.get("owned")));
            assertEquals(1,b.received.size());assertEquals(1,c.received.size());assertEquals(0,a.received.size());
            long sent=mesh.recordsFrom(2)+mesh.recordsFrom(3);mesh.settle();
            assertEquals(sent,mesh.recordsFrom(2)+mesh.recordsFrom(3));
        }
    }
    @Test void noAckRelayOrHostNotificationHappensBeforePersistence() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            assertTrue(a.publish("owned"));mesh.step(250);
            assertNull(b.saved.get("owned"));assertEquals(0,b.received.size());
            long acks=mesh.sent.stream().filter(p->p.from==2&&SyncWire.parse(p.wire).hasAck()).count();
            assertEquals(0,acks);mesh.step(250);assertNotNull(b.saved.get("owned"));assertEquals(1,b.received.size());
        }
    }
    @Test void storageFailureStopsWithoutAcknowledgingTheUncommittedRecord() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            b.failSave=true;a.publish("owned");mesh.step(250);
            assertThrows(IllegalStateException.class,()->mesh.step(250));
            assertTrue(b.sync.isClosed());assertNull(b.saved.get("owned"));assertEquals(0,b.received.size());
            assertEquals(0,mesh.sent.stream().filter(p->p.from==2&&SyncWire.parse(p.wire).hasAck()).count());
        }
    }
    @Test void missingAcksCauseExactlyThreeRetriesAndDuplicatesDoNotSaveAgain() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            mesh.drop=p->SyncWire.parse(p.wire).hasAck();a.publish("owned");mesh.step(250);mesh.step(250);
            for(int n=0;n<6;n++)mesh.step(1000);
            assertEquals(4,mesh.recordsFrom(1));assertEquals(1,b.saves);assertEquals(1,b.received.size());
        }
    }
    @Test void newerLocalUpdatesAreCoalescedWithoutLosingTheLastUpdateOrTombstone() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            for(int n=0;n<100;n++)assertTrue(a.publish("owned"));assertTrue(a.sync.remove("owned"));
            assertEquals(0,a.saves);mesh.settle();
            assertEquals(1,a.saves);assertTrue(a.saved.get("owned").deleted());assertTrue(b.saved.get("owned").deleted());
            assertEquals(1,b.received.size());
        }
    }
    @Test void configuredSendIntervalKeepsTheLatestCommittedVersionUntilDue() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1,1_000_000_000L);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            a.publish("owned");mesh.step(250);mesh.step(250);long first=b.saved.get("owned").time();
            a.publish("owned");mesh.step(250);mesh.step(250);assertEquals(first,b.saved.get("owned").time());
            mesh.step(500);mesh.step(250);assertTrue(b.saved.get("owned").time()>first);
        }
    }
    @Test void externalAndPreviouslyReceivedUidsCannotBePublishedAsLocalObjects() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();
            a.publish("remote");mesh.settle();assertFalse(b.publish("remote"));assertFalse(b.sync.remove("remote"));
            b.sync.external("external");assertFalse(b.publish("external"));assertFalse(b.sync.remove("external"));
            mesh.settle();assertNull(a.saved.get("external"));
        }
    }
    @Test void foreignAuthorsCannotReplaceLocalPositionOrCreatedObjectsButOwnEchoIsAcked() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);mesh.node(2);mesh.connect(1,2);mesh.settle();
            assertTrue(a.sync.publish("self",CotRecordTest.xml("self",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_POSITION));
            a.publish("owned");mesh.settle();
            for(String uid:List.of("self","owned")){
                CotRecord old=a.saved.get(uid);
                var collision=CotRecord.tombstone(uid,mesh.clock.millis()+1,CotRecordTest.id(2),1);
                a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(collision));
                assertTrue(a.sync.snapshot().get(uid).sameRecord(old));
            }
            var echo=a.saved.get("owned").relay().relay();long before=mesh.sent.size();
            a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(echo));mesh.drain();
            assertTrue(mesh.sent.size()>before);assertTrue(a.publish("owned"));assertEquals(0,a.received.size());
        }
    }
    @Test void firstHopAuthorFutureTimeAndExpiredStaleAreRejectedWithoutEscaping() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);mesh.node(2);mesh.connect(1,2);mesh.settle();
            byte[] xml=CotRecordTest.xml("wrong",CotRecordTest.NOW+60000);
            var wrong=CotRecord.record("wrong",mesh.clock.millis(),CotRecordTest.id(3),CotRecordTest.NOW+60000,xml,1);
            a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(wrong));
            var future=CotRecord.tombstone("future",mesh.clock.millis()+300001,CotRecordTest.id(2),1);
            a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(future));
            mesh.settle();assertNull(a.saved.get("wrong"));assertNull(a.saved.get("future"));assertEquals(0,a.received.size());
        }
    }
    @Test void hopSixteenCanBeStoredButNotRelayedOrAdvertised() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);var c=mesh.node(3);mesh.connect(1,2);mesh.connect(2,3);mesh.settle();
            var record=CotRecord.record("last",mesh.clock.millis(),CotRecordTest.id(1),CotRecordTest.NOW+60000,CotRecordTest.xml("last",CotRecordTest.NOW+60000),16);
            b.sync.receive(CotRecordTest.id(1),SyncFragmentsTest.token(18),SyncWire.encode(record));mesh.settle();
            assertNotNull(b.saved.get("last"));assertNull(c.saved.get("last"));
        }
    }
    @Test void largeRecordsKeepTheirOriginalBytesAcrossThreeNodes() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);var c=mesh.node(3);mesh.connect(1,2);mesh.connect(2,3);mesh.settle();
            String xml=new String(CotRecordTest.xml("large",CotRecordTest.NOW+60000),StandardCharsets.UTF_8)
                    .replace("<detail/>","<detail><remarks>"+"x".repeat(60000)+"</remarks></detail>");
            assertTrue(a.sync.publish("large",xml.getBytes(StandardCharsets.UTF_8),SyncState.Origin.LOCAL_CREATED));mesh.settle();
            assertNotNull(b.saved.get("large"));assertNotNull(c.saved.get("large"));
            assertArrayEquals(a.saved.get("large").xml(),c.saved.get("large").xml());assertEquals(1,c.received.size());
        }
    }
    @Test void reconnectUsesTheInventoryCursorToCatchUpMoreThanThirtyTwoRecords() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);
            for(int n=0;n<64;n++)assertTrue(a.publish("owned-"+n));mesh.step(250);
            mesh.connect(1,2);mesh.settle();
            for(int n=0;n<64;n++)assertNotNull(b.saved.get("owned-"+n));assertEquals(64,b.received.size());
        }
    }
    @Test void lostAckForALargeRecordIsReturnedFromTheCompletedTransferCache() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();var dropped=new java.util.concurrent.atomic.AtomicBoolean();
            mesh.drop=packet->packet.from==2&&SyncWire.parse(packet.wire).hasAck()&&!dropped.getAndSet(true);
            String xml=new String(CotRecordTest.xml("large",CotRecordTest.NOW+60000),StandardCharsets.UTF_8)
                    .replace("<detail/>","<detail><remarks>"+"x".repeat(60000)+"</remarks></detail>");
            a.sync.publish("large",xml.getBytes(StandardCharsets.UTF_8),SyncState.Origin.LOCAL_CREATED);
            mesh.settle();assertTrue(dropped.get());assertEquals(1,b.saves);assertEquals(0,a.sync.statistics().pending());
        }
    }
    @Test void aLateInventoryFragmentDoesNotLeaveAnAlreadySatisfiedRequestBlockingThePeer() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);for(int n=0;n<64;n++)a.publish("owned-"+n);mesh.step(250);
            mesh.connect(1,2);mesh.settle();byte[] late=null;
            try(var fragments=new SyncFragments(()->0)){
                for(Packet packet:mesh.sent)if(packet.from==1&&packet.to==2){
                    try(var result=fragments.accept(CotRecordTest.id(1),packet.session,packet.wire)){
                        if(result!=null&&result.message()!=null&&SyncWire.parse(result.message()).hasInventory()){late=packet.wire;break;}
                    }
                }
            }
            assertNotNull(late);assertEquals(0,b.sync.statistics().pending());
            b.sync.receive(CotRecordTest.id(1),SyncFragmentsTest.token(18),late);mesh.settle();
            assertEquals(0,b.sync.statistics().pending());assertEquals(64,b.received.size());
        }
    }
    @Test void anUnrecognizedRecordClaimingOurAuthorIdCannotOverwriteOurOwnPosition() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);mesh.node(2);mesh.connect(1,2);mesh.settle();
            a.sync.publish("self",CotRecordTest.xml("self",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_POSITION);mesh.settle();
            var old=a.saved.get("self");
            var forged=CotRecord.tombstone("self",mesh.clock.millis()+1,CotRecordTest.id(1),2);
            a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(forged));mesh.settle();
            assertTrue(a.saved.get("self").sameRecord(old));assertEquals(0,a.received.size());
        }
    }
    @Test void anotherPeerOrOldSessionCannotAcknowledgeTheWaitingPeersRecord() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);mesh.node(2);mesh.node(3);mesh.connect(1,2);mesh.connect(1,3);mesh.settle();
            mesh.drop=packet->packet.from==2&&SyncWire.parse(packet.wire).hasAck();a.publish("owned");mesh.step(250);mesh.step(250);
            Packet ack=mesh.sent.stream().filter(packet->packet.from==2&&SyncWire.parse(packet.wire).hasAck()).findFirst().orElseThrow();
            assertEquals(1,a.sync.statistics().pending());
            a.sync.receive(CotRecordTest.id(3),SyncFragmentsTest.token(19),ack.wire);
            a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(99),ack.wire);
            assertEquals(1,a.sync.statistics().pending());long before=mesh.recordsFrom(1);mesh.step(1000);
            assertEquals(before+1,mesh.recordsFrom(1));
        }
    }
    @Test void theCommittedHashWinnerIsSentBackEvenWhenBothConflictsArriveBeforeTheFirstSave() {
        for(boolean reverse:new boolean[]{false,true})try(var mesh=new Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);var c=mesh.node(3);mesh.connect(1,2);mesh.connect(2,3);mesh.settle();
            var record=CotRecord.record("conflict",mesh.clock.millis(),CotRecordTest.id(1),CotRecordTest.NOW+60000,CotRecordTest.xml("conflict",CotRecordTest.NOW+60000),1);
            var deleted=CotRecord.tombstone("conflict",mesh.clock.millis(),CotRecordTest.id(1),1);
            CotRecord winner=Arrays.compareUnsigned(record.hash(),deleted.hash())<0?record:deleted;
            b.sync.receive(CotRecordTest.id(1),SyncFragmentsTest.token(18),SyncWire.encode(reverse?record:deleted));
            b.sync.receive(CotRecordTest.id(1),SyncFragmentsTest.token(18),SyncWire.encode(reverse?deleted:record));
            assertNull(b.saved.get("conflict"));mesh.settle();
            assertTrue(b.saved.get("conflict").sameRecord(winner));assertTrue(c.saved.get("conflict").sameRecord(winner));
            assertNotNull(a.saved.get("conflict"));assertTrue(a.saved.get("conflict").sameRecord(winner));
            assertEquals(1,b.received.size());assertEquals(1,c.received.size());
        }
    }
    @Test void selfUidIsProtectedBeforeTheFirstLocalPositionUpdate() {
        try(var mesh=new Mesh()){
            var a=mesh.node(1);mesh.node(2);assertTrue(a.sync.protectPosition("self"));mesh.connect(1,2);
            var collision=CotRecord.record("self",mesh.clock.millis(),CotRecordTest.id(2),CotRecordTest.NOW+60000,CotRecordTest.xml("self",CotRecordTest.NOW+60000),1);
            a.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(collision));mesh.step(250);
            assertNull(a.saved.get("self"));assertEquals(0,a.received.size());
            assertTrue(a.sync.publish("self",CotRecordTest.xml("self",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_POSITION));mesh.settle();
            assertArrayEquals(CotRecordTest.id(1),a.saved.get("self").author());
        }
    }
}
