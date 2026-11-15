// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.security.SecureRandom;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncStartupTest {
    static final class Restart implements AutoCloseable {
        final java.util.concurrent.atomic.AtomicBoolean ready=new java.util.concurrent.atomic.AtomicBoolean(true);final AtomicLong nanos=new AtomicLong();final List<byte[]> frames=new ArrayList<>();final CotSync sync;
        SyncState saved;final int id;
        Restart(SyncState initial,int id){
            this.id=id;saved=SyncState.decode(initial.encode(),new byte[32],CotRecordTest.id(id));
            Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId zone){return this;}public Instant instant(){return Instant.ofEpochMilli(CotRecordTest.NOW+1000+nanos.get()/1_000_000);}};
            sync=new CotSync(CotRecordTest.id(id),saved,clock,nanos::get,s->saved=s.copy(),(p,s,w)->{if(!ready.get()&&!SyncWire.parse(w).hasInventory())return false;frames.add(w.clone());return true;},r->{},new SecureRandom(),CotSyncDiag8Test.INTERVAL);
        }
        void connect(int other){sync.connected(CotRecordTest.id(other),SyncFragmentsTest.token(18));}
        void emptyInventory(int other){var inv=io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.SyncInventory.newBuilder().setSnapshotId(SyncWire.bytes(SyncFragmentsTest.token(22))).setPage(0).setLast(true);sync.receive(CotRecordTest.id(other),SyncFragmentsTest.token(18),SyncWire.envelope().setInventory(inv).build().toByteArray());}
        List<io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.SyncEnvelope> messages(){
            var result=new ArrayList<io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.SyncEnvelope>();
            try(var fragments=new SyncFragments(nanos::get)){for(byte[] w:frames)try(var r=fragments.accept(CotRecordTest.id(id),SyncFragmentsTest.token(18),w)){if(r!=null&&r.message()!=null)result.add(SyncWire.parse(r.message()));}}
            return result;
        }
        public void close(){sync.close();}
    }
    static SyncState initial(int id,String...uids){var state=new SyncState(new byte[32],CotRecordTest.id(id));for(String uid:uids)state.apply(CotRecord.record(uid,CotRecordTest.NOW,CotRecordTest.id(id),CotRecordTest.NOW+60000,CotRecordTest.xml(uid,CotRecordTest.NOW+60000),0),CotRecordTest.NOW,SyncState.Origin.LOCAL_CREATED,CotRecordTest.NOW);return state;}
    @Test void encodedOldBodyCannotAuthorizeEditsDeletionOrAnyNormalTaskAfterReconnectAndBoundary()throws Exception{
        try(var r=new Restart(initial(1,"old"),1)){
            assertFalse(r.sync.publish("old",CotSyncDiag8Test.xml("old",CotRecordTest.NOW+60000,30),SyncState.Origin.LOCAL_CREATED));assertFalse(r.sync.remove("old"));
            r.connect(2);r.sync.disconnected(CotRecordTest.id(2));r.connect(2);r.nanos.set(CotSyncDiag8Test.INTERVAL);r.sync.poll();
            assertTrue(r.messages().stream().noneMatch(e->e.hasRecord()||e.hasTombstone()));assertTrue(CotSyncDiag8Test.localDeferred(r.sync).isEmpty());assertTrue(CotSyncDiag8Test.recordTasks(r.sync).isEmpty());assertEquals(CotRecordTest.NOW,r.sync.snapshot().maximum());
        }
    }
    @Test void inventoryFiltersOldBodiesAtPageBoundariesWithoutChangingOrder(){
        var state=initial(1,"a-old","b-063a-old","z-old");
        for(int i=0;i<65;i++){String uid=String.format(java.util.Locale.ROOT,"b-%03d",i);state.apply(CotRecord.record(uid,CotRecordTest.NOW,CotRecordTest.id(3),CotRecordTest.NOW+60000,CotRecordTest.xml(uid,CotRecordTest.NOW+60000),1),CotRecordTest.NOW,SyncState.Origin.DISTRIBUTAK,CotRecordTest.NOW);}
        try(var r=new Restart(state,1)){
            r.connect(2);var pages=new ArrayList<io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.SyncInventory>();
            for(int page=0;page<2;page++){
                var inv=r.messages().stream().filter(e->e.hasInventory()&&e.getInventory().getPage()==pages.size()).findFirst().orElseThrow().getInventory();pages.add(inv);
                var req=io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.SyncRequest.newBuilder().setSnapshotId(inv.getSnapshotId()).setPage(inv.getPage());r.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.envelope().setRequest(req).build().toByteArray());
            }
            var names=pages.stream().flatMap(p->p.getEntriesList().stream()).map(e->e.getUid()).toList();assertEquals(65,names.size());assertEquals("b-000",names.get(0));assertEquals("b-063",names.get(63));assertEquals("b-064",names.get(64));assertTrue(pages.get(1).getLast());
        }
    }
    @Test void requestedOldBodyIsUnavailableAndServeFinishes()throws Exception{
        // 一覧のあとで捕捉世代を切り替える経路を試す。
        try(var r=new Restart(new SyncState(new byte[32],CotRecordTest.id(1)),1)){
            assertTrue(r.sync.publish("old",CotRecordTest.xml("old",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));r.sync.flush();r.connect(2);
            var inv=r.messages().stream().filter(e->e.hasInventory()).findFirst().orElseThrow().getInventory();r.sync.beginCreatedCapture();
            var request=io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.SyncRequest.newBuilder().setSnapshotId(inv.getSnapshotId()).setPage(inv.getPage()).addAllWanted(inv.getEntriesList());
            r.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.envelope().setRequest(request).build().toByteArray());
            Object peer=peer(r.sync);var serves=peer.getClass().getDeclaredField("serves");serves.setAccessible(true);Object serve=((Map<?,?>)serves.get(peer)).values().iterator().next();var unavailable=serve.getClass().getDeclaredField("unavailable");unavailable.setAccessible(true);assertEquals(Set.of("old"),unavailable.get(serve));
            assertTrue(r.messages().stream().noneMatch(e->e.hasRecord()));r.nanos.set(CotSync.CATCHUP_NANOS);r.sync.poll();assertTrue(((Map<?,?>)serves.get(peer)).isEmpty());assertEquals(0,r.sync.statistics().pending());
        }
    }
    static Object peer(CotSync sync)throws Exception{var field=CotSync.class.getDeclaredField("peers");field.setAccessible(true);return ((Map<?,?>)field.get(sync)).values().iterator().next();}
    @Test void requesterAlsoTimesOutWhenRevokedBodyCannotBeReturned()throws Exception{
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);assertTrue(a.publish("fresh"));a.sync.flush();mesh.drop=p->SyncWire.parse(p.wire()).hasRequest();mesh.connect(1,2);
            var request=mesh.sent.stream().filter(p->p.from()==2&&SyncWire.parse(p.wire()).hasRequest()).findFirst().orElseThrow();a.sync.beginCreatedCapture();mesh.drop=p->false;
            a.sync.receive(CotRecordTest.id(2),request.session(),request.wire());mesh.drain();assertNull(b.saved.get("fresh"));
            mesh.step(30000);var other=peer(b.sync);var failed=other.getClass().getDeclaredField("remoteFailed");failed.setAccessible(true);assertTrue(failed.getBoolean(other));assertEquals(0,b.sync.statistics().pending());assertNull(b.saved.get("fresh"));
        }
    }
    @Test void missingDoesNotOfferOldBodyToNeverCaughtUpPeer(){
        try(var r=new Restart(initial(2,"old"),2)){r.connect(1);r.emptyInventory(1);r.nanos.set(CotSyncDiag8Test.INTERVAL);r.sync.poll();assertTrue(r.messages().stream().noneMatch(e->e.hasRecord()));}
    }
    @Test void neverCaughtUpPeerRemainsWithoutOldBodyAfterFullTwoWayInventory(){
        record Delivery(int to,byte[] wire){}
        var queue=new ArrayDeque<Delivery>();var time=new AtomicLong();var pair=new CotSync[2];
        for(int i=0;i<2;i++){
            final int from=i;int id=i+1;var state=i==0?initial(id,"old"):new SyncState(new byte[32],CotRecordTest.id(id));
            state=SyncState.decode(state.encode(),new byte[32],CotRecordTest.id(id));
            pair[i]=new CotSync(CotRecordTest.id(id),state,Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW+1000),ZoneOffset.UTC),time::get,saved->{},(peer,session,wire)->{queue.addLast(new Delivery(1-from,wire.clone()));return true;},r->{},new SecureRandom(),CotSyncDiag8Test.INTERVAL);
        }
        try{
            pair[0].connected(CotRecordTest.id(2),SyncFragmentsTest.token(18));pair[1].connected(CotRecordTest.id(1),SyncFragmentsTest.token(18));
            for(int step=0;step<45;step++){
                int processed=0;while(!queue.isEmpty()){assertTrue(++processed<1000);var d=queue.removeFirst();pair[d.to].receive(CotRecordTest.id(2-d.to),SyncFragmentsTest.token(18),d.wire);}
                for(var sync:pair){sync.flush();sync.poll();}time.addAndGet(1_000_000_000L);
            }
            assertNull(pair[1].snapshot().get("old"));assertEquals(SyncState.Origin.UNKNOWN,pair[1].snapshot().origin("old"));assertEquals(0,pair[0].statistics().sent());
        }finally{for(var sync:pair)sync.close();}
    }
    @Test void losingOldEchoGetsAckButNoWinnerBodyReply(){
        var state=initial(1,"old");try(var r=new Restart(state,1)){
            r.connect(2);var older=CotRecord.record("old",CotRecordTest.NOW-1,CotRecordTest.id(1),CotRecordTest.NOW+60000,CotRecordTest.xml("old",CotRecordTest.NOW+60000),2);
            r.sync.receive(CotRecordTest.id(2),SyncFragmentsTest.token(18),SyncWire.encode(older));r.sync.poll();
            assertTrue(r.messages().stream().anyMatch(e->e.hasAck()));assertTrue(r.messages().stream().noneMatch(e->e.hasRecord()));
        }
    }
    @Test void restoredTombstoneStillCatchesUpUntilOriginalThirtyDayExpiry(){
        var state=initial(2,"deleted");var tomb=CotRecord.tombstone("deleted",CotRecordTest.NOW,CotRecordTest.id(2),0);state.apply(tomb,CotRecordTest.NOW,SyncState.Origin.LOCAL_CREATED,CotRecordTest.NOW);
        try(var r=new Restart(state,2)){
            r.connect(1);r.emptyInventory(1);assertTrue(r.messages().stream().anyMatch(e->e.hasTombstone()));
            var before=r.saved.encode();r.sync.flush();assertArrayEquals(before,r.saved.encode());
            r.nanos.set(30L*24*60*60*1_000_000_000L);r.sync.poll();r.sync.flush();assertNull(r.sync.snapshot().get("deleted"));
        }
    }
    @Test void localPositionAndReceivedRelayRemainAllowedAfterRestart(){
        var state=initial(2,"old");for(var origin:List.of(SyncState.Origin.LOCAL_POSITION,SyncState.Origin.DISTRIBUTAK)){
            String uid=origin.name();state.apply(CotRecord.record(uid,CotRecordTest.NOW,CotRecordTest.id(origin==SyncState.Origin.LOCAL_POSITION?2:3),CotRecordTest.NOW+60000,CotRecordTest.xml(uid,CotRecordTest.NOW+60000),1),CotRecordTest.NOW,origin,CotRecordTest.NOW);
        }
        try(var r=new Restart(state,2)){r.connect(1);r.emptyInventory(1);var names=r.messages().stream().filter(e->e.hasRecord()).map(e->e.getRecord().getUid()).toList();assertEquals(Set.of("LOCAL_POSITION","DISTRIBUTAK"),new HashSet<>(names));assertFalse(names.contains("old"));}
    }
    @Test void newCreationStillAddsChangesDeletesAndRecreationLosesOnlyItsOwnership(){
        try(var mesh=new CotSyncTest.Mesh()){
            var a=mesh.node(1);var b=mesh.node(2);mesh.connect(1,2);mesh.settle();assertTrue(a.publish("fresh"));mesh.settle();assertNotNull(b.saved.get("fresh"));long first=b.saved.get("fresh").time();
            byte[] changed=CotSyncDiag8Test.xml("fresh",CotRecordTest.NOW+60000,20);assertTrue(a.sync.publish("fresh",changed,SyncState.Origin.LOCAL_CREATED));mesh.settle();assertTrue(b.saved.get("fresh").time()>first);assertArrayEquals(changed,b.saved.get("fresh").xml());assertTrue(a.sync.remove("fresh"));mesh.settle();assertTrue(b.saved.get("fresh").deleted());
        }
    }
    @Test void createdThenDeletedUidsRetainOriginCapacityButNeverGrowLastLocalPast4096()throws Exception{
        try(var r=new Restart(new SyncState(new byte[32],CotRecordTest.id(1)),1)){
            for(int i=0;i<SyncState.MAX_UIDS;i++){String uid="new-"+i;assertTrue(r.sync.publish(uid,CotRecordTest.xml(uid,CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));assertTrue(r.sync.remove(uid));}
            r.sync.flush();var field=CotSync.class.getDeclaredField("lastLocal");field.setAccessible(true);assertEquals(4096,((Map<?,?>)field.get(r.sync)).size());
            r.nanos.set(30L*24*60*60*1_000_000_000L);r.sync.poll();r.sync.flush();assertTrue(r.sync.snapshot().records().isEmpty());assertEquals(4096,r.sync.snapshot().uidCount());
            assertFalse(r.sync.publish("over-cap",CotRecordTest.xml("over-cap",CotRecordTest.NOW+31L*24*60*60*1000),SyncState.Origin.LOCAL_CREATED));assertTrue(((Map<?,?>)field.get(r.sync)).size()<=4096);
        }
    }
    @Test void captureGenerationKeepsAlreadySavedDeferredTombstone(){
        try(var r=new Restart(new SyncState(new byte[32],CotRecordTest.id(1)),1)){
            assertTrue(r.sync.publish("fresh",CotRecordTest.xml("fresh",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));r.sync.flush();r.connect(2);assertTrue(r.sync.remove("fresh"));r.sync.flush();
            r.sync.beginCreatedCapture();r.frames.clear();r.nanos.set(1_000_000_000L);r.sync.poll();assertTrue(r.messages().stream().anyMatch(e->e.hasTombstone()));
            assertTrue(r.messages().stream().filter(e->e.hasInventory()).flatMap(e->e.getInventory().getEntriesList().stream()).noneMatch(e->e.getUid().equals("fresh")&&!e.getDeleted()));
        }
    }
    @Test void captureGenerationKeepsDeletionTaskBypassWhenLaterBodyIsBlocked(){
        try(var r=new Restart(new SyncState(new byte[32],CotRecordTest.id(1)),1)){
            r.connect(2);r.ready.set(false);assertTrue(r.sync.publish("fresh",CotRecordTest.xml("fresh",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));r.sync.flush();assertTrue(r.sync.remove("fresh"));r.sync.flush();r.sync.poll();
            r.nanos.set(1_000_000_000L);assertTrue(r.sync.publish("fresh",CotRecordTest.xml("fresh",CotRecordTest.NOW+61000),SyncState.Origin.LOCAL_CREATED));r.sync.flush();
            r.sync.beginCreatedCapture();r.ready.set(true);r.nanos.set(2_000_000_000L);r.sync.poll();assertTrue(r.messages().stream().anyMatch(e->e.hasTombstone()));assertTrue(r.messages().stream().noneMatch(e->e.hasRecord()));
        }
    }
    @Test void captureGenerationRevokesPreviousFreshBodyEvenOnSameInstance(){
        try(var r=new Restart(new SyncState(new byte[32],CotRecordTest.id(2)),2)){
            assertTrue(r.sync.publish("fresh",CotRecordTest.xml("fresh",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));r.sync.flush();r.sync.beginCreatedCapture();assertFalse(r.sync.publish("fresh",CotRecordTest.xml("fresh",CotRecordTest.NOW+60000),SyncState.Origin.LOCAL_CREATED));assertFalse(r.sync.remove("fresh"));r.connect(1);r.emptyInventory(1);assertTrue(r.messages().stream().noneMatch(e->e.hasRecord()));
        }
    }
}
