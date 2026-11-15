// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncExternalPolicyTest {
    static final long NOW=CotRecordTest.NOW;
    static final Clock WALL=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
    static final byte[] LOCAL=CotRecordTest.id(1),PEER=CotRecordTest.id(2),SESSION=SyncFragmentsTest.token(1);
    static final class Node implements AutoCloseable {
        final AtomicLong time=new AtomicLong();final List<byte[]> sent=new ArrayList<>();final List<CotRecord> imported=new ArrayList<>();final CotSync sync;
        SyncState saved;ExternalMarks marks;
        Node(SyncState initial,ExternalMarks external){saved=initial;marks=external;
            sync=new CotSync(LOCAL,initial,WALL,time::get,s->saved=SyncState.decode(s.encode(),new byte[32],LOCAL),(p,se,w)->{sent.add(w.clone());return true;},imported::add,new SecureRandom(),0,external,m->marks=ExternalMarks.decode(m.encode(),new byte[32],LOCAL));
        }
        public void close(){sync.close();}
    }
    static SyncState own(String uid){var state=new SyncState(new byte[32],LOCAL);state.origin(uid,SyncState.Origin.LOCAL_CREATED);state.put(CotRecord.record(uid,NOW,LOCAL,NOW+60000,CotRecordTest.xml(uid,NOW+60000),0),NOW);return state;}
    static Node fresh(boolean marked){
        var node=new Node(new SyncState(new byte[32],LOCAL),new ExternalMarks(new byte[32],LOCAL));
        assertTrue(node.sync.publish("own",CotRecordTest.xml("own",NOW+60000),SyncState.Origin.LOCAL_CREATED));node.sync.flush();
        if(marked){node.sync.external("own");node.sync.flush();}return node;
    }
    static long records(Node node){return node.sent.stream().filter(w->SyncWire.parse(w).hasRecord()||SyncWire.parse(w).hasTombstone()).count();}
    @Test void inventoryAndServeExcludeMarkedOwnRecordsIncludingAfterBothFilesReload(){
        for(boolean marked:new boolean[]{false,true})for(boolean restart:new boolean[]{false,true}){
            var state=own("own");var marks=new ExternalMarks(new byte[32],LOCAL);if(marked)marks.add("own");
            if(restart){state=SyncState.decode(state.encode(),new byte[32],LOCAL);marks=ExternalMarks.decode(marks.encode(),new byte[32],LOCAL);}
            try(var node=restart?new Node(state,marks):fresh(marked)){
                node.sync.connected(PEER,SESSION);byte[] wire=node.sent.stream().filter(w->SyncWire.parse(w).hasInventory()).findFirst().orElseThrow();
                assertEquals(marked||restart?0:1,SyncWire.parse(wire).getInventory().getEntriesCount());
                node.sync.receive(PEER,SESSION,new SyncInventory.Receiver().accept(wire,e->true));assertEquals(marked||restart?0:1,records(node));
                assertNotNull(node.saved.get("own"));assertEquals(marked,node.marks.contains("own"));
            }
        }
    }
    @Test void markingAnAlreadyQueuedOwnRecordCancelsRetryAndDoesNotDeletePrimary(){
        for(boolean marked:new boolean[]{false,true})try(var node=new Node(new SyncState(new byte[32],LOCAL),new ExternalMarks(new byte[32],LOCAL))){
            node.sync.connected(PEER,SESSION);assertTrue(node.sync.publish("queued",CotRecordTest.xml("queued",NOW+60000),SyncState.Origin.LOCAL_CREATED));node.sync.flush();node.sync.poll();assertEquals(1,records(node));
            node.sent.clear();if(marked){node.sync.external("queued");node.sync.flush();}node.time.set(1_000_000_000L);node.sync.poll();
            assertEquals(marked?0:1,records(node));assertNotNull(node.saved.get("queued"));
        }
    }
    @Test void markingCancelsAnAlreadyQueuedFrozenInventoryPageAndItsRetries(){
        try(var node=fresh(false)){
            node.sync.connected(PEER,SESSION);assertTrue(node.sent.stream().anyMatch(w->SyncWire.parse(w).hasInventory()));node.sent.clear();
            node.sync.external("own");node.sync.flush();node.time.set(1_000_000_000L);node.sync.poll();
            assertTrue(node.sent.stream().noneMatch(w->SyncWire.parse(w).hasInventory()&&SyncWire.parse(w).getInventory().getEntriesCount()>0));assertEquals(0,records(node));
        }
    }
    @Test void aRequestForAPageOfferedBeforeTheMarkCannotSendTheOwnRecord(){
        try(var node=fresh(false)){
            node.sync.connected(PEER,SESSION);byte[] page=node.sent.stream().filter(w->SyncWire.parse(w).hasInventory()).findFirst().orElseThrow();byte[] request=new SyncInventory.Receiver().accept(page,e->true);
            node.sync.external("own");node.sync.flush();node.sync.receive(PEER,SESSION,request);assertEquals(0,records(node));
        }
    }
    @Test void receivedRecordRelayRemainsAllowedEvenWhenItsUidIsExternal(){
        var state=new SyncState(new byte[32],LOCAL);state.origin("received",SyncState.Origin.DISTRIBUTAK);state.put(CotRecord.record("received",NOW,CotRecordTest.id(3),NOW+60000,CotRecordTest.xml("received",NOW+60000),1),NOW);
        var marks=new ExternalMarks(new byte[32],LOCAL);marks.add("received");
        try(var node=new Node(state,marks)){node.sync.connected(PEER,SESSION);byte[] page=node.sent.stream().filter(w->SyncWire.parse(w).hasInventory()).findFirst().orElseThrow();assertEquals(1,SyncWire.parse(page).getInventory().getEntriesCount());node.sync.receive(PEER,SESSION,new SyncInventory.Receiver().accept(page,e->true));assertEquals(1,records(node));}
    }
    @Test void externalRecordAndTombstoneAreSavedAndAckedWithoutImportNotification(){
        for(boolean marked:new boolean[]{false,true})for(boolean deleted:new boolean[]{false,true})for(boolean restart:new boolean[]{false,true}){
            var marks=new ExternalMarks(new byte[32],LOCAL);if(marked)marks.add("incoming");if(restart)marks=ExternalMarks.decode(marks.encode(),new byte[32],LOCAL);
            try(var node=new Node(new SyncState(new byte[32],LOCAL),marks)){
                node.sync.connected(PEER,SESSION);var item=deleted?CotRecord.tombstone("incoming",NOW,PEER,1):CotRecord.record("incoming",NOW,PEER,NOW+60000,CotRecordTest.xml("incoming",NOW+60000),1);
                node.sync.receive(PEER,SESSION,SyncWire.encode(item));node.sync.flush();assertNotNull(node.saved.get("incoming"));assertTrue(node.saved.get("incoming").sameRecord(item));
                assertEquals(1,node.sent.stream().filter(w->SyncWire.parse(w).hasAck()).count());assertEquals(marked?0:1,node.imported.size());
            }
        }
    }
    @Test void externalImportSkipCountIsAfterSaveAndOnlyForChangedReceivedRecordsAndIsNotRestored(){
        for(boolean deleted:new boolean[]{false,true}){
            var marks=new ExternalMarks(new byte[32],LOCAL);marks.add("incoming");
            SyncState saved;
            try(var node=new Node(new SyncState(new byte[32],LOCAL),marks)){
                assertEquals(0,node.sync.externalImportsSkipped());node.sync.connected(PEER,SESSION);
                var item=deleted?CotRecord.tombstone("incoming",NOW,PEER,1):CotRecord.record("incoming",NOW,PEER,NOW+60000,CotRecordTest.xml("incoming",NOW+60000),1);
                node.sync.receive(PEER,SESSION,SyncWire.encode(item));assertEquals(0,node.sync.externalImportsSkipped());
                node.sync.flush();assertEquals(1,node.sync.externalImportsSkipped());assertEquals(1,node.sync.statistics().received());
                assertTrue(node.imported.isEmpty());assertTrue(node.saved.get("incoming").sameRecord(item));
                assertEquals(1,node.sent.stream().filter(w->SyncWire.parse(w).hasAck()).count());
                node.sync.receive(PEER,SESSION,SyncWire.encode(item));node.sync.flush();assertEquals(1,node.sync.externalImportsSkipped());
                assertEquals(2,node.sent.stream().filter(w->SyncWire.parse(w).hasAck()).count());saved=node.saved;
            }
            try(var restored=new Node(SyncState.decode(saved.encode(),new byte[32],LOCAL),marks)){
                assertEquals(0,restored.sync.externalImportsSkipped());
            }
        }
        try(var node=new Node(new SyncState(new byte[32],LOCAL),new ExternalMarks(new byte[32],LOCAL))){
            node.sync.connected(PEER,SESSION);node.sync.receive(PEER,SESSION,SyncWire.encode(CotRecord.record("incoming",NOW,PEER,NOW+60000,CotRecordTest.xml("incoming",NOW+60000),1)));node.sync.flush();
            assertEquals(0,node.sync.externalImportsSkipped());assertEquals(1,node.imported.size());
        }
    }
    @Test void failedSaveDoesNotCountAnExternalImportSkipOrAckTheRecord(){
        var sent=new ArrayList<byte[]>();var marks=new ExternalMarks(new byte[32],LOCAL);marks.add("incoming");
        try(var sync=new CotSync(LOCAL,new SyncState(new byte[32],LOCAL),WALL,()->0,
                s->{throw new IllegalStateException("test save failure");},(p,se,w)->{sent.add(w.clone());return true;},
                r->fail("failed save must not import"),new SecureRandom(),0,marks,m->{})){
            sync.connected(PEER,SESSION);
            sync.receive(PEER,SESSION,SyncWire.encode(CotRecord.record("incoming",NOW,PEER,NOW+60000,CotRecordTest.xml("incoming",NOW+60000),1)));
            assertThrows(IllegalStateException.class,sync::flush);assertEquals(0,sync.externalImportsSkipped());
            assertTrue(sent.stream().noneMatch(w->SyncWire.parse(w).hasAck()));
        }
    }
}
