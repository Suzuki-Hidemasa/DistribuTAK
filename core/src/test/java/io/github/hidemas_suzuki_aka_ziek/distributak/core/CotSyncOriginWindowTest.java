// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CotSyncOriginWindowTest {
    static final long NOW=CotSyncExternalPolicyTest.NOW;
    static final byte[] LOCAL=CotSyncExternalPolicyTest.LOCAL,PEER=CotSyncExternalPolicyTest.PEER,THIRD=CotRecordTest.id(3),SESSION=CotSyncExternalPolicyTest.SESSION;
    static final String UID="own";
    static CotSyncExternalPolicyTest.Node node(boolean marked){return CotSyncExternalPolicyTest.fresh(marked);}
    static CotRecord incoming(byte[] author,long time){return CotRecord.record(UID,time,author,NOW+60000,CotRecordTest.xml(UID,NOW+60000),1);}
    static byte[] page(CotSyncExternalPolicyTest.Node node){return node.sent.stream().filter(w->SyncWire.parse(w).hasInventory()).reduce((a,b)->b).orElseThrow();}
    static long oldOwn(List<byte[]> wires){return wires.stream().map(SyncWire::parse).filter(e->e.hasRecord()||e.hasTombstone()).map(SyncWire::decodeRecord).filter(r->Arrays.equals(r.author(),LOCAL)).count();}
    static long received(List<byte[]> wires,CotRecord expected){return wires.stream().map(SyncWire::parse).filter(e->e.hasRecord()||e.hasTombstone()).map(SyncWire::decodeRecord).filter(expected::sameRecord).count();}
    static void assertWindow(CotSyncExternalPolicyTest.Node node,boolean marked){
        assertEquals(SyncState.Origin.LOCAL_CREATED,node.saved.origin(UID));
        var working=(SyncState)SyncOffloadTest.field(node.sync,"working");assertEquals(marked?SyncState.Origin.DISTRIBUTAK:SyncState.Origin.LOCAL_CREATED,working.origin(UID));
    }
    static byte[] pulse(){return SyncWire.ack(CotRecord.tombstone("unrelated",NOW,THIRD,1));}

    @Test void frozenRequestUsesCommittedOriginWhileReceivedRevisionIsStillUnsaved(){
        for(boolean marked:new boolean[]{false,true})try(var node=node(false)){
            node.sync.connected(PEER,SESSION);byte[] request=new SyncInventory.Receiver().accept(page(node),e->true);
            if(marked){node.sync.external(UID);node.sync.flush();}node.sent.clear();
            var next=incoming(PEER,NOW+1);node.sync.receive(PEER,SESSION,SyncWire.encode(next));assertWindow(node,marked);
            node.sync.receive(PEER,SESSION,request);assertEquals(marked?0:1,oldOwn(node.sent));
            node.sent.clear();node.sync.flush();node.time.set(1_000_000_000L);node.sync.poll();assertEquals(marked?0:1,oldOwn(node.sent));
            if(marked){assertTrue(node.saved.get(UID).sameRecord(next));assertTrue(node.marks.contains(UID));assertTrue(node.imported.isEmpty());}
        }
    }
    @Test void anEmptyOfferCannotBecomeAnOwnInventoryOrMissingReplyThroughWorkingOrigin(){
        for(boolean marked:new boolean[]{false,true})try(var node=node(marked)){
            node.sync.connected(PEER,SESSION);byte[] ownPage=page(node);assertEquals(marked?0:1,SyncWire.parse(ownPage).getInventory().getEntriesCount());
            byte[] noWanted=new SyncInventory.Receiver().accept(ownPage,e->false);node.sent.clear();
            node.sync.receive(PEER,SESSION,SyncWire.encode(incoming(PEER,NOW+1)));assertWindow(node,marked);
            node.sync.receive(PEER,SESSION,noWanted);
            byte[] remoteEmpty=SyncInventory.offer(new SyncState(new byte[32],PEER),SyncFragmentsTest.token(9),NOW).page(0);
            node.sync.receive(PEER,SESSION,remoteEmpty);assertEquals(marked?0:1,oldOwn(node.sent));
            node.sync.connected(THIRD,SESSION);assertEquals(marked?0:1,SyncWire.parse(page(node)).getInventory().getEntriesCount());assertWindow(node,marked);
        }
    }
    @Test void winnerDeferredDeliveryAndRetryCannotUseOnlyTheUnsavedOrigin(){
        for(boolean marked:new boolean[]{false,true})try(var node=node(false)){
            node.sync.connected(PEER,SESSION);node.sync.connected(THIRD,SESSION);
            assertTrue(node.sync.publish(UID,CotRecordTest.xml(UID,NOW+60000),SyncState.Origin.LOCAL_CREATED));node.sync.flush();node.sync.poll();assertTrue(oldOwn(node.sent)>0);
            if(marked){node.sync.external(UID);node.sync.flush();}node.sent.clear();
            node.sync.receive(PEER,SESSION,SyncWire.encode(incoming(PEER,NOW+1)));assertWindow(node,marked);
            node.sync.receive(THIRD,SESSION,SyncWire.encode(incoming(THIRD,NOW-1)));
            // pollの自動保存より先に受信による送り出しを起こす。
            node.time.set(1_000_000_000L);node.sync.receive(THIRD,SESSION,pulse());assertWindow(node,marked);
            assertEquals(marked?0:1,oldOwn(node.sent)>0?1:0);
            node.sent.clear();node.sync.flush();node.time.addAndGet(1_000_000_000L);node.sync.poll();if(marked)assertEquals(0,oldOwn(node.sent));
        }
    }
    @Test void aSelectedOldTaskCannotBorrowTheSavedReceivedRevisionsOrigin()throws Exception{
        try(var node=node(false)){
            node.sync.connected(PEER,SESSION);assertTrue(node.sync.publish(UID,CotRecordTest.xml(UID,NOW+60000),SyncState.Origin.LOCAL_CREATED));node.sync.flush();node.sync.poll();
            Object peer=((Map<?,?>)SyncOffloadTest.field(node.sync,"peers")).values().iterator().next();Object task=((Map<?,?>)SyncOffloadTest.field(peer,"records")).get(UID);assertNotNull(task);
            node.sync.external(UID);node.sync.flush();node.sync.receive(PEER,SESSION,SyncWire.encode(incoming(PEER,NOW+1)));node.sync.flush();assertEquals(SyncState.Origin.DISTRIBUTAK,node.saved.origin(UID));
            node.sent.clear();node.time.set(1_000_000_000L);
            // 送り出すリストに取り出してあった古い待ちも、後の版の出所では許可しない。
            var send=CotSync.class.getDeclaredMethod("send",peer.getClass(),task.getClass());send.setAccessible(true);send.invoke(node.sync,peer,task);assertEquals(0,oldOwn(node.sent));
        }
    }
    @Test void savedReceivedRevisionStillRelaysAndRetriesWhileImportRemainsExcluded(){
        for(boolean deleted:new boolean[]{false,true})try(var node=node(true)){
            node.sync.connected(PEER,SESSION);node.sync.connected(THIRD,SESSION);node.sent.clear();var next=deleted?CotRecord.tombstone(UID,NOW+1,PEER,1):incoming(PEER,NOW+1);
            node.sync.receive(PEER,SESSION,SyncWire.encode(next));assertWindow(node,true);node.sync.flush();
            assertEquals(1,node.sent.stream().filter(w->SyncWire.parse(w).hasAck()).count());assertTrue(node.imported.isEmpty());assertEquals(SyncState.Origin.DISTRIBUTAK,node.saved.origin(UID));assertTrue(node.marks.contains(UID));
            node.sent.clear();node.sync.poll();assertEquals(0,oldOwn(node.sent));assertTrue(received(node.sent,next)>0);
            node.sent.clear();node.time.set(1_000_000_000L);node.sync.poll();assertEquals(0,oldOwn(node.sent));assertTrue(received(node.sent,next)>0);
        }
    }
}
