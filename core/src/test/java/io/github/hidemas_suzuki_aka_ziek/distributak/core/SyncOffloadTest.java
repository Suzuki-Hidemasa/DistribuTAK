// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncOffloadTest {
    @Test void decodedServeEntriesIncludeTheirOwnPayloadInTheMetadataBudget(){
        var state=SyncStateTest.state();for(int n=0;n<64;n++)state.put(CotRecord.tombstone(String.format(java.util.Locale.ROOT,"%0256d",n),CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        var disk=new SyncCacheTest.Disk();var cache=new SyncCache(disk,65536,8192,()->0);
        try(var node=new CotSync(CotRecordTest.id(1),state,java.time.Clock.fixed(java.time.Instant.ofEpochMilli(CotRecordTest.NOW),java.time.ZoneOffset.UTC),()->0,next->{},(p,se,w)->true,r->{},new java.security.SecureRandom(),0,new ExternalMarks(new byte[32],CotRecordTest.id(1)),m->{},SyncLimits.DEFAULT,cache)){
            byte[] peer=CotRecordTest.id(2),session=SyncFragmentsTest.token(1);node.connected(peer,session);Object exchange=((java.util.Map<?,?>)field(node,"peers")).values().iterator().next();
            var offer=(SyncInventory.Offer)field(exchange,"offer");deliver(node,peer,session,new SyncInventory.Receiver().accept(offer.page(0),e->true),2);
            Object serve=((java.util.Map<?,?>)field(exchange,"serves")).get(0);int bytes=(Integer)field(serve,"entryBytes");
            int serialized=0;for(var entry:SyncWire.parse(offer.page(0)).getInventory().getEntriesList())serialized+=entry.getSerializedSize();
            assertTrue(bytes>=2*serialized+64*64+64*8);assertTrue(bytes>64*256);
        }
    }
    @Test void inventoryUsesColdPagesAndPreservesFixedRequestsUntilTheirCacheIsLost(){
        var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,64*1024,8192,time::get);
        var state=SyncStateTest.state();
        for(int n=0;n<193;n++)state.put(CotRecord.tombstone("item-"+n,CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        var offer=SyncInventory.offer(state,SyncFragmentsTest.token(1),CotRecordTest.NOW,8*1024*1024,cache,"offer");
        var receiver=new SyncInventory.Receiver(cache,"receive");
        byte[] first=receiver.accept(offer.page(0),entry->true);
        for(int n=1;n<4;n++)receiver.accept(offer.page(n),entry->true);
        assertTrue(receiver.complete());assertEquals(193,receiver.entries().size());
        time.set(6_000_000_000L);cache.sweep();assertEquals(0,cache.hotBytes());
        assertArrayEquals(first,receiver.accept(offer.page(0),entry->false));
        assertTrue(receiver.retainedBytes()<100000);assertTrue(offer.retainedBytes()<10000);
        time.set(12_000_000_000L);cache.sweep();disk.values.clear();
        assertThrows(SyncInventory.CacheMiss.class,receiver::entries);assertFalse(receiver.complete());assertThrows(IllegalStateException.class,()->receiver.knows("absent"));
        var replacement=SyncInventoryTest.offer(193);
        assertEquals(0,SyncWire.parse(receiver.accept(replacement.page(0),entry->false)).getRequest().getWantedCount());
        assertThrows(SyncInventory.CacheMiss.class,receiver::entries);assertFalse(receiver.complete());
        cache.close();assertEquals(0,disk.files());
    }
    @Test void missingOfferedPageCanBeRebuiltOnlyWhenTheFrozenPageIsIdentical(){
        var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,1024,8192,time::get);
        var state=SyncStateTest.state();state.put(CotRecord.tombstone("frozen",CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        var offer=SyncInventory.offer(state,SyncFragmentsTest.token(1),CotRecordTest.NOW,8*1024*1024,cache,"offer",state::copy);
        byte[] original=offer.page(0);time.set(6_000_000_000L);cache.sweep();disk.values.clear();assertArrayEquals(original,offer.page(0));
        state.put(CotRecord.tombstone("changed",CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        time.set(12_000_000_000L);cache.sweep();disk.values.clear();assertThrows(SyncInventory.CacheMiss.class,()->offer.page(0));
    }
    @Test void fixedRequestLossReevaluatesOnlyThatPageAndKeepsTheOtherPage(){
        for(boolean corrupt:new boolean[]{false,true}){
            var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,1024,8192,time::get);
            var offer=SyncInventoryTest.offer(65);var receiver=new SyncInventory.Receiver(cache,"r");
            byte[] first=receiver.accept(offer.page(0),e->true);receiver.accept(offer.page(1),e->true);
            time.set(6_000_000_000L);cache.sweep();
            var refs=(SyncCache.Ref[])field(receiver,"coldRequests");String key=disk.key(refs[0].key());
            if(corrupt)disk.values.get(key)[0]^=1;else disk.values.remove(key);
            assertEquals(0,SyncWire.parse(receiver.accept(offer.page(0),e->false)).getRequest().getWantedCount());
            assertTrue(receiver.complete());assertEquals(1,receiver.wanted().size());assertEquals(64,SyncWire.parse(first).getRequest().getWantedCount());
        }
    }
    static Object field(Object object,String name){try{var field=object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);}catch(Exception e){throw new AssertionError(e);}}
    @Test void engineActuallyOffloadsCommittedXmlAndClosesTheSessionCache(){
        var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,64*1024,8192,time::get);
        var primary=new SyncState[]{SyncStateTest.state()};primary[0].put(CotRecordTest.record(CotRecordTest.NOW,1,0),CotRecordTest.NOW);
        var store=new CotSync.Store(){public void save(SyncState state){primary[0]=SyncState.decode(state.encode(),new byte[32],CotRecordTest.id(1));}public SyncState load(){return primary[0].copy();}};
        var node=new CotSync(CotRecordTest.id(1),primary[0],java.time.Clock.fixed(java.time.Instant.ofEpochMilli(CotRecordTest.NOW),java.time.ZoneOffset.UTC),time::get,store,(p,s,w)->true,r->{},new java.security.SecureRandom(),0,new ExternalMarks(new byte[32],CotRecordTest.id(1)),m->{},SyncLimits.DEFAULT,cache);
        assertTrue(node.snapshot().records().get(0).cold());assertTrue(disk.files()>0);
        time.set(6_000_000_000L);node.poll();assertEquals(0,cache.hotBytes());disk.values.clear();
        assertArrayEquals(primary[0].records().get(0).xml(),node.snapshot().records().get(0).xml());
        node.close();assertEquals(0,disk.files());
    }
    @Test void completedServeLeavesRamAndOnlyALostServeIsRetried(){
        var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,64*1024,8192,time::get);
        var state=SyncStateTest.state();for(int n=0;n<65;n++)state.put(CotRecord.tombstone("item-"+n,CotRecordTest.NOW,CotRecordTest.id(1),0),CotRecordTest.NOW);
        var queue=new java.util.ArrayDeque<byte[]>();byte[] peer=CotRecordTest.id(2),session=SyncFragmentsTest.token(1);
        var node=new CotSync(CotRecordTest.id(1),state,java.time.Clock.fixed(java.time.Instant.ofEpochMilli(CotRecordTest.NOW),java.time.ZoneOffset.UTC),time::get,next->{},(p,se,w)->{queue.add(w.clone());return true;},r->{},new java.security.SecureRandom(),0,new ExternalMarks(new byte[32],CotRecordTest.id(1)),m->{},SyncLimits.DEFAULT,cache);
        try{
            node.connected(peer,session);var peers=(java.util.Map<?,?>)field(node,"peers");Object exchange=peers.values().iterator().next();
            var offer=(SyncInventory.Offer)field(exchange,"offer");byte[] request=new SyncInventory.Receiver().accept(offer.page(0),e->true);
            deliver(node,peer,session,request,2);ackAll(node,peer,session,queue);
            assertEquals(64,node.statistics().sent());assertFalse(((java.util.Map<?,?>)field(exchange,"serves")).containsKey(0));
            var completed=(java.util.Map<?,?>)field(exchange,"completedServes");assertTrue(completed.containsKey(0));
            time.set(6_000_000_000L);cache.sweep();deliver(node,peer,session,request,3);ackAll(node,peer,session,queue);assertEquals(64,node.statistics().sent());
            var ref=(SyncCache.Ref)completed.get(0);cache.evict(ref);disk.values.get(disk.key(ref.key()))[0]^=1;
            deliver(node,peer,session,request,4);ackAll(node,peer,session,queue);assertEquals(128,node.statistics().sent());assertFalse(((java.util.Map<?,?>)field(exchange,"serves")).containsKey(0));assertTrue(completed.containsKey(0));assertFalse(node.isClosed());assertEquals(0,node.statistics().failed());
        }finally{node.close();}
    }
    static void deliver(CotSync node,byte[] peer,byte[] session,byte[] wire,int transfer){for(byte[] frame:SyncFragments.split(wire,SyncFragmentsTest.token(transfer)))node.receive(peer,session,frame);}
    static void ackAll(CotSync node,byte[] peer,byte[] session,java.util.ArrayDeque<byte[]> queue){
        int count=0;for(byte[] wire;(wire=queue.poll())!=null;){assertTrue(++count<10000);var envelope=SyncWire.parse(wire);if(envelope.hasTombstone())node.receive(peer,session,SyncWire.ack(SyncWire.decodeRecord(envelope)));}
    }
    @Test void corruptPrimaryAfterXmlSpillLossStillStopsTheEngine(){
        var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,1024,8192,time::get);
        var state=SyncStateTest.state();state.put(CotRecordTest.record(CotRecordTest.NOW,1,0),CotRecordTest.NOW);
        var store=new CotSync.Store(){public void save(SyncState state){}public SyncState load(){throw new IllegalStateException("private primary detail");}};
        var node=new CotSync(CotRecordTest.id(1),state,java.time.Clock.fixed(java.time.Instant.ofEpochMilli(CotRecordTest.NOW),java.time.ZoneOffset.UTC),time::get,store,(p,se,w)->true,r->{},new java.security.SecureRandom(),0,new ExternalMarks(new byte[32],CotRecordTest.id(1)),m->{},SyncLimits.DEFAULT,cache);
        var cold=node.snapshot().records().get(0);time.set(6_000_000_000L);node.poll();disk.values.clear();
        var failure=assertThrows(IllegalStateException.class,cold::xml);assertTrue(node.isClosed());assertFalse(failure.getMessage().contains("private"));
    }
    @Test void xmlLeavesTheRecordAndRecoversFromPrimaryWhenSpillIsMissing(){
        var disk=new SyncCacheTest.Disk();var time=new AtomicLong();var cache=new SyncCache(disk,64*1024,8192,time::get);
        var original=CotRecordTest.record(CotRecordTest.NOW,1,0);byte[] xml=original.xml();int[] loads={0};
        var cold=original.offload(cache,()->{loads[0]++;return xml.clone();});
        assertTrue(cold.cold());assertEquals(original.xmlSize(),cold.xmlSize());assertTrue(original.sameRecord(cold));
        time.set(6_000_000_000L);cache.sweep();assertEquals(0,cache.hotBytes());
        assertArrayEquals(xml,cold.xml());assertEquals(0,loads[0]);
        time.set(12_000_000_000L);cache.sweep();disk.values.clear();
        assertArrayEquals(xml,cold.xml());assertEquals(1,loads[0]);assertTrue(disk.files()>0);
        assertArrayEquals(xml,cold.relay().xml());
        var broken=original.offload(new SyncCache(new SyncCacheTest.Disk(),1024,32,time::get),()->new byte[]{1});
        assertTrue(broken.cold());
    }
}
