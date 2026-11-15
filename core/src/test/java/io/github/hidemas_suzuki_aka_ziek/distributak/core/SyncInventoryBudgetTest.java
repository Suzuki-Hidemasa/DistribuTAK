// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncInventoryBudgetTest {
    static SyncState full(){
        var state=new SyncState(new byte[32],CotRecordTest.id(255));
        for(int n=0;n<1024;n++)state.put(CotRecord.tombstone(String.format("%04d",n)+"x".repeat(252),CotRecordTest.NOW,CotRecordTest.id(1),1),CotRecordTest.NOW);
        return state;
    }
    static int metadata(CotSync sync)throws Exception{var method=CotSync.class.getDeclaredMethod("metadata");method.setAccessible(true);return (int)method.invoke(sync);}
    @Test void retainedBytesCoverActualPageAndRequestAndRequestsReferToOfferedEntries(){
        var offer=SyncInventory.offer(full(),new byte[16],CotRecordTest.NOW);var receiver=new SyncInventory.Receiver();int serialized=0;
        for(int page=0;page<16;page++){
            byte[] wire=offer.page(page),request=receiver.accept(wire,e->true);serialized+=wire.length+request.length;
            assertTrue(receiver.retainedBytes()>=serialized);assertTrue(receiver.retainedBytes()<=SyncInventory.PEER_BYTES);
            var first=offer.request(request);var duplicate=offer.request(request);assertEquals(64,first.size());assertSame(first.get(0),duplicate.get(0));
        }
        assertTrue(receiver.complete());
        // 同じ相手の送信一覧が予算を持っていれば、受信一覧は残りだけを使う。
        var limited=new SyncInventory.Receiver();boolean rejected=false;
        for(int page=0;page<16;page++){
            int before=limited.retainedBytes();
            try{limited.accept(offer.page(page),e->true,1024*1024-offer.retainedBytes());}
            catch(IllegalArgumentException e){assertEquals(before,limited.retainedBytes());rejected=true;break;}
            assertTrue(offer.retainedBytes()+limited.retainedBytes()<=1024*1024);
        }
        assertTrue(rejected);
    }
    @Test void actualSyncRefusesPeerOfferAndGlobalInventoryOverflowAndReleasesCompletedCaches()throws Exception {
        var time=new AtomicLong();var initial=full();var offer=SyncInventory.offer(initial,new byte[16],CotRecordTest.NOW);
        var clock=Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW),ZoneOffset.UTC);
        try(var sync=new CotSync(CotRecordTest.id(255),initial,clock,time::get,s->{},(p,s,w)->true,r->{},new SecureRandom(),0,
                new ExternalMarks(new byte[32],CotRecordTest.id(255)),marks->{},new SyncLimits(1024*1024,8*1024*1024))){
            long rejected=0;
            for(int peer=1;peer<=16;peer++){
                byte[] id=CotRecordTest.id(peer),session=SyncFragmentsTest.token(peer);sync.connected(id,session);
                for(int page=0;page<16;page++){
                    byte[] transfer=new byte[16];transfer[0]=(byte)peer;transfer[1]=(byte)page;
                    for(byte[] frame:SyncFragments.split(offer.page(page),transfer))sync.receive(id,session,frame);
                }
                sync.poll();assertTrue(metadata(sync)<=8*1024*1024);
                if(peer==1){assertEquals(0,sync.statistics().rejected());assertTrue(sync.statistics().capacity()>0,"same-peer receiver leaves too little room for a full offer");}
                rejected=sync.statistics().rejected();
            }
            assertTrue(rejected>0,"global byte budget must reject otherwise valid additional pages");
            time.set(CotSync.CATCHUP_NANOS);sync.poll();assertTrue(metadata(sync)<=8*1024*1024);
        }
    }
}
