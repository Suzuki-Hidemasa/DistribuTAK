// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncPrimaryBatchTest {
    @Test void missingColdBodiesAndRejectedReinsertOpenPrimaryAtMostOncePerReceive(){
        for(boolean corrupt:new boolean[]{false,true}){
            var initial=SyncStateTest.state();for(int n=0;n<64;n++)initial.put(CotRecord.record("item-"+n,CotRecordTest.NOW,CotRecordTest.id(1),CotRecordTest.NOW+60000,CotRecordTest.xml("item-"+n,CotRecordTest.NOW+60000),0),CotRecordTest.NOW);
            var primary=new byte[][]{initial.encode()};int[] opens={0};var time=new AtomicLong();var disk=new SyncCacheTest.Disk();var cache=new SyncCache(disk,65536,8192,time::get);
            var store=new CotSync.Store(){public boolean encoded(){return true;}public byte[] loadEncoded(){opens[0]++;return primary[0].clone();}public SyncState load(){opens[0]++;return SyncState.decode(primary[0],new byte[32],CotRecordTest.id(1));}public void save(SyncState state){primary[0]=state.encode();}public void saveEncoded(SyncState state,byte[] encoded){primary[0]=encoded.clone();}};
            try(var node=new CotSync(CotRecordTest.id(1),initial,Clock.fixed(Instant.ofEpochMilli(CotRecordTest.NOW),ZoneOffset.UTC),time::get,store,(p,se,w)->true,r->{},new SecureRandom(),0,new ExternalMarks(new byte[32],CotRecordTest.id(1)),m->{},SyncLimits.DEFAULT,cache)){
                byte[] peer=CotRecordTest.id(2),session=SyncFragmentsTest.token(1);node.connected(peer,session);Object exchange=((Map<?,?>)SyncOffloadTest.field(node,"peers")).values().iterator().next();var offer=(SyncInventory.Offer)SyncOffloadTest.field(exchange,"offer");byte[] request=new SyncInventory.Receiver().accept(offer.page(0),e->true);
                var refs=(Map<?,?>)SyncOffloadTest.field(node,"bodies");for(Object value:refs.values()){var ref=(SyncCache.Ref)value;cache.evict(ref);if(corrupt)disk.values.get(disk.key(ref.key()))[0]^=1;else disk.remove(ref.key());}
                disk.limit=disk.bytes();opens[0]=0;SyncOffloadTest.deliver(node,peer,session,request,2);assertEquals(1,opens[0]);assertFalse(node.isClosed());
                assertNull(SyncOffloadTest.field(node,"primaryEncoded"));assertNull(SyncOffloadTest.field(node,"restored"));
                assertTrue(node.registerReceivedUid("registry"));opens[0]=0;node.flush();assertEquals(1,opens[0]);assertEquals(64,SyncState.decode(primary[0],new byte[32],CotRecordTest.id(1)).records().size());
            }
        }
    }
}
