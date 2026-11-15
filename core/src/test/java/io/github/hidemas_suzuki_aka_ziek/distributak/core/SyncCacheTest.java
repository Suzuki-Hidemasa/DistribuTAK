// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncCacheTest {
    static final class Disk implements SyncSpill {
        final Map<String,byte[]> values=new HashMap<>();long limit=64*1024*1024;int reads;
        String key(byte[] key){return org.bouncycastle.util.encoders.Hex.toHexString(key);}
        public boolean put(byte[] key,byte[] value){if(bytes()+value.length>limit)return false;values.put(key(key),value.clone());return true;}
        public byte[] get(byte[] key){reads++;byte[] value=values.get(key(key));return value==null?null:value.clone();}
        public void remove(byte[] key){values.remove(key(key));}public void clear(){values.clear();}
        public long bytes(){long n=0;for(byte[] value:values.values())n+=value.length;return n;}public int files(){return values.size();}
    }
    @Test void sessionSaltSeparatesIdenticalPayloadsAndIsWipedOnClose(){
        var first=new SyncCache(new Disk(),512,32,()->0);var second=new SyncCache(new Disk(),512,32,()->0);
        var a=first.put("xml",new byte[]{1,2},2);var b=second.put("xml",new byte[]{1,2},2);
        assertFalse(java.util.Arrays.equals(a.key(),b.key()));assertArrayEquals(new byte[]{1,2},first.get(a));assertSame(a,first.put("xml",new byte[]{1,2},2));
        byte[] salt=(byte[])SyncOffloadTest.field(first,"salt");assertEquals(32,salt.length);first.close();assertArrayEquals(new byte[32],salt);second.close();
    }
    @Test void coldRoundtripPrefetchAndFiveSecondEvictionStayBounded(){
        var disk=new Disk();var time=new AtomicLong();var cache=new SyncCache(disk,512,32,time::get);
        var first=cache.put("peer-a",new byte[]{1},2);var second=cache.put("peer-a",new byte[]{2},2);var third=cache.put("peer-a",new byte[]{3},2);
        assertNotNull(first);assertNotNull(second);assertNotNull(third);assertTrue(cache.hotBytes()<=512);assertEquals(2,cache.hotCount("peer-a"));
        assertArrayEquals(new byte[]{1},cache.get(first));time.set(5_000_000_000L);cache.sweep();assertEquals(0,cache.hotBytes());
        cache.prefetch(second);int reads=disk.reads;assertArrayEquals(new byte[]{2},cache.get(second));assertEquals(reads,disk.reads);assertTrue(cache.hotBytes()<=512);
        cache.close();assertEquals(0,disk.files());
    }
    @Test void missingOrCorruptItemIsNotEmptySuccessAndDoesNotLoseOtherItems(){
        for(boolean missing:new boolean[]{true,false}){
            var disk=new Disk();var cache=new SyncCache(disk,512,32,()->0);
            var first=cache.put("peer-a",new byte[]{1,2},2);var second=cache.put("peer-b",new byte[]{3},2);cache.evict(first);
            if(missing)disk.remove(first.key());else disk.values.get(disk.key(first.key()))[0]^=1;
            assertNull(cache.get(first));assertArrayEquals(new byte[]{3},cache.get(second));assertNotNull(cache.put("peer-a",new byte[]{1,2},2));
        }
    }
    @Test void diskAndReferenceLimitsRefuseWithoutChangingAcceptedItems(){
        var disk=new Disk();disk.limit=2;var cache=new SyncCache(disk,512,32,()->0);var first=cache.put("a",new byte[]{1,2},2);assertNotNull(first);
        assertNull(cache.put("b",new byte[]{3},2));assertArrayEquals(new byte[]{1,2},cache.get(first));assertEquals(1,disk.files());
        var one=new SyncCache(new Disk(),512,1,()->0);assertNotNull(one.put("a",new byte[]{1},2));assertNull(one.put("b",new byte[]{2},2));
    }
}
