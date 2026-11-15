// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SyncLimitsTest {
    @Test void heapBoundKeepsInventoryBudgetAtOrBelowOneEighthAndFixedCeiling(){
        for(int heap:new int[]{64,128,256,512}){
            var limits=SyncLimits.forHeap((long)heap*1024*1024);
            assertTrue(limits.totalBytes()<=32*1024*1024);assertTrue(limits.totalBytes()<=(long)heap*1024*1024/8);
            assertTrue(limits.peerBytes()<=8*1024*1024);assertTrue(limits.peerBytes()<=limits.totalBytes());
        }
        assertEquals(16*1024*1024,SyncLimits.forHeap(128L*1024*1024).totalBytes());
        assertThrows(IllegalArgumentException.class,()->new SyncLimits(8,4));
    }
}
