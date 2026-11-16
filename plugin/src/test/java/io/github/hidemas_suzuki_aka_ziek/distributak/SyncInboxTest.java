// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

public class SyncInboxTest {
    @Test public void timestampSurvivesQueueAndOwnedPlaintextIsWipedOnDiscard(){
        var inbox=new SyncInbox();byte[] wire={1,2,3};
        assertTrue(inbox.offer(1,peer(1),new byte[16],wire,123));
        var packet=inbox.take();assertEquals(123,packet.receivedAt);packet.close();
        assertArrayEquals(new byte[3],packet.wire);assertArrayEquals(new byte[]{1,2,3},wire);
    }
    private static byte[] peer(int id){byte[] peer=new byte[32];peer[0]=(byte)id;return peer;}
    @Test public void acceptsAllSeventyTwoFragmentsAndLimitsPeer() {
        var inbox=new SyncInbox();byte[] session=new byte[16],wire=new byte[1024];
        for(int i=0;i<80;i++)assertTrue(inbox.offer(3,peer(1),session,wire));
        assertFalse(inbox.offer(3,peer(1),session,wire));
        for(int i=0;i<80;i++)try(var packet=inbox.take()){assertNotNull(packet);assertEquals(3,packet.epoch);assertArrayEquals(wire,packet.wire);}
        assertNull(inbox.take());assertEquals(0,inbox.bytes());
    }
    @Test public void globalAndByteLimitsAreIndependent() {
        var inbox=new SyncInbox();byte[] session=new byte[16];
        for(int i=0;i<256;i++)assertTrue(inbox.offer(0,peer(i/80),session,new byte[1]));
        assertFalse(inbox.offer(0,peer(9),session,new byte[1]));inbox.clear();
        assertTrue(inbox.offer(0,peer(0),session,new byte[1024*1024-48]));
        assertFalse(inbox.offer(0,peer(1),session,new byte[1]));
        assertEquals(1,inbox.size());
    }
    @Test public void copiesBorrowedArraysAndWipesOwnedCopies() {
        var inbox=new SyncInbox();byte[] id=peer(1),session=new byte[16],wire={1,2,3};
        assertTrue(inbox.offer(0,id,session,wire));wire[0]=9;id[0]=9;
        var packet=inbox.take();assertEquals(1,packet.wire[0]);assertEquals(1,packet.peer[0]);
        packet.close();assertArrayEquals(new byte[3],packet.wire);assertArrayEquals(new byte[32],packet.peer);
        assertArrayEquals(new byte[16],packet.session);
        assertTrue(inbox.offer(0,id,session,wire));inbox.clear();assertEquals(0,inbox.size());assertEquals(0,inbox.bytes());
    }
}
