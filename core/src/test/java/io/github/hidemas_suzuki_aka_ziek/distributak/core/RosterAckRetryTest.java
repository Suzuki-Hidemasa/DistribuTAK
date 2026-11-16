// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RosterAckRetryTest {
    final AtomicLong time=new AtomicLong();
    final Clock clock=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(time.get());}};
    final byte[] group=new byte[32],peer=new byte[32],session=new byte[16];
    final ManagementPageAssembler pages=new ManagementPageAssembler(group,clock,new TransferResources(),true);
    ManagementPage page(int operation,ManagementPage.Kind kind){
        byte[] id=new byte[16];id[0]=(byte)operation;
        return ManagementPage.split(kind,id,group,new byte[]{1},0).get(0);
    }
    ManagementPageAck complete(ManagementPage page){
        try(var completed=pages.receive(peer,session,1,page).completed()){assertNotNull(completed);}
        var ack=pages.confirm(peer,session,1,page);assertNotNull(ack);return ack;
    }
    @Test void retriesShareEightCompletionRecordsAndDisappearOnEvictionForgetAndClose(){
        for(int i=0;i<9;i++){
            var page=page(i,ManagementPage.Kind.ROSTER);var ack=complete(page);
            assertTrue(pages.deferRosterAck(peer,session,1,ack,0,0));
            assertEquals(Math.min(i+1,8),pages.rosterAckRetries().size());
        }
        assertNull(pages.completedRosterAck(peer,session,1,page(0,ManagementPage.Kind.ROSTER)));
        pages.forget(peer);assertTrue(pages.rosterAckRetries().isEmpty());
        var page=page(10,ManagementPage.Kind.ROSTER);assertTrue(pages.deferRosterAck(peer,session,1,complete(page),0,0));
        pages.clearRosterAckRetries();assertTrue(pages.rosterAckRetries().isEmpty());
        assertNotNull(pages.completedRosterAck(peer,session,1,page));
    }
    @Test void repeatedDeferralDoesNotExtendOriginalReceptionOrAssemblyDeadline(){
        var page=page(1,ManagementPage.Kind.ROSTER);var ack=complete(page);
        assertTrue(pages.deferRosterAck(peer,session,1,ack,0,0));
        time.set(29999);assertTrue(pages.deferRosterAck(peer,session,1,ack,29999,29999));
        time.set(30000);assertTrue(pages.rosterAckRetries().isEmpty());
        time.set(239999);assertTrue(pages.deferRosterAck(peer,session,1,ack,239999,239999));
        time.set(240000);assertTrue(pages.rosterAckRetries().isEmpty());
    }
    @Test void replayRequiresExactPageBindingAndRevocationNeverGetsRetrySlot(){
        var page=page(1,ManagementPage.Kind.ROSTER);var ack=complete(page);
        byte[] other=session.clone();other[0]=1;
        assertNull(pages.completedRosterAck(peer,other,1,page));assertNull(pages.completedRosterAck(peer,session,2,page));
        byte[] stranger=peer.clone();stranger[0]=1;assertNull(pages.completedRosterAck(stranger,session,1,page));
        assertFalse(pages.deferRosterAck(peer,other,1,ack,0,0));
        assertThrows(IllegalArgumentException.class,()->new ManagementPageAck(group,page.operationId(),page.objectDigest(),new int[]{0,1,2,3,4},true));
        var revocation=page(2,ManagementPage.Kind.REVOCATION);var revocationAck=complete(revocation);
        assertFalse(pages.deferRosterAck(peer,session,1,revocationAck,0,0));
        assertTrue(pages.rosterAckRetries().isEmpty());
    }
}
