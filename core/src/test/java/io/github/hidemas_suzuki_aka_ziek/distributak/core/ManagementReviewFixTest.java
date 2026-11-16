// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementPageSenderTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementPageAssembler.Status.*;

class ManagementReviewFixTest {
    final Time clock=new Time();
    final TransferResources resources=new TransferResources();
    final ManagementPageAssembler assembler=new ManagementPageAssembler(GROUP,clock,resources);
    final ManagementSendBudget budget=new ManagementSendBudget(clock);
    final List<ManagementPage> sent=new ArrayList<>();
    final ManagementPageSender sender=new ManagementPageSender(GROUP,clock,budget,(p,s,d)->{sent.add(ManagementPage.decodeEnvelope(d));return true;});
    List<ManagementPage> pages(int operation,int bytes){return ManagementPage.split(ManagementPage.Kind.REVOCATION,op(operation),GROUP,new byte[bytes],0);}
    ManagementPageAssembler.Result receive(ManagementPage page){return assembler.receive(peer(1),SESSION,1,page);}
    void offer(ManagementPage.Kind kind,int operation,int bytes){assertEquals(ManagementPageSender.Offer.ACCEPTED,
            sender.offer(peer(1),SESSION,1,kind,op(operation),new byte[bytes],0,false));}
    void ack(ManagementPage page){sender.acknowledge(peer(1),SESSION,1,new ManagementPageAck(GROUP,page.operationId(),page.objectDigest(),new int[]{page.pageIndex()}));}
    @Test void aLostFinalAckDoesNotReserveAgainAndTheNextObjectCompletes(){
        var all=pages(1,4096);for(var p:all)receive(p);
        var retry=receive(all.get(3));assertEquals(DUPLICATE,retry.status());assertNull(retry.completed());
        assertNotNull(retry.ack());assertArrayEquals(new int[]{3},retry.ack().pageIndices());
        assertEquals(0,resources.reservedBytes());assertEquals(COMPLETE,receive(pages(2,1).get(0)).status());
    }
    @Test void onePageRetransmissionsNeverDeliverTheWholeObjectTwice(){
        var p=pages(1,1).get(0);assertEquals(COMPLETE,receive(p).status());
        for(int i=0;i<4;i++){var result=receive(p);assertEquals(DUPLICATE,result.status());assertNull(result.completed());assertNotNull(result.ack());}
        assertEquals(0,resources.active());
    }
    @Test void completedRecordsAreBoundedExpireAndBindSessionGenerationAndMetadata(){
        var first=pages(1,1).get(0);receive(first);
        assertEquals(COMPLETE,assembler.receive(peer(1),SESSION,2,first).status());
        byte[] otherSession=op(9);assertEquals(COMPLETE,assembler.receive(peer(1),otherSession,1,first).status());
        for(int i=2;i<=9;i++)assertEquals(COMPLETE,receive(pages(i,1).get(0)).status());
        assertEquals(COMPLETE,receive(first).status());
        clock.now=239999;assertEquals(DUPLICATE,receive(first).status());
        clock.now=240000;assertEquals(COMPLETE,receive(first).status());
        assembler.forget(peer(1));assertEquals(COMPLETE,receive(first).status());
        clock.now=240100;assembler.poll();clock.now=240050;assembler.poll();
        var duplicate=receive(first);assertEquals(DUPLICATE,duplicate.status());assertNull(duplicate.completed());assertNotNull(duplicate.ack());
        assembler.clear();assertEquals(COMPLETE,receive(first).status());
    }
    @Test void rememberedTargetsKeepTheirStatusForTwoHundredFortySecondsAfterRollback(){
        clock.now=1000;var old=pages(1,2048);receive(old.get(0));
        var complete=pages(2,1).get(0);receive(complete);clock.now=900;assembler.poll();
        assertEquals(REJECTED,receive(old.get(0)).status());assertEquals(DUPLICATE,receive(complete).status());
        clock.now=240899;assertEquals(REJECTED,receive(old.get(0)).status());assertEquals(DUPLICATE,receive(complete).status());
        clock.now=240900;assertEquals(INCOMPLETE,receive(old.get(0)).status());
        assertEquals(COMPLETE,receive(complete).status());
    }
    int read,receiverCompleted,rostersCompleted,rejected;
    void drain(boolean dropRosterTail){
        while(read<sent.size()){
            var page=sent.get(read++);
            if(dropRosterTail&&page.kind()==ManagementPage.Kind.ROSTER&&page.pageIndex()==1)continue;
            var result=receive(page);
            if(result.completed()!=null){receiverCompleted++;if(page.kind()==ManagementPage.Kind.ROSTER)rostersCompleted++;}
            if(result.status()==REJECTED)rejected++;
            if(result.ack()!=null)sender.acknowledge(peer(1),SESSION,1,result.ack());
        }
    }
    @Test void resumedRosterCompletesAtBothEndsAfterTheReceiverAssemblyExpires(){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();drain(true);
        sender.rotating(true);ack(sent.get(1));assertEquals(0,sender.completed());
        clock.now=31000;assembler.poll();assertEquals(0,assembler.active());
        sender.rotating(false);sender.poll();drain(false);
        assertEquals(1,sender.completed());
        assertEquals(1,receiverCompleted,"sender completed="+sender.completed()+", receiver completed="+receiverCompleted);
        assertEquals(1,rostersCompleted);assertEquals(0,sender.failed());assertEquals(0,assembler.active());
    }
    @Test void resumedRosterFailsAfterARevocationReplacesItDuringAFiveSecondPause(){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();drain(true);sender.rotating(true);
        offer(ManagementPage.Kind.REVOCATION,2,1);clock.now=1000;sender.poll();drain(false);
        assertEquals(1,receiverCompleted);assertEquals(1,sender.completed());
        clock.now=5000;sender.rotating(false);
        for(int i=5;i<=9;i++){clock.now=i*1000;sender.poll();drain(false);}
        assertTrue(rejected>0);assertEquals(0,rostersCompleted);assertEquals(1,receiverCompleted);
        assertEquals(1,sender.completed());assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());
    }
    @Test void resumedRosterGetsAFreshRetryBudgetButKeepsItsOriginalTotalDeadline(){
        offer(ManagementPage.Kind.ROSTER,1,2048);
        for(int i=0;i<=3;i++){clock.now=i*1000;sender.poll();drain(true);}
        sender.rotating(true);clock.now=34000;assembler.poll();sender.rotating(false);sender.poll();drain(true);
        clock.now=35000;sender.poll();drain(false);
        assertEquals(1,sender.completed());assertEquals(1,receiverCompleted);assertEquals(0,sender.failed());
        offer(ManagementPage.Kind.ROSTER,3,2048);sender.poll();sender.rotating(true);
        clock.now=275000;sender.rotating(false);sender.poll();
        assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());
    }
    @Test void aFailedObjectIsReplacedAtFourSecondsAndOldFirstPagesCannotBounceBack(){
        offer(ManagementPage.Kind.REVOCATION,1,2048);offer(ManagementPage.Kind.ANNOUNCEMENT,2,2048);
        int read=0,completed=0;ManagementPage old=null;
        for(int tick=0;tick<=50;tick++){
            clock.now=tick*100;sender.poll();
            while(read<sent.size()){
                var p=sent.get(read++);
                if(p.kind()==ManagementPage.Kind.REVOCATION){if(old==null){old=p;receive(p);}continue;}
                var result=receive(p);if(result.status()==COMPLETE)completed++;
                assertNotEquals(REJECTED,result.status());ack(p);
            }
        }
        assertEquals(1,completed);assertEquals(1,sender.completed());assertEquals(1,sender.failed());
        assertEquals(REJECTED,receive(old).status());assertEquals(0,resources.active());
    }
    @Test void replacedFirstPagesDoNotResetTheNewAssemblyOrItsProgressDeadline(){
        var a=pages(1,2048);var b=pages(2,2048);receive(a.get(0));clock.now=4000;
        assertEquals(INCOMPLETE,receive(b.get(0)).status());clock.now=5000;
        assertEquals(REJECTED,receive(a.get(0)).status());assertEquals(2048,resources.reservedBytes());
        clock.now=33999;assertEquals(DUPLICATE,receive(b.get(0)).status());
        clock.now=34000;assembler.poll();assertEquals(0,resources.active());
    }
    @Test void aCompletedOldFirstPageNeverReplacesAnUnfinishedNewObject(){
        var old=pages(1,1).get(0);receive(old);var next=pages(2,2048);receive(next.get(0));
        assertEquals(DUPLICATE,receive(old).status());assertEquals(2048,resources.reservedBytes());
        assertEquals(COMPLETE,receive(next.get(1)).status());
    }
    @Test void bothRosterKindsRejectTooManyEntriesOrBytesBeforeReservation(){
        for(var kind:List.of(ManagementPage.Kind.ROSTER,ManagementPage.Kind.ROSTER_SUMMARY)){
            var valid=ManagementPage.split(kind,op(1),GROUP,new byte[65536],32).get(0);
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(ManagementPageTest.changed(valid,10,33)));
            var large=ManagementPage.split(ManagementPage.Kind.REVOCATION,op(1),GROUP,new byte[65537],32).get(0);
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(ManagementPageTest.changed(large,2,kind.number())));
            assertThrows(IllegalArgumentException.class,()->ManagementPage.split(kind,op(1),GROUP,new byte[65537],32));
            assertThrows(IllegalArgumentException.class,()->ManagementPage.split(kind,op(1),GROUP,new byte[1],33));
        }
        assertEquals(0,resources.active());
    }
    @Test void anActiveRosterReturnsToPendingAndRevocationUsesItsSlot(){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();sender.rotating(true);
        offer(ManagementPage.Kind.REVOCATION,2,1);clock.now=1000;sender.poll();
        assertEquals(ManagementPage.Kind.REVOCATION,sent.get(sent.size()-1).kind());ack(sent.get(sent.size()-1));
        assertEquals(0,sender.active());clock.now=31000;sender.poll();assertEquals(0,sender.failed());
        sender.rotating(false);sender.poll();assertEquals(1,sender.active());
    }
    @Test void completionDoesNotPromoteABlockedRosterAndItsOriginalDeadlineIsKept(){
        offer(ManagementPage.Kind.REVOCATION,1,1);offer(ManagementPage.Kind.ROSTER,2,2048);
        sender.rotating(true);sender.poll();ack(sent.get(0));assertEquals(0,sender.active());
        clock.now=31000;sender.poll();assertEquals(0,sender.failed());
        clock.now=240000;sender.rotating(false);sender.poll();assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());
    }
    @Test void rollingBackTheBudgetPreservesCountsAndRecoversAfterOneSecond(){
        clock.now=600000;assertTrue(budget.tryTake(peer(1),4));clock.now=0;
        assertFalse(budget.tryTake(peer(1),1));clock.now=999;assertFalse(budget.tryTake(peer(1),1));
        clock.now=1000;assertTrue(budget.tryTake(peer(1),4));
    }
    @Test void returningTwoActiveRostersMayKeepThirtyFourPeersButCannotAdmitAnother(){
        for(int i=1;i<=2;i++)assertEquals(ManagementPageSender.Offer.ACCEPTED,
                sender.offer(peer(i),SESSION,1,ManagementPage.Kind.ROSTER,op(i),new byte[2048],0,false));
        sender.poll();assertEquals(2,sender.active());
        for(int i=3;i<=34;i++)assertEquals(ManagementPageSender.Offer.ACCEPTED,
                sender.offer(peer(i),SESSION,1,ManagementPage.Kind.ROSTER,op(i),new byte[2048],0,false));
        assertEquals(32,sender.pendingPeers());long held=sender.heldBytes();sender.rotating(true);
        assertEquals(0,sender.active());assertEquals(34,sender.pendingPeers());assertEquals(held,sender.heldBytes());
        assertEquals(ManagementPageSender.Offer.BUSY,
                sender.offer(peer(35),SESSION,1,ManagementPage.Kind.REVOCATION,op(35),new byte[1],0,false));
        clock.now=240000;sender.poll();assertEquals(0,sender.pendingPeers());assertEquals(0,sender.heldBytes());
    }
}
