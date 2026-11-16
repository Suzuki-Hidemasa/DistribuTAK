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
    void assertRejectedWithoutAck(ManagementPageAssembler.Result result){
        assertEquals(REJECTED,result.status());assertNull(result.ack());assertNull(result.completed());
    }
    @Test void budgetWaitPastReceiverExpiryFailsInsteadOfCompletingOnlyAtTheSender(){
        offer(ManagementPage.Kind.ROSTER,1,2048);assertTrue(budget.tryTake(peer(1),3));sender.poll();
        var firstAck=receive(sent.get(0)).ack();assertNotNull(firstAck);read=sent.size();
        for(int second=1;second<30;second++){
            clock.now=second*1000;assertTrue(budget.tryTake(peer(1),4));
            if(second==2)sender.acknowledge(peer(1),SESSION,1,firstAck);
            sender.poll();assembler.poll();
        }
        clock.now=30000;sender.poll();drain(false);
        assertEquals(0,sender.completed());assertEquals(0,receiverCompleted);assertEquals(1,rejected);
        clock.now=32000;sender.poll();assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());
        assertEquals(0,resources.active());
    }
    void boundaryWait(long firstAckDelay,long sendAt,long pageDelay,long ackDelay){
        offer(ManagementPage.Kind.ROSTER,1,8192);sender.poll();
        var acks=new ArrayList<ManagementPageAck>();
        while(read<sent.size())acks.add(receive(sent.get(read++)).ack());
        clock.now=firstAckDelay;for(var ack:acks)sender.acknowledge(peer(1),SESSION,1,ack);
        for(long at=firstAckDelay+1;at<sendAt-1100;at+=250){
            clock.now=at;budget.tryTake(peer(1),4);sender.poll();
        }
        assertEquals(4,sent.size());clock.now=sendAt;sender.poll();assertEquals(8,sent.size());
        clock.now=sendAt+pageDelay;
        while(read<sent.size())assertRejectedWithoutAck(receive(sent.get(read++)));
        clock.now=sendAt+pageDelay+ackDelay;sender.poll();
        assertEquals(0,sender.completed());assertEquals(0,receiverCompleted);
        clock.now=firstAckDelay+30000;sender.poll();
        assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());assertEquals(0,resources.active());
    }
    @Test void boundaryWithDelayedFirstAckRejectsRemainingPages(){boundaryWait(1000,30500,100,100);}
    @Test void pageInTransitAcrossReceiverDeadlineIsRejected(){boundaryWait(0,29900,200,50);}
    void delayedAckAfterExpiry(int evictionPeer){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();
        var oldAck=receive(sent.get(0)).ack();assertNotNull(oldAck);read=sent.size();
        sender.rotating(true);clock.now=31000;assembler.poll();assertEquals(0,assembler.active());
        if(evictionPeer!=0){
            // 指定した相手の対象を期限切れにして、破棄記録の上限を試す。
            // Expire targets from the specified peer to exercise the retirement limit.
            for(int i=0;i<(evictionPeer==1?8:10);i++){
                var first=pages(10+i,2048).get(0);
                assertEquals(INCOMPLETE,assembler.receive(peer(evictionPeer),SESSION,1,first).status());
                clock.now--;assembler.poll();
                if(i<7&&evictionPeer==1)assertRejectedWithoutAck(receive(sent.get(0)));
            }
        }
        sender.rotating(false);sender.poll();
        // 再開後の先頭ページを落とし、末尾ページのあとに停止前のACKを届ける。
        // Drop the resumed first page and deliver the pre-pause ACK after the tail page.
        read++;drain(false);sender.acknowledge(peer(1),SESSION,1,oldAck);
    }
    @Test void delayedPrePauseAckCannotCompleteAnExpiredRoster(){
        delayedAckAfterExpiry(0);
        assertEquals(0,sender.completed());assertEquals(0,receiverCompleted);assertEquals(1,rejected);
        clock.now=61000;sender.poll();assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());
        assertEquals(0,resources.active());
    }
    @Test void evictingEightRetiredTargetsCanAgainCompleteOnlyAtTheSender(){
        delayedAckAfterExpiry(1);
        assertEquals(1,sender.completed());assertEquals(0,receiverCompleted);assertEquals(0,sender.failed());
        assertEquals(1,assembler.active());assertEquals(2048,resources.reservedBytes());
    }
    @Test void anotherPeerCannotEvictAnExpiredRosterAndCompleteOnlyAtTheSender(){
        delayedAckAfterExpiry(2);
        assertEquals(0,sender.completed());assertEquals(0,receiverCompleted);assertEquals(1,rejected);
        clock.now=61000;sender.poll();assertEquals(1,sender.failed());assertEquals(0,resources.active());
    }
    @Test void anotherPeersFirstPagesCannotEvictAReplacedRosterDespiteAStaleAck(){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();
        var staleAck=receive(sent.get(0)).ack();assertNotNull(staleAck);read=sent.size();
        sender.rotating(true);
        assertEquals(COMPLETE,receive(pages(2,1).get(0)).status());
        for(int i=0;i<10;i++)assertEquals(INCOMPLETE,
                assembler.receive(peer(2),SESSION,1,pages(10+i,2048).get(0)).status());
        sender.rotating(false);sender.poll();read++;drain(false);
        sender.acknowledge(peer(1),SESSION,1,staleAck);
        assertEquals(0,sender.completed());assertEquals(0,receiverCompleted);assertEquals(1,rejected);
        for(var page:sent)assertRejectedWithoutAck(receive(page));
        clock.now=30000;sender.poll();assembler.poll();
        assertEquals(1,sender.failed());assertEquals(0,resources.active());
    }
    void retireByReplacement(int peerId,int operation){
        assertEquals(INCOMPLETE,assembler.receive(peer(peerId),SESSION,1,pages(operation,2048).get(0)).status());
        assertEquals(COMPLETE,assembler.receive(peer(peerId),SESSION,1,pages(100+operation,1).get(0)).status());
    }
    void assertRetired(int peerId,int operation){
        for(var page:pages(operation,2048))assertRejectedWithoutAck(assembler.receive(peer(peerId),SESSION,1,page));
    }
    @Test void ninthRetirementEvictsOnlyThatPeersOldestRecord(){
        retireByReplacement(2,1);
        for(int i=1;i<=8;i++)retireByReplacement(1,i);
        for(int i=1;i<=8;i++)assertRetired(1,i);
        retireByReplacement(1,9);
        assertRetired(2,1);for(int i=2;i<=9;i++)assertRetired(1,i);
        var oldest=pages(1,2048);
        assertEquals(INCOMPLETE,receive(oldest.get(1)).status());
        assertEquals(COMPLETE,receive(oldest.get(0)).status());assertEquals(0,resources.active());
    }
    @Test void sixtyFifthRetirementEvictsTheGlobalOldestRecord(){
        for(int peerId=1;peerId<=8;peerId++)for(int i=1;i<=8;i++)retireByReplacement(peerId,i);
        for(int peerId=1;peerId<=8;peerId++)for(int i=1;i<=8;i++)assertRetired(peerId,i);
        retireByReplacement(9,1);
        assertRetired(9,1);
        for(int peerId=1;peerId<=8;peerId++)for(int i=1;i<=8;i++)if(peerId!=1||i!=1)assertRetired(peerId,i);
        var oldest=pages(1,2048);
        assertEquals(INCOMPLETE,receive(oldest.get(1)).status());
        assertEquals(COMPLETE,receive(oldest.get(0)).status());assertEquals(0,resources.active());
    }
    @Test void expiredTargetIsRejectedUntilRetentionEndsButNewOperationCanComplete(){
        var old=pages(1,2048);receive(old.get(0));clock.now=30000;assembler.poll();
        assertEquals(0,resources.reservedBytes());
        for(var page:old)assertRejectedWithoutAck(receive(page));
        var next=pages(2,2048);assertEquals(INCOMPLETE,receive(next.get(0)).status());
        assertEquals(COMPLETE,receive(next.get(1)).status());
        clock.now=269999;assertRejectedWithoutAck(receive(old.get(1)));
        clock.now=270000;assertEquals(INCOMPLETE,receive(old.get(1)).status());
        assertEquals(COMPLETE,receive(old.get(0)).status());assertEquals(0,resources.active());
    }
    @Test void rollbackRetiresTheAssemblyAndKeepsItRejectedForTwoHundredFortySeconds(){
        clock.now=1000;var old=pages(1,2048);receive(old.get(0));clock.now=999;assembler.poll();
        assertEquals(0,resources.reservedBytes());
        for(var page:old)assertRejectedWithoutAck(receive(page));
        assertEquals(COMPLETE,receive(pages(2,1).get(0)).status());
        clock.now=240998;assertRejectedWithoutAck(receive(old.get(1)));
        clock.now=240999;assertEquals(INCOMPLETE,receive(old.get(1)).status());
    }
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
    @Test void resumedRosterFailsAfterTheReceiverAssemblyExpires(){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();drain(true);
        sender.rotating(true);ack(sent.get(1));assertEquals(0,sender.completed());
        clock.now=31000;assembler.poll();assertEquals(0,assembler.active());
        sender.rotating(false);sender.poll();drain(false);
        assertEquals(0,sender.completed());assertEquals(0,receiverCompleted);assertEquals(0,rostersCompleted);
        assertEquals(2,rejected);clock.now=61000;sender.poll();
        assertEquals(1,sender.failed());assertEquals(0,sender.heldBytes());assertEquals(0,assembler.active());
    }
    @Test void matchingDuplicateKeepsAssemblyAliveUntilTheNextNewPage(){
        var all=pages(1,3072);assertEquals(INCOMPLETE,receive(all.get(0)).status());
        clock.now=29000;var duplicate=receive(all.get(0));
        assertEquals(DUPLICATE,duplicate.status());assertNotNull(duplicate.ack());assertNull(duplicate.completed());
        clock.now=58000;assertEquals(INCOMPLETE,receive(all.get(1)).status());
        var complete=receive(all.get(2));assertEquals(COMPLETE,complete.status());
        assertArrayEquals(new byte[3072],complete.completed().data());assertEquals(0,resources.active());
    }
    @Test void matchingDuplicatesDoNotExtendTheOriginalTotalDeadline(){
        var all=pages(1,2048);assertEquals(INCOMPLETE,receive(all.get(0)).status());
        for(int i=1;i<=8;i++){
            clock.now=i*29000;assertEquals(DUPLICATE,receive(all.get(0)).status());
            assertEquals(1,assembler.active());assertEquals(2048,resources.reservedBytes());
        }
        clock.now=239999;assertEquals(DUPLICATE,receive(all.get(0)).status());
        assertEquals(1,assembler.active());clock.now=240000;assembler.poll();
        assertEquals(0,assembler.active());assertEquals(0,resources.reservedBytes());
        assertRejectedWithoutAck(receive(all.get(1)));
    }
    @Test void resumedRosterCompletesAtBothEndsAfterOverThirtySecondsOfDuplicates(){
        offer(ManagementPage.Kind.ROSTER,1,65536);
        for(int i=0;i<12;i++){clock.now=i*1000;sender.poll();drain(false);}
        assertEquals(48,sent.size());assertEquals(1,assembler.active());assertEquals(0,receiverCompleted);
        sender.rotating(true);clock.now=12000;sender.rotating(false);
        int duplicates=0;long firstDuplicate=-1,lastDuplicate=-1;
        // 共有枠の他の送信で毎秒3件を使い、名簿は毎秒1ページだけ送り直す。
        // Consume three sends each second from the shared budget, leaving one roster page per second.
        for(int i=0;i<64;i++){
            clock.now=12000+i*1000;assertTrue(budget.tryTake(peer(1),3));sender.poll();
            while(read<sent.size()){
                var page=sent.get(read++);var result=receive(page);
                if(result.status()==DUPLICATE){
                    duplicates++;if(firstDuplicate<0)firstDuplicate=clock.now;lastDuplicate=clock.now;
                }
                if(result.completed()!=null){receiverCompleted++;rostersCompleted++;}
                if(result.ack()!=null)sender.acknowledge(peer(1),SESSION,1,result.ack());
            }
        }
        assertEquals(1,sender.completed());
        assertEquals(1,receiverCompleted,"sender completed="+sender.completed()+", receiver completed="+receiverCompleted);
        assertEquals(1,rostersCompleted);assertEquals(48,duplicates);assertTrue(lastDuplicate-firstDuplicate>30000);
        assertEquals(0,sender.failed());assertEquals(0,sender.heldBytes());assertEquals(0,resources.active());
    }
    @Test void resumedCompletedRosterUsesDuplicateAcksWithoutDeliveringAgain(){
        offer(ManagementPage.Kind.ROSTER,1,2048);sender.poll();
        // 完成まで受信するが、停止前のACKはすべて落とす。
        // Receive through completion but drop every ACK before pausing.
        while(read<sent.size()){
            var result=receive(sent.get(read++));assertNotNull(result.ack());
            if(result.completed()!=null)receiverCompleted++;
        }
        assertEquals(1,receiverCompleted);assertEquals(0,sender.completed());assertEquals(0,assembler.active());
        sender.rotating(true);clock.now=1000;sender.rotating(false);sender.poll();
        int duplicates=0;
        while(read<sent.size()){
            var result=receive(sent.get(read++));assertEquals(DUPLICATE,result.status());
            assertNull(result.completed());assertNotNull(result.ack());duplicates++;
            sender.acknowledge(peer(1),SESSION,1,result.ack());
        }
        assertEquals(2,duplicates);assertEquals(1,sender.completed());assertEquals(1,receiverCompleted);
        assertEquals(0,sender.failed());assertEquals(0,sender.heldBytes());assertEquals(0,resources.reservedBytes());
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
        sender.rotating(true);clock.now=4000;assembler.poll();sender.rotating(false);sender.poll();drain(true);
        clock.now=5000;sender.poll();drain(false);
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
        clock.now=33999;assertEquals(REJECTED,receive(a.get(0)).status());
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
