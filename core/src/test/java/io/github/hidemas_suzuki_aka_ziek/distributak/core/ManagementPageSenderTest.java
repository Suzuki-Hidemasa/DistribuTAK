// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ManagementPageSenderTest {
    static final byte[] GROUP=new byte[32],SESSION=new byte[16];
    static byte[] peer(int n){byte[] b=new byte[32];b[0]=(byte)n;return b;}
    static byte[] op(int n){byte[] b=new byte[16];b[0]=(byte)n;return b;}
    static class Time extends Clock {
        long now;
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(now);}
        public long millis(){return now;}
    }
    record Frame(long time,byte[] peer,byte[] data) {}
    final Time clock=new Time();
    final ManagementSendBudget budget=new ManagementSendBudget(clock);
    final List<Frame> frames=new ArrayList<>();
    final ManagementPageSender sender=new ManagementPageSender(GROUP,clock,budget,(p,s,d)->{frames.add(new Frame(clock.now,p,d));return true;});
    ManagementPageSender.Offer offer(int peer,int operation,ManagementPage.Kind kind,int bytes,int entries,boolean notice){
        return sender.offer(peer(peer),SESSION,7,kind,op(operation),new byte[bytes],entries,notice);
    }
    void ack(Frame frame,long generation){
        var page=ManagementPage.decodeEnvelope(frame.data());
        sender.acknowledge(frame.peer(),SESSION,generation,new ManagementPageAck(GROUP,page.operationId(),page.objectDigest(),new int[]{page.pageIndex()}));
    }
    @Test void slidingBudgetReservesAtomicallyAndCountsTheExactOneSecondBoundary(){
        assertTrue(budget.tryTake(peer(1),3));assertFalse(budget.tryTake(peer(1),2));assertTrue(budget.tryTake(peer(1),1));
        for(int i=2;i<=8;i++)assertTrue(budget.tryTake(peer(i),4));
        assertFalse(budget.tryTake(peer(9),1));clock.now=999;assertFalse(budget.tryTake(peer(1),1));
        clock.now=1000;assertTrue(budget.tryTake(peer(1),4));
    }
    @Test void fourPageWindowAndAckGenerationControlWhatCanBeSent(){
        assertEquals(ManagementPageSender.Offer.ACCEPTED,offer(1,1,ManagementPage.Kind.REVOCATION,8192,0,false));
        sender.poll();assertEquals(4,frames.size());
        ack(frames.get(0),8);clock.now=1000;sender.poll();assertEquals(8,frames.size());
        assertEquals(0,ManagementPage.decodeEnvelope(frames.get(4).data()).pageIndex());
        for(int i=0;i<4;i++)ack(frames.get(i),7);
        clock.now=2000;sender.poll();assertEquals(12,frames.size());
        for(int i=8;i<12;i++)assertTrue(ManagementPage.decodeEnvelope(frames.get(i).data()).pageIndex()>=4);
    }
    @Test void acknowledgementUsesTheSendingEndpointsOwnBudget(){
        var page=ManagementPage.split(ManagementPage.Kind.ROSTER,op(1),GROUP,new byte[1024],1).get(0);
        var ack=new ManagementPageAck(GROUP,op(1),page.objectDigest(),new int[]{0});
        assertTrue(sender.sendAck(peer(1),SESSION,ack));
        offer(1,2,ManagementPage.Kind.REVOCATION,4096,0,false);sender.poll();assertEquals(4,frames.size());
        assertFalse(sender.sendAck(peer(1),SESSION,ack));
        var other=new ManagementSendBudget(clock);assertTrue(other.tryTake(peer(1),4));
    }
    @Test void retriesStopAfterThreeAndAckedPagesNeverRepeat(){
        offer(1,1,ManagementPage.Kind.REVOCATION,2048,0,false);sender.poll();ack(frames.get(0),7);
        clock.now=999;sender.poll();assertEquals(2,frames.size());
        for(int i=1;i<=4;i++){clock.now=i*1000;sender.poll();}
        assertEquals(5,frames.size());assertEquals(1,sender.failed());assertEquals(0,sender.active());
        for(int i=2;i<5;i++)assertEquals(1,ManagementPage.decodeEnvelope(frames.get(i).data()).pageIndex());
    }
    @Test void noticesHaveThreeRoundsAtZeroFiveAndFifteenSeconds(){
        offer(1,1,ManagementPage.Kind.REVOCATION,1,0,true);
        for(int i=0;i<=20;i++){clock.now=i*1000;sender.poll();}
        assertEquals(List.of(0L,1000L,2000L,3000L,5000L,6000L,7000L,8000L,15000L,16000L,17000L,18000L),
                frames.stream().map(Frame::time).toList());
        assertEquals(1,sender.failed());
    }
    @Test void priorityRotationAndBatchCompletionControlTheQueue(){
        offer(1,3,ManagementPage.Kind.ROSTER,2048,2,false);
        offer(1,2,ManagementPage.Kind.ANNOUNCEMENT,1,0,false);
        offer(1,1,ManagementPage.Kind.REVOCATION,1,0,false);
        assertEquals(ManagementPageSender.Offer.PEER_BUSY,offer(1,4,ManagementPage.Kind.ROSTER,1,1,false));
        sender.rotating(true);sender.poll();assertEquals(ManagementPage.Kind.REVOCATION,ManagementPage.decodeEnvelope(frames.get(0).data()).kind());
        ack(frames.get(0),7);sender.poll();assertEquals(ManagementPage.Kind.ANNOUNCEMENT,ManagementPage.decodeEnvelope(frames.get(1).data()).kind());
        ack(frames.get(1),7);sender.poll();assertEquals(2,frames.size());
        sender.rotating(false);clock.now=1000;sender.poll();assertEquals(4,frames.size());
        ack(frames.get(2),7);ack(frames.get(3),7);sender.poll();assertEquals(3,sender.completed());
        assertEquals(ManagementPageSender.Offer.ACCEPTED,offer(1,4,ManagementPage.Kind.ROSTER,1,1,false));
        assertEquals(ManagementPageSender.Offer.INVALID,offer(2,5,ManagementPage.Kind.ROSTER,1,33,false));
    }
    @Test void twoActiveAndThirtyTwoPendingPeersAreTheLimit(){
        offer(1,1,ManagementPage.Kind.REVOCATION,1,0,false);offer(2,2,ManagementPage.Kind.REVOCATION,1,0,false);sender.poll();
        assertEquals(2,sender.active());
        for(int i=3;i<=34;i++)assertEquals(ManagementPageSender.Offer.ACCEPTED,offer(i,i,ManagementPage.Kind.REVOCATION,1,0,false));
        assertEquals(32,sender.pendingPeers());assertEquals(ManagementPageSender.Offer.FULL,offer(35,35,ManagementPage.Kind.REVOCATION,1,0,false));
    }
    @Test void deliveryPlanningRejectsFourHundredEightyOneAndTheLargestRevocationBeforeSending(){
        assertEquals(ManagementPageSender.Offer.ACCEPTED,ManagementPageSender.deliveryPlan(480));
        assertEquals(ManagementPageSender.Offer.DHT_TRANSFER_OR_INVITATION,ManagementPageSender.deliveryPlan(481));
        assertEquals(ManagementPageSender.Offer.DHT_TRANSFER_OR_INVITATION,ManagementPageSender.deliveryPlan(2177));
        assertEquals(ManagementPageSender.Offer.DHT_TRANSFER_OR_INVITATION,offer(1,1,ManagementPage.Kind.REVOCATION,2228416,65536,false));
        assertTrue(frames.isEmpty());
    }
    @Test void sixtyFourPagesWithLossAndAcknowledgementsFinishWithinTheBudgetAndDeadline(){
        var reverseBudget=new ManagementSendBudget(clock);
        var pendingAcks=new ArrayList<Frame>();
        offer(1,1,ManagementPage.Kind.REVOCATION,65536,100,false);int read=0,ackCount=0;boolean lost=false;
        for(int tick=0;tick<2400&&sender.completed()==0;tick++){
            clock.now=tick*100;sender.poll();
            while(read<frames.size()){
                Frame f=frames.get(read++);var page=ManagementPage.decodeEnvelope(f.data());
                if(page.pageIndex()==2&&!lost){lost=true;continue;}pendingAcks.add(f);
            }
            var it=pendingAcks.iterator();while(it.hasNext()){
                Frame f=it.next();if(!reverseBudget.tryTake(peer(1),1))break;ack(f,7);ackCount++;it.remove();
            }
        }
        assertEquals(1,sender.completed());assertTrue(clock.now<240000);assertTrue(frames.size()+ackCount<960);
        for(var frame:frames){
            long count=frames.stream().filter(f->f.time()>frame.time()-1000&&f.time()<=frame.time()).count();
            assertTrue(count<=4);assertTrue(count<=32);
        }
    }
    @Test void rotatingQueuedObjectsExpireAndCannotBeRevivedByPolling(){
        offer(1,1,ManagementPage.Kind.ROSTER,2048,2,false);sender.rotating(true);sender.poll();
        clock.now=240000;sender.rotating(false);sender.poll();assertTrue(frames.isEmpty());assertEquals(1,sender.failed());
        clock.now=241000;sender.poll();assertTrue(frames.isEmpty());
    }
    @Test void outgoingObjectsHaveAnIndependentEightMebibyteMemoryLimit(){
        for(int i=1;i<=17;i++)assertEquals(ManagementPageSender.Offer.ACCEPTED,offer(i,i,ManagementPage.Kind.REVOCATION,480*1024,0,false));
        assertEquals(17L*480*1024,sender.heldBytes());
        assertEquals(ManagementPageSender.Offer.BUSY,offer(18,18,ManagementPage.Kind.REVOCATION,480*1024,0,false));
        clock.now=240000;sender.poll();assertEquals(0,sender.heldBytes());assertTrue(frames.isEmpty());
    }
}
