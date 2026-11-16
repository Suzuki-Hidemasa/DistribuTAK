// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementPageSenderTest.*;

class FinalManagementNoticeTest {
    final Time clock=new Time();
    final ManagementSendBudget budget=new ManagementSendBudget(clock);
    final List<byte[]> frames=new ArrayList<>();
    int closes;
    boolean canSend=true;
    final FinalManagementNotice.Port port=new FinalManagementNotice.Port(){
        public boolean send(byte[] bytes){frames.add(bytes);return canSend;}
        public void close(){closes++;}
    };
    AdminRecords.Record record(int count){
        var members=new ArrayList<byte[]>();for(int i=0;i<count;i++){byte[] b=new byte[32];b[30]=(byte)(i>>>8);b[31]=(byte)i;members.add(b);}
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,Long.MAX_VALUE,Long.MAX_VALUE,members,new byte[32]);
    }
    FinalManagementNotice notice(AdminRecords.Record record){return new FinalManagementNotice(peer(1),GROUP,op(1),record,clock,budget,port);}
    @Test void oneHundredFourteenEntriesSendExactlyTheInnerRecordAndOneHundredFifteenDoNotSend(){
        var record=record(114);assertEquals(4066,record.encode().length);var notice=notice(record);notice.poll();
        assertEquals(FinalManagementNotice.Outcome.SENT,notice.outcome());assertEquals(4,frames.size());
        var bytes=new ByteArrayOutputStream();for(var frame:frames){var page=ManagementPage.decodeEnvelope(frame);
            assertEquals(ManagementPage.Kind.REVOCATION,page.kind());assertEquals(114,page.totalEntries());bytes.writeBytes(page.data());}
        assertArrayEquals(record.encode(),bytes.toByteArray());
        clock.now=1000;notice.poll();assertEquals(1,closes);frames.clear();
        var larger=record(115);assertEquals(4100,larger.encode().length);var next=notice(larger);next.poll();
        assertEquals(FinalManagementNotice.Outcome.INCOMPLETE,next.outcome());assertTrue(frames.isEmpty());
    }
    @Test void bothPeerAndGlobalBudgetsMustHaveFourSlotsAvailable(){
        assertTrue(budget.tryTake(peer(1),1));var first=notice(record(114));first.poll();assertTrue(frames.isEmpty());
        assertEquals(FinalManagementNotice.Outcome.INCOMPLETE,first.outcome());
        clock.now=1000;first.poll();for(int i=2;i<=8;i++)assertTrue(budget.tryTake(peer(i),4));
        assertTrue(budget.tryTake(peer(9),1));var second=notice(record(114));second.poll();
        assertTrue(frames.isEmpty());assertEquals(FinalManagementNotice.Outcome.INCOMPLETE,second.outcome());
    }
    @Test void receptionNeverSendsAckAndThePortIsDestroyedOnceAtOneSecond(){
        var notice=notice(record(114));notice.receive(new byte[]{1});assertTrue(frames.isEmpty());notice.poll();
        assertEquals(4,frames.size());clock.now=999;notice.poll();notice.receive(new byte[]{1});assertEquals(0,closes);
        clock.now=1000;notice.receive(new byte[]{1});assertEquals(1,closes);assertTrue(notice.closed());
        clock.now=2000;notice.poll();notice.close();assertEquals(1,closes);assertEquals(4,frames.size());
    }
    @Test void failedSendingAndMissingPagesDoNotProveDeliveryAndNeverTriggerRetries(){
        canSend=false;var notice=notice(record(114));notice.poll();assertEquals(FinalManagementNotice.Outcome.INCOMPLETE,notice.outcome());
        clock.now=999;notice.poll();assertEquals(4,frames.size());
        var resources=new io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources();
        var receiver=new ManagementPageAssembler(GROUP,clock,resources);
        for(int i=0;i<3;i++)assertNotEquals(ManagementPageAssembler.Status.COMPLETE,
                receiver.receive(peer(1),SESSION,1,ManagementPage.decodeEnvelope(frames.get(i))).status());
        assertEquals(1,receiver.active());assertEquals(4,frames.size());
    }
    @Test void otherRecordKindsAreNeverAllowedIntoTheFinalSlot(){
        var admin=AdminRecords.list(AdminRecords.Kind.ADMINS,GROUP,1,1,List.of(Crypto.ed25519Public(new byte[32])),new byte[32]);
        assertThrows(IllegalArgumentException.class,()->notice(admin));assertTrue(frames.isEmpty());
    }
    @Test void aSendThatConsumesTheRemainingTimeClosesThePortBeforePollReturns(){
        var slowPort=new FinalManagementNotice.Port(){
            public boolean send(byte[] bytes){frames.add(bytes);clock.now=1000;return true;}
            public void close(){closes++;}
        };
        var notice=new FinalManagementNotice(peer(1),GROUP,op(1),record(1),clock,budget,slowPort);
        notice.poll();assertTrue(notice.closed());assertEquals(1,closes);assertEquals(1,frames.size());
    }
}
