// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class NormalRevocationTransportTest {
    private static List<ManagementPage> pages(RecoveryTransportTest.Pair p,long version,int operation){
        byte[] id=new byte[16];id[0]=(byte)operation;
        var body=p.body(version,List.of(p.subject));
        return ManagementPage.split(ManagementPage.Kind.REVOCATION,id,p.a.groupId,body.encode(),1);
    }
    private static void receive(RecoveryTransportTest.Pair p,ManagementPage page){
        assertTrue(p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope()));
    }
    @Test public void normalPageSavesBeforeCompleteAckAndRetainsOldSession()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            byte[] session=p.sa.sessionId(p.b.id());
            p.duringSave=()->{assertEquals(CorePersistenceCoordinator.State.PERSISTING,p.ca.state());assertTrue(p.requestWire.sent.isEmpty());};
            receive(p,pages(p,2,1).get(0));
            assertEquals(1,p.saves);assertArrayEquals(session,p.sa.sessionId(p.b.id()));
            assertTrue(ManagementPageAck.decodeEnvelope(p.requestWire.sent.get(0)).complete());
            assertTrue(p.ca.isRevoked(p.subject));
        }
    }
    @Test public void lostNormalCompletionAckOnlyResendsAck()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var page=pages(p,2,1).get(0);receive(p,page);p.requestWire.sent.clear();receive(p,page);
            assertEquals(1,p.saves);assertEquals(1,p.requestWire.sent.size());assertTrue(ManagementPageAck.decodeEnvelope(p.requestWire.sent.get(0)).complete());
        }
    }
    @Test public void lostRecoveryCompletionAckSurvivesSwitchToRunning()throws Exception{
        try(var p=new RecoveryTransportTest.Pair()){
            var request=RevocationsRecoveryRequest.decodeEnvelope(p.request());var body=p.body(2,List.of(p.subject));
            var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,request.operationId(),p.a.groupId,body.encode(),1).get(0);
            receive(p,page);p.requestWire.sent.clear();receive(p,page);
            assertEquals(1,p.saves);assertEquals(1,p.requestWire.sent.size());assertTrue(ManagementPageAck.decodeEnvelope(p.requestWire.sent.get(0)).complete());
        }
    }
    @Test public void failedSaveNeverProducesCompletionAck()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            p.duringSave=()->{throw new IllegalStateException("test persistence failure");};receive(p,pages(p,2,1).get(0));
            assertEquals(CorePersistenceCoordinator.State.STORAGE_FAILED,p.ca.state());assertTrue(p.requestWire.sent.isEmpty());assertEquals("保存がいっぱい",p.ca.statusText());
        }
    }
    @Test public void invalidSignatureNeverSavesOrAcknowledgesCompletion()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var body=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,2,StorageGroupTest.NOW,List.of(p.subject),StoredUpdatesTest.key(83));
            receive(p,ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],p.a.groupId,body.encode(),1).get(0));
            assertEquals(0,p.saves);assertTrue(p.requestWire.sent.isEmpty());
        }
    }
    @Test public void savedDuplicateWithNewOperationDoesNotWriteAgain()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            receive(p,pages(p,2,1).get(0));p.requestWire.sent.clear();receive(p,pages(p,2,2).get(0));
            assertEquals(1,p.saves);assertTrue(ManagementPageAck.decodeEnvelope(p.requestWire.sent.get(0)).complete());
        }
    }
    @Test public void bufferedPageExpiresAtThirtySecondsWithoutSaving()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            p.time.now=30_000;
            assertTrue(p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),pages(p,2,1).get(0).envelope(),0));
            assertEquals(0,p.saves);assertTrue(p.requestWire.sent.isEmpty());
        }
    }
    @Test public void bufferedPageBeforeDeadlineCanStillSave()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            p.time.now=29_999;
            assertTrue(p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),pages(p,2,1).get(0).envelope(),0));assertEquals(1,p.saves);
        }
    }
    @Test public void normalPollingNeverGeneratesRecoveryRequest()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){p.receiver.poll(List.of(p.b.id()));assertTrue(p.requestWire.sent.isEmpty());}
    }
    @Test public void sessionReplacementForgetsIncompleteAssembly()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var subjects=new ArrayList<byte[]>();for(int i=1;i<=40;i++){byte[] id=new byte[32];id[0]=(byte)i;subjects.add(id);}
            var body=p.body(2,subjects);var pages=ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],p.a.groupId,body.encode(),40);
            receive(p,pages.get(0));assertEquals(0,p.saves);
            var second=p.sb.receive(p.sa.start(p.b.id()).packet());var confirm=p.sa.receive(second.outbound().get(0).packet());p.sb.receive(confirm.outbound().get(0).packet());
            p.requestWire.sent.clear();for(var page:pages)receive(p,page);assertEquals(1,p.saves);
        }
    }
    @Test public void persistingOnlyAuthenticatesExistingRevocationData()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            byte[] page=pages(p,2,1).get(0).envelope();byte[] packet=p.sb.send(p.a.id(),page).get(0).packet();
            p.ca.saveUnchanged(()->{
                var received=p.sa.receive(packet);assertArrayEquals(page,received.plaintext());Crypto.wipe(received.plaintext());
                assertThrows(RuntimeException.class,()->p.sa.receive(packet));
                assertThrows(RuntimeException.class,()->p.sa.start(p.b.id()));
                assertThrows(RuntimeException.class,()->p.sa.receive(p.sb.send(p.a.id(),new byte[]{1,2,3}).get(0).packet()));
            });
        }
    }
    @Test public void persistingDoesNotDispatchAckOrRecoveryRequests()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var page=pages(p,2,1).get(0);
            var ack=new ManagementPageAck(p.a.groupId,page.operationId(),page.objectDigest(),new int[]{0},true);
            byte[] encrypted=p.sb.send(p.a.id(),ack.envelope()).get(0).packet();
            p.ca.saveUnchanged(()->assertThrows(RuntimeException.class,()->p.sa.receive(encrypted)));
        }
    }
    @Test public void normalCompletionAckReleasesSharedSender()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            p.b.state.acceptRevocations(p.body(2,List.of(p.subject)));
            assertEquals(ManagementPageSender.Offer.ACCEPTED,p.responder.offerRevocations(p.a.id()));p.responder.poll(List.of());
            assertEquals(1,p.responseWire.sent.size());receive(p,ManagementPage.decodeEnvelope(p.responseWire.sent.get(0)));
            p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),p.requestWire.sent.get(0));
            var sender=(ManagementPageSender)LanControllerHarness.field(p.responder,"sender");assertEquals(0,sender.active());assertEquals(1,sender.completed());
        }
    }

    @Test public void normalAndRecoveryShareOperationIssuer()throws Exception{
        try(var p=new RecoveryTransportTest.Pair()){
            var request=RevocationsRecoveryRequest.decodeEnvelope(p.request());var body=p.body(2,List.of(p.subject));
            receive(p,ManagementPage.split(ManagementPage.Kind.REVOCATION,request.operationId(),p.a.groupId,body.encode(),1).get(0));
            assertEquals(ManagementPageSender.Offer.ACCEPTED,p.receiver.offerRevocations(p.b.id()));p.receiver.poll(List.of());
            byte[] last=p.requestWire.sent.get(p.requestWire.sent.size()-1);
            assertFalse(Arrays.equals(request.operationId(),ManagementPage.decodeEnvelope(last).operationId()));
        }
    }
    @Test public void closedSessionReleasesOutgoingPagesAtPoll()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            p.b.state.acceptRevocations(p.body(2,List.of(p.subject)));p.responder.offerRevocations(p.a.id());p.responder.poll(List.of());
            var sender=(ManagementPageSender)LanControllerHarness.field(p.responder,"sender");assertTrue(sender.heldBytes()>0);
            p.sb.close();p.responder.poll(List.of());assertEquals(0,sender.heldBytes());
        }
    }
    @Test public void secondRevocationCanAuthenticateDuringFirstReceivedSave()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var queue=new SyncInbox();var second=pages(p,3,2).get(0);byte[] encrypted=p.sb.send(p.a.id(),second.envelope()).get(0).packet();
            p.duringSave=()->{
                try(var received=p.sa.receive(encrypted)){
                    byte[] plain=received.plaintext();try{assertTrue(queue.offer(1,p.b.id(),received.sessionId(),plain,p.time.now));}finally{Crypto.wipe(plain);}
                    assertEquals(1,p.saves);assertEquals(1,queue.size());
                }
            };
            receive(p,pages(p,2,1).get(0));p.duringSave=()->{};
            var packet=queue.take();try(packet){assertTrue(p.receiver.receive(packet.peer,packet.session,packet.wire,packet.receivedAt));}
            assertEquals(2,p.saves);assertArrayEquals(new byte[packet.wire.length],packet.wire);
        }
    }

    @Test public void queuedAckDoesNotRefreshSenderProgressAtProcessingTime()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var subjects=new ArrayList<byte[]>();for(int i=1;i<=40;i++){byte[] id=new byte[32];id[0]=(byte)i;subjects.add(id);}
            p.b.state.acceptRevocations(p.body(2,subjects));p.responder.offerRevocations(p.a.id());p.responder.poll(List.of());
            receive(p,ManagementPage.decodeEnvelope(p.responseWire.sent.get(0)));byte[] ack=p.requestWire.sent.get(0);
            p.time.now=20_000;p.responder.receive(p.a.id(),p.sb.sessionId(p.a.id()),ack,1_000);
            p.time.now=31_000;p.responder.poll(List.of());
            var sender=(ManagementPageSender)LanControllerHarness.field(p.responder,"sender");assertEquals(0,sender.heldBytes());
        }
    }

}
