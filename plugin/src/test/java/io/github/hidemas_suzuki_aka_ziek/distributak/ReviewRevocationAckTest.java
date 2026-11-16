// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class ReviewRevocationAckTest {
    private static ManagementPage page(RecoveryTransportTest.Pair p,AdminRecords.Record body,int operation){
        byte[] id=new byte[16];id[0]=(byte)operation;
        return ManagementPage.split(ManagementPage.Kind.REVOCATION,id,p.a.groupId,body.encode(),body.entries().size()).get(0);
    }
    private static void receive(RecoveryTransportTest.Pair p,ManagementPage page){
        assertTrue(p.receiver.receive(p.b.id(),p.sa.sessionId(p.b.id()),page.envelope()));
    }
    private static void assertComplete(RecoveryTransportTest.Pair p){
        assertEquals(1,p.requestWire.sent.size());assertTrue(ManagementPageAck.decodeEnvelope(p.requestWire.sent.get(0)).complete());
    }
    @Test public void olderListWithoutNewSubjectsIsRejectedIncludingRetransmission()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            receive(p,page(p,p.body(2,List.of(p.subject)),1));p.requestWire.sent.clear();
            var old=page(p,p.body(1,List.of()),2);receive(p,old);
            assertTrue(p.requestWire.sent.isEmpty());receive(p,old);
            assertTrue(p.requestWire.sent.isEmpty());assertEquals(1,p.saves);assertEquals(2,p.a.state.revocations().version());
        }
    }
    @Test public void sameVersionDifferentSignedContentIsNotAnExactMatch()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            receive(p,page(p,p.body(2,List.of(p.subject)),1));p.requestWire.sent.clear();
            var other=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,p.a.groupId,2,StorageGroupTest.NOW-1,List.of(p.subject),p.a.administratorSecret);
            receive(p,page(p,other,2));assertTrue(p.requestWire.sent.isEmpty());assertEquals(1,p.saves);
        }
    }
    @Test public void exactSavedListWithAnotherOperationAcknowledgesWithoutSaving()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var body=p.body(2,List.of(p.subject));receive(p,page(p,body,1));p.requestWire.sent.clear();
            var duplicate=page(p,body,2);receive(p,duplicate);assertComplete(p);assertEquals(1,p.saves);
            p.requestWire.sent.clear();receive(p,duplicate);assertComplete(p);assertEquals(1,p.saves);
        }
    }
    @Test public void losingListThatGrowsUnionIsSavedAndAcknowledged()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            var winner=p.body(3,List.of(p.subject));receive(p,page(p,winner,1));p.requestWire.sent.clear();
            var extra=StoredUpdatesTest.key(82);var losing=p.body(2,List.of(extra));
            receive(p,page(p,losing,2));assertComplete(p);assertEquals(2,p.saves);
            assertTrue(Arrays.equals(winner.encode(),p.a.state.revocations().encode()));
            assertTrue(p.ca.isRevoked(p.subject));assertTrue(p.ca.isRevoked(extra));
            assertEquals(2,p.a.state.revokedSubjects().size());
            assertTrue(p.a.state.snapshot().records().stream().anyMatch(record->Arrays.equals(losing.encode(),record)));
        }
    }
    @Test public void recoveryListMissingSavedUnionNeverAcknowledgesCompletion()throws Exception{
        try(var p=new RecoveryTransportTest.Pair()){
            var request=RevocationsRecoveryRequest.decodeEnvelope(p.request());p.requestWire.sent.clear();
            var body=p.body(3,List.of());
            var missing=ManagementPage.split(ManagementPage.Kind.REVOCATION,request.operationId(),p.a.groupId,body.encode(),0).get(0);
            receive(p,missing);assertTrue(p.requestWire.sent.isEmpty());assertEquals(0,p.saves);
            assertEquals(CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS,p.ca.state());
        }
    }
    @Test public void failedStalePersistenceCannotConfirmEvenIfStateIsRunning()throws Exception{
        try(var p=new RecoveryTransportTest.Pair(false)){
            p.duringSave=()->{
                try{
                    var operation=CorePersistenceCoordinator.class.getDeclaredField("operation");operation.setAccessible(true);operation.setLong(p.ca,operation.getLong(p.ca)+1);
                    var state=CorePersistenceCoordinator.class.getDeclaredField("state");state.setAccessible(true);state.set(p.ca,CorePersistenceCoordinator.State.RUNNING);
                }catch(ReflectiveOperationException failure){throw new AssertionError(failure);}
                throw new IllegalStateException("test stale persistence");
            };
            var failed=page(p,p.body(2,List.of(p.subject)),1);receive(p,failed);
            assertTrue(p.requestWire.sent.isEmpty());receive(p,failed);assertTrue(p.requestWire.sent.isEmpty());
        }
    }
}
