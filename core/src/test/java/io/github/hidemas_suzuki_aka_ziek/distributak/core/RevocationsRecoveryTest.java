// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class RevocationsRecoveryTest {
    final CorePersistenceCoordinatorTest t=new CorePersistenceCoordinatorTest();
    final SessionManagerTest f=t.f;
    final byte[] target=key(60),operation=new byte[16];
    RecoveryRequirement requirement(){return new RecoveryRequirement(1,revocationDigest(List.of(target)),List.of(target));}
    CorePersistenceCoordinator recovering(SessionManagerTest.Node a,RecoveryRequirement requirement){
        return new CorePersistenceCoordinator(a.state,a.sessions,t.union(a),f.time,t.deadlines(),requirement);
    }
    RevocationsRecoveryRequest request(){return new RevocationsRecoveryRequest(f.group,operation,1,revocationDigest(List.of(target)));}
    void bind(CorePersistenceCoordinator c,SessionManagerTest.Node a,SessionManagerTest.Node b){
        f.connect(a,b);assertTrue(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),request()));
    }
    ManagementPageAssembler.Result deliver(CorePersistenceCoordinator c,SessionManagerTest.Node a,SessionManagerTest.Node b,
            AdminRecords.Record r,PersistenceHooks hooks){
        ManagementPageAssembler.Result result=null;
        for(var page:ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,f.group,r.encode(),r.entries().size()))
            result=c.receiveRecoveryPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,hooks);
        return result;
    }
    @Test void u1AllowsOnlyHandshakeRequestRevocationPagesAndAck(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());
            for(var op:Operation.values())assertEquals(Set.of(Operation.HANDSHAKE,Operation.RECOVERY_REQUEST,Operation.REVOCATION_PAGE,Operation.PAGE_ACK).contains(op),c.permits(op),op.name());
            bind(c,a,b);assertEquals("保存がいっぱい",c.statusText());
            var sent=a.sessions.send(b.id,request().envelope());assertFalse(sent.isEmpty());
            assertArrayEquals(request().envelope(),b.sessions.receive(sent.get(sent.size()-1).packet()).plaintext());
            var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,operation,f.group,t.revoked(target).encode(),1).get(0);
            assertDoesNotThrow(()->a.sessions.send(b.id,page.envelope()));
            assertDoesNotThrow(()->a.sessions.send(b.id,new ManagementPageAck(f.group,operation,page.objectDigest(),new int[]{0},true).envelope()));
            assertThrows(SecurityException.class,()->a.sessions.send(b.id,new byte[]{1}));
            assertThrows(IllegalStateException.class,()->a.sessions.rotateGroupKey(key(40),1));
        }
    }
    @Test void stoppedSubjectsRejectRegistrationWithEmptySavedUnion(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,new RecoveryRequirement(1,revocationDigest(List.of(b.id)),List.of(b.id)));
            assertTrue(c.isRevoked(b.id));
            assertThrows(SecurityException.class,()->a.remember(b));
            assertFalse(c.bindRecovery(b.id,new byte[16],a.sessions.generation(),
                    new RevocationsRecoveryRequest(f.group,operation,1,revocationDigest(List.of(b.id)))));
        }
    }
    @Test void stoppedSubjectsRejectOutboundHandshakeEvenIfPreviouslyRegistered(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            a.remember(b);recovering(a,new RecoveryRequirement(1,revocationDigest(List.of(b.id)),List.of(b.id)));
            assertThrows(SecurityException.class,()->a.sessions.start(b.id));
            assertFalse(a.sessions.isEstablished(b.id));
        }
    }
    @Test void stoppedSubjectsRejectIncomingHandshakeWithEmptySavedUnion(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            a.remember(b);b.remember(a);
            recovering(a,new RecoveryRequirement(1,revocationDigest(List.of(b.id)),List.of(b.id)));
            var packet=b.sessions.start(a.id).packet();
            assertThrows(SecurityException.class,()->a.sessions.receive(packet));
            assertFalse(a.sessions.isEstablished(b.id));
        }
    }
    @Test void u1DropsCotAnnouncementsRosterAndRenewalInsteadOfStartingNormalDispatch(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);
            for(var kind:List.of(ManagementPage.Kind.ANNOUNCEMENT,ManagementPage.Kind.ROSTER,ManagementPage.Kind.ROSTER_SUMMARY)){
                var wire=ManagementPage.split(kind,operation,f.group,new byte[]{1},1).get(0).envelope();
                assertThrows(SecurityException.class,()->a.sessions.send(b.id,wire));
                var packet=b.sessions.send(a.id,wire).get(0).packet();assertThrows(SecurityException.class,()->a.sessions.receive(packet));
            }
            for(byte[] wire:List.of(new byte[]{8,1,18,0},new byte[]{8,2,74,0},ManagementWire.wrap(ManagementEnvelopeFields.CERTIFICATE_RENEWAL,new byte[]{8,1})))
                assertThrows(SecurityException.class,()->a.sessions.send(b.id,wire));
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());
        }
    }
    @Test void validSignedRecoveryPreservesSavedRAndResumesOnlyAfterClear(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);
            deliver(c,a,b,t.revoked(target),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){assertEquals(State.PERSISTING,c.state());assertFalse(c.permits(Operation.COT_SEND));}
                public void clear(AdminRecordStore.Snapshot s){assertFalse(c.permits(Operation.COT_SEND));}
            });assertEquals(State.RUNNING,c.state());assertTrue(c.isRevoked(target));
            assertArrayEquals(new byte[]{9},b.sessions.receive(f.data(a,b,9)).plaintext());
        }
    }
    @Test void recoveryRequiresVersionLowerBound(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,new RecoveryRequirement(2,revocationDigest(List.of(target)),List.of(target)));f.connect(a,b);
            var request=new RevocationsRecoveryRequest(f.group,operation,2,revocationDigest(List.of(target)));
            assertTrue(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),request));
            deliver(c,a,b,t.revoked(target),t.hooks(()->fail()));assertEquals(State.RECOVERING_REVOCATIONS,c.state());
        }
    }
    @Test void newerVersionWithoutStoppedRDoesNotRecover(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);deliver(c,a,b,t.revoked(),t.hooks(()->fail()));
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void unreconstructableStoppedRRequiresExactDigest(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,new RecoveryRequirement(1,revocationDigest(List.of(target)),null));bind(c,a,b);
            deliver(c,a,b,t.revoked(target,key(61)),t.hooks(()->fail()));assertEquals(State.RECOVERING_REVOCATIONS,c.state());
        }
    }
    @Test void exactDigestCanRecoverWithoutReconstructingStoppedSet(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,new RecoveryRequirement(1,revocationDigest(List.of(target)),null));bind(c,a,b);
            deliver(c,a,b,t.revoked(target),t.hooks(()->{}));assertEquals(State.RUNNING,c.state());
        }
    }
    @Test void recoveryCannotDropPreviouslySavedR(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            a.state.acceptRevocations(t.revoked(key(61)));var c=recovering(a,requirement());bind(c,a,b);
            var r=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(target),f.admin);
            deliver(c,a,b,r,t.hooks(()->fail()));assertEquals(State.RECOVERING_REVOCATIONS,c.state());
        }
    }
    @Test void lowerRankedResponseCannotClearStopWithUnsuitableSavedList(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin));
            var c=recovering(a,requirement());bind(c,a,b);deliver(c,a,b,t.revoked(target),t.hooks(()->fail()));
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertEquals(2,a.state.revocations().version());
        }
    }
    @Test void recoverySaveFailureKeepsStoppedState(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);
            deliver(c,a,b,t.revoked(target),t.hooks(()->{throw new IllegalStateException("test");}));
            assertEquals(State.STORAGE_FAILED,c.state());assertEquals("保存がいっぱい",c.statusText());assertTrue(a.sessions.isClosed());
        }
    }
    @Test void recoveryKeepsStorageFullStatusThroughoutSaveAndClear(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);
            deliver(c,a,b,t.revoked(target),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){assertEquals("保存がいっぱい",c.statusText());}
                public void clear(AdminRecordStore.Snapshot s){assertEquals("保存がいっぱい",c.statusText());}
            });assertEquals(State.RUNNING,c.state());assertEquals("",c.statusText());
        }
    }
    @Test void ordinaryPersistenceDoesNotShowStorageFullStatus(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);
            assertTrue(c.receiveRevocations(t.revoked(),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){assertEquals("",c.statusText());}
                public void clear(AdminRecordStore.Snapshot s){assertEquals("",c.statusText());}
            }));assertEquals("",c.statusText());
        }
    }
    @Test void recoverySaveStartedAt239SecondsCanFinishAt241Seconds(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());f.time.advance(239);bind(c,a,b);
            deliver(c,a,b,t.revoked(target),t.hooks(()->{f.time.advance(2);c.poll();}));
            assertEquals(State.RUNNING,c.state());assertEquals(1,a.state.revocations().version());
            assertTrue(c.permits(Operation.COT_SEND));
        }
    }
    @Test void recoverySaveCannotStartAt241Seconds(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);f.time.advance(241);
            assertEquals(ManagementPageAssembler.Status.REJECTED,deliver(c,a,b,t.revoked(target),t.hooks(()->fail("save reached"))).status());
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertEquals(0,a.state.revocations().version());
            assertFalse(c.permits(Operation.HANDSHAKE));
        }
    }
    @Test void rejectedRecoveryAndRequestRetryDoNotRestart240SecondDeadline(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());f.time.advance(239);bind(c,a,b);
            deliver(c,a,b,t.revoked(),t.hooks(()->fail("save reached")));
            assertTrue(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),request()));
            f.time.advance(1);assertFalse(c.permits(Operation.RECOVERY_REQUEST));
            assertFalse(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),request()));
            f.time.advance(1);assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void requestRetriesDoNotExtendGlobal240SecondDeadline(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);f.time.advance(179);
            assertTrue(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),request()));
            f.time.advance(61);c.poll();assertFalse(c.permits(Operation.HANDSHAKE));assertFalse(c.permits(Operation.REVOCATION_PAGE));
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertEquals("保存がいっぱい",c.statusText());
        }
    }
    @Test void operationsAndSessionGenerationsCannotBeMixed(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);byte[] other=new byte[16];other[0]=1;
            assertFalse(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),new RevocationsRecoveryRequest(f.group,other,1,request().targetDigest())));
            var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,other,f.group,t.revoked(target).encode(),1).get(0);
            assertEquals(ManagementPageAssembler.Status.REJECTED,c.receiveRecoveryPage(b.id,a.sessions.sessionId(b.id),a.sessions.generation(),page,t.hooks(()->fail())).status());
            assertFalse(c.bindRecovery(b.id,a.sessions.sessionId(b.id),a.sessions.generation()+1,request()));
        }
    }
    @Test void rotatedRemoteKeyMakesRecoveryImpossibleWithoutOldKeyException(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());a.remember(b);b.remember(a);b.sessions.rotateGroupKey(key(40),1);
            assertThrows(SecurityException.class,()->b.sessions.receive(a.sessions.start(b.id).packet()));
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertFalse(c.permits(Operation.KEY_APPLY));
        }
    }
    @Test void mismatchedGroupKeyCannotRecover(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());a.remember(b);
            try(var remote=new SessionManager(b.state,b.cert,b.secret,key(90),0,f.time,()->f.time.nanos,256)){
                remote.rememberPeer(a.cert);
                var second=remote.receive(a.sessions.start(b.id).packet()).outbound().get(0).packet();
                assertThrows(SecurityException.class,()->a.sessions.receive(second));
                assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertFalse(c.permits(Operation.KEY_APPLY));
            }
        }
    }
    @Test void expiredCertificateDoesNotGainRecoveryHandshakeException(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());a.remember(b);b.remember(a);f.time.millis=a.cert.expiresAt();
            assertThrows(IllegalStateException.class,()->a.sessions.start(b.id));assertEquals(State.RECOVERING_REVOCATIONS,c.state());
            assertFalse(c.permits(Operation.COT_SEND));
        }
    }
    @Test void missingAdministratorChainCannotValidateRecoveryList(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);
            var untrusted=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(target),key(70));
            deliver(c,a,b,untrusted,t.hooks(()->fail()));assertEquals(State.RECOVERING_REVOCATIONS,c.state());
        }
    }
    @Test void recoveryCannotRestoreOldSessionsOrApplyKeysAfter180Seconds(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=recovering(a,requirement());bind(c,a,b);
            f.time.advance(180);assertThrows(IllegalStateException.class,()->a.sessions.rotateGroupKey(key(40),1));
            assertEquals(State.RECOVERING_REVOCATIONS,c.state());assertFalse(c.permits(Operation.COT_SEND));
            assertThrows(SecurityException.class,()->a.sessions.send(b.id,new byte[]{1}));
        }
    }
}
