// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class RotationReviewFixTest {
    @Test void intermediateAdoptionCannotMarkHigherConflictAsHandled(){
        var t=new KeyRotationConflictTest();var f=t.f;
        try(var a=f.new Node(1);var rotation=t.rotation(a,2000)){
            t.conflict(a,rotation);
            var highA=t.ann(a,2,key(70));var highB=t.ann(a,2,key(71));
            rotation.observe(highA,a.state.revocations());rotation.observe(highB,a.state.revocations());
            var intermediate=t.ann(a,1,key(72));
            var wrap=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),1,f.time.millis(),key(72),f.admin,Crypto.blake2s(intermediate.signedBytes()));
            assertEquals(CorePersistenceCoordinator.KeyResult.APPLIED,rotation.persistence().applyGroupKey(intermediate,wrap,a.id,a.secret,0,a.sessions.generation(),t.hooks()));
            f.time.advance(5);assertTrue(rotation.pending());
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),t.hooks()));
            assertEquals(3,rotation.publication().announcement().keyVersion());
        }
    }
    @Test void repeatedRevocationDoesNotReserveVersionOrUseCooldownButEmptyRequestStillRotates(){
        var t=new KeyRotationConflictTest();var f=t.f;
        try(var a=f.new Node(1);var rotation=t.rotation(a,0)){
            var subjects=List.of(key(85));assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(subjects,List.of(a.cert),t.hooks()));
            f.time.advance(5);long keyVersion=rotation.reservedKeyVersion(),revocationVersion=rotation.reservedRevocationVersion();
            assertEquals(KeyRotationCoordinator.Result.IDLE,rotation.manual(subjects,List.of(a.cert),t.hooks()));
            assertEquals(keyVersion,rotation.reservedKeyVersion());assertEquals(revocationVersion,rotation.reservedRevocationVersion());
            assertEquals(keyVersion,a.sessions.keyVersion());
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(List.of(),List.of(a.cert),t.hooks()));
            assertEquals(keyVersion+1,a.sessions.keyVersion());
        }
    }
    @Test void alreadyRevokedTargetStillConsolidatesPendingConflict(){
        var t=new KeyRotationConflictTest();var f=t.f;
        try(var a=f.new Node(1);var rotation=t.rotation(a,0)){
            var subjects=List.of(key(85));rotation.manual(subjects,List.of(a.cert),t.hooks());f.time.advance(5);
            rotation.observe(t.ann(a,1,key(72)),a.state.revocations());
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(subjects,List.of(a.cert),t.hooks()));
            assertEquals(2,a.sessions.keyVersion());
        }
    }
    @Test void olderSelfRevocationOnlyInUnionErasesExactlyOnceAfterSave(){
        var t=new CorePersistenceCoordinatorTest();var f=t.f;
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);int[] erased={0};
            var hooks=new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){}
                public void selfRevoked(){erased[0]++;assertTrue(a.sessions.isClosed());}
            };
            assertTrue(c.receiveRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin),hooks));
            assertTrue(c.receiveRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(a.id),f.admin),hooks));
            assertFalse(a.state.revocations().hasEntry(a.id));assertTrue(a.sessions.localRevoked());assertEquals(1,erased[0]);
            assertThrows(IllegalStateException.class,()->c.receiveRevocations(t.revoked(a.id),hooks));assertEquals(1,erased[0]);
        }
    }
    @Test void endpointForgetsPeerPresentOnlyInUnion(){
        var f=new SessionManagerTest();var io=new JoinPortLimitsTest.MemoryIo();
        try(var a=f.new Node(1);var b=f.new Node(2);var endpoint=new UdpEndpoint(a.sessions,a.state,io,(id,p)->{},Duration.ofDays(1))){
            endpoint.rememberPeer(b.cert);endpoint.setPeerAddress(b.id,JoinPortLimitsTest.SOURCE);
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin));
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(b.id),f.admin));
            assertDoesNotThrow(()->endpoint.forgetPeer(b.id));assertNull(endpoint.peerAddress(b.id));assertTrue(endpoint.knownPeers().isEmpty());
        }
    }
    @Test void renewalRestoreRefusesLocalMemberPresentOnlyInUnion(){
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)){
            a.remember(b);f.time.advance(1);var renewal=b.certificate(b.secret,f.time.millis());
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin));
            a.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(a.id),f.admin));
            assertThrows(SecurityException.class,()->a.sessions.restorePeerRenewal(b.id,renewal.encode(),Crypto.ed25519Public(f.admin)));
        }
    }
}
