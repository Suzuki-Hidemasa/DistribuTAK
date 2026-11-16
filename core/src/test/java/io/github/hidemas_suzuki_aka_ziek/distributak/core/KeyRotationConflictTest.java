// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.security.SecureRandom;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class KeyRotationConflictTest {
    final CorePersistenceCoordinatorTest t=new CorePersistenceCoordinatorTest();final SessionManagerTest f=t.f;
    static final class RandomWait extends SecureRandom {
        int wait;
        RandomWait(int wait){this.wait=wait;}
        @Override public int nextInt(int bound){return wait;}
    }
    KeyRotationCoordinator rotation(SessionManagerTest.Node a,int wait){
        return new KeyRotationCoordinator(a.state,a.sessions,t.union(a),f.admin,f.time,t.deadlines(),new RandomWait(wait));
    }
    KeyAnnouncement ann(SessionManagerTest.Node a,long version,byte[] value){
        var r=a.state.revocations();var admins=a.state.administrators();
        return KeyAnnouncement.issue(f.group,f.admin,version,f.time.millis(),r.version(),Crypto.blake2s(r.signedBytes()),
            KeyAnnouncement.commitment(f.group,version,value),admins.version(),Crypto.blake2s(admins.signedBytes()));
    }
    CorePersistenceCoordinator.PersistenceHooks hooks(){return new CorePersistenceCoordinator.PersistenceHooks(){
        public void save(AdminRecordStore.Snapshot s){}
        public void saveKey(byte[] value,long version){}
    };}
    void conflict(SessionManagerTest.Node a,KeyRotationCoordinator rotation){
        rotation.observe(ann(a,0,f.psk),a.state.revocations());rotation.observe(ann(a,0,key(70)),a.state.revocations());
    }
    @Test void validatedConflictWaitsAtMostTwoSecondsAndDuplicatePairHasOnePendingOperation(){
        try(var a=f.new Node(1);var rotation=rotation(a,2000)){
            conflict(a,rotation);conflict(a,rotation);assertTrue(rotation.pending());
            assertEquals(KeyRotationCoordinator.Result.WAITING,rotation.poll(List.of(a.cert),hooks()));
            f.time.nanos=1_999_000_000L;assertEquals(KeyRotationCoordinator.Result.WAITING,rotation.poll(List.of(a.cert),hooks()));
            f.time.nanos=2_000_000_000L;assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),hooks()));
            assertEquals(1,rotation.publication().announcement().keyVersion());assertFalse(rotation.pending());
        }
    }
    @Test void manualRotationAndConsolidationShareFiveSecondLimit(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(List.of(),List.of(a.cert),hooks()));
            assertEquals(KeyRotationCoordinator.Result.TOO_EARLY,rotation.manual(List.of(),List.of(a.cert),hooks()));
            rotation.observe(ann(a,1,key(71)),a.state.revocations());
            assertEquals(KeyRotationCoordinator.Result.WAITING,rotation.poll(List.of(a.cert),hooks()));
            f.time.advance(5);assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),hooks()));
            assertEquals(2,rotation.publication().announcement().keyVersion());
        }
    }
    @Test void noPublicationBeforeSaveAndFailedRetryDoesNotReuseVersion(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            conflict(a,rotation);var fail=new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){assertNull(rotation.publication());throw new IllegalStateException("injected failure");}
            };
            assertEquals(KeyRotationCoordinator.Result.CANCELLED,rotation.poll(List.of(a.cert),fail));
            assertNull(rotation.publication());f.time.advance(5);
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),hooks()));
            assertEquals(2,rotation.publication().announcement().keyVersion());
        }
    }
    @Test void revokedRecipientsReceiveNoEnvelopeAndConsolidatedListCoversUnion(){
        try(var a=f.new Node(1);var x=f.new Node(2);var y=f.new Node(3);var rotation=rotation(a,0)){
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(List.of(x.id),List.of(a.cert,x.cert,y.cert),hooks()));
            var p=rotation.publication();assertTrue(p.revocations().hasEntry(x.id));assertEquals(2,p.envelopes().size());
            for(var wrap:p.envelopes())assertFalse(Crypto.equal(x.id,wrap.field(0)));
        }
    }
    @Test void greaterAdoptedCompleteKeyCancelsPendingAndPreviouslyQueuedPublication(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            conflict(a,rotation);assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),hooks()));
            var old=rotation.publication();rotation.observe(ann(a,1,key(72)),a.state.revocations());assertTrue(rotation.pending());
            var current=ann(a,3,key(73));var wrap=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),3,f.time.millis(),key(73),f.admin,Crypto.blake2s(current.signedBytes()));
            assertEquals(CorePersistenceCoordinator.KeyResult.APPLIED,rotation.persistence().applyGroupKey(current,wrap,a.id,a.secret,1,a.sessions.generation(),hooks()));
            assertThrows(IllegalStateException.class,old::envelopes);
            assertEquals(KeyRotationCoordinator.Result.IDLE,rotation.poll(List.of(a.cert),hooks()));
            assertFalse(rotation.pending());assertNull(rotation.publication());assertThrows(IllegalStateException.class,old::envelopes);
        }
    }
    @Test void missingUnionInWinningListTriggersConsolidationWithoutLosingAdministrator(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            var high=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(key(80)),f.admin);
            var low=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(key(81)),f.admin);
            rotation.persistence().receiveRevocations(high,hooks());rotation.persistence().receiveRevocations(low,hooks());
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),hooks()));
            var p=rotation.publication();assertEquals(3,p.revocations().version());assertTrue(p.revocations().hasEntry(key(80)));assertTrue(p.revocations().hasEntry(key(81)));
        }
    }
    @Test void unsignedOrRemovedAdministratorAnnouncementCannotTriggerRotation(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            var r=a.state.revocations();var admins=a.state.administrators();
            var bad=KeyAnnouncement.issue(f.group,key(89),10,f.time.millis(),r.version(),Crypto.blake2s(r.signedBytes()),new byte[32],admins.version(),Crypto.blake2s(admins.signedBytes()));
            assertThrows(SecurityException.class,()->rotation.observe(bad,r));assertFalse(rotation.pending());
            assertEquals(KeyRotationCoordinator.Result.IDLE,rotation.poll(List.of(a.cert),hooks()));
        }
    }
    @Test void restoredReservationsPreventReuseAndVersionLimitStopsWithNotification(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            rotation.restoreReservations(Long.MAX_VALUE,Long.MAX_VALUE);
            assertEquals(KeyRotationCoordinator.Result.VERSION_LIMIT,rotation.manual(List.of(),List.of(a.cert),hooks()));
            assertNull(rotation.publication());assertEquals(0,a.sessions.keyVersion());
        }
    }
    @Test void sameVersionDifferentAnnouncementNeverReplacesReceivedKey(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            var current=ann(a,0,key(74));var wrap=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),0,f.time.millis(),key(74),f.admin,Crypto.blake2s(current.signedBytes()));
            assertEquals(CorePersistenceCoordinator.KeyResult.REJECTED,rotation.persistence().applyGroupKey(current,wrap,a.id,a.secret,0,a.sessions.generation(),hooks()));
            assertEquals(0,a.sessions.keyVersion());
        }
    }
    @Test void alreadyKnownDhtUnionIsIncludedInRotationAndNeverWrappedForRevokedPeer(){
        try(var a=f.new Node(1);var x=f.new Node(2)){
            var union=t.union(a);union.add(t.revoked(x.id));
            try(var rotation=new KeyRotationCoordinator(a.state,a.sessions,union,f.admin,f.time,t.deadlines(),new RandomWait(0))){
                assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert,x.cert),hooks()));
                assertTrue(rotation.publication().revocations().hasEntry(x.id));assertEquals(1,rotation.publication().envelopes().size());
            }
        }
    }
    @Test void savedRotationIncludesEnvelopeQueueAndReservationsAndRestoresOnlyForMatchingKey(){
        try(var a=f.new Node(1);var rotation=rotation(a,0)){
            var saved=new java.util.concurrent.atomic.AtomicReference<KeyRotationCoordinator.SavedRotation>();
            var savedKey=new java.util.concurrent.atomic.AtomicReference<byte[]>();
            var hooks=new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail("complete rotation save required");}
                public void saveRotation(KeyRotationCoordinator.SavedRotation value,byte[] key){saved.set(value);savedKey.set(key.clone());assertNull(rotation.publication());}
            };
            conflict(a,rotation);assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.poll(List.of(a.cert),hooks));
            assertEquals(1,saved.get().envelopes().size());assertEquals(1,saved.get().keyVersion());
            try(var sessions=new SessionManager(a.state,a.cert,a.secret,savedKey.get(),1,f.time,()->f.time.nanos,256);
                var restored=new KeyRotationCoordinator(a.state,sessions,t.union(a),f.admin,f.time,t.deadlines(),new RandomWait(0))){
                assertThrows(SecurityException.class,()->restored.restorePublication(saved.get(),key(95)));
                restored.restorePublication(saved.get(),savedKey.get());
                assertEquals(1,restored.reservedKeyVersion());assertEquals(1,restored.publication().envelopes().size());
                assertEquals(KeyRotationCoordinator.Result.TOO_EARLY,restored.manual(List.of(),List.of(a.cert),hooks));
            }finally{Crypto.wipe(savedKey.get());}
        }
    }
}
