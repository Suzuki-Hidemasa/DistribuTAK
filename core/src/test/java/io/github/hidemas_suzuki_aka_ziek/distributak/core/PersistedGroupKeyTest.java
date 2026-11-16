// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class PersistedGroupKeyTest {
    final CorePersistenceCoordinatorTest t=new CorePersistenceCoordinatorTest();
    final SessionManagerTest f=t.f;
    KeyAnnouncement announcement(SessionManagerTest.Node a,AdminRecords.Record r,byte[] digest){
        var admins=a.state.administrators();return KeyAnnouncement.issue(f.group,f.admin,1,f.time.millis(),r.version(),digest,
            KeyAnnouncement.commitment(f.group,1,key(40)),admins.version(),Crypto.blake2s(admins.signedBytes()));
    }
    AdminRecords.Record wrap(SessionManagerTest.Node a,KeyAnnouncement announcement){
        return GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),1,f.time.millis(),key(40),f.admin,Crypto.blake2s(announcement.signedBytes()));
    }
    PersistenceHooks keyHooks(Runnable save){return new PersistenceHooks(){
        public void save(AdminRecordStore.Snapshot s){}
        public void saveKey(byte[] key,long version){save.run();}
    };}
    @Test void announcementAndWrapWaitForReferencedRevocationBody(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);var r=t.revoked();var ann=announcement(a,r,Crypto.blake2s(r.signedBytes()));
            assertEquals(KeyResult.DEFERRED,c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->fail())));
            assertEquals(0,a.sessions.keyVersion());c.receiveRevocations(r,t.hooks(()->{}));
            assertEquals(KeyResult.APPLIED,c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->{})));
        }
    }
    @Test void equalVersionWithoutMatchingBodyDigestDoesNotApplyKey(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);var r=t.revoked();c.receiveRevocations(r,t.hooks(()->{}));
            var ann=announcement(a,r,new byte[32]);
            assertEquals(KeyResult.DEFERRED,c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->fail())));
            assertEquals(0,a.sessions.keyVersion());
        }
    }
    @Test void keyArrivalDuringPersistenceIsDeferredAndNotRetained(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);var r=t.revoked();var ann=announcement(a,r,Crypto.blake2s(r.signedBytes()));
            c.receiveRevocations(r,t.hooks(()->assertEquals(KeyResult.DEFERRED,
                c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->fail())))));
            assertEquals(0,a.sessions.keyVersion());
        }
    }
    @Test void keyPersistenceRechecksGenerationAndDoesNotApplyStaleCompletion(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);var r=t.revoked();c.receiveRevocations(r,t.hooks(()->{}));var ann=announcement(a,r,Crypto.blake2s(r.signedBytes()));
            assertEquals(KeyResult.STALE,c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->a.sessions.forgetAllVolatile())));
            assertEquals(0,a.sessions.keyVersion());assertTrue(a.sessions.isClosed());assertEquals(State.STORAGE_FAILED,c.state());
            assertEquals(StopReason.COMMITTED_NOT_APPLIED,c.stopReason());assertEquals("",c.statusText());
        }
    }
    @Test void keyCommitmentAndWrapAnnouncementBindingAreVerified(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);var r=t.revoked();c.receiveRevocations(r,t.hooks(()->{}));var ann=announcement(a,r,Crypto.blake2s(r.signedBytes()));
            var wrong=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),1,f.time.millis(),key(41),f.admin,Crypto.blake2s(ann.signedBytes()));
            assertEquals(KeyResult.REJECTED,c.applyGroupKey(ann,wrong,a.id,a.secret,0,a.sessions.generation(),keyHooks(()->fail())));
            wrong=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),1,f.time.millis(),key(40),f.admin,new byte[32]);
            assertEquals(KeyResult.REJECTED,c.applyGroupKey(ann,wrong,a.id,a.secret,0,a.sessions.generation(),keyHooks(()->fail())));
        }
    }
    @Test void keyOnlySaveFailureCancelsWithoutStarting180SecondsOrStorageFailure(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);byte[] old=a.sessions.sessionId(b.id);
            var c=t.coordinator(a);var r=t.revoked();c.receiveRevocations(r,t.hooks(()->{}));var ann=announcement(a,r,Crypto.blake2s(r.signedBytes()));
            assertEquals(KeyResult.CANCELLED,c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->{throw new IllegalStateException("test");})));
            assertEquals(State.RUNNING,c.state());assertEquals(0,a.sessions.keyVersion());assertEquals("",c.statusText());
            assertFalse(a.sessions.isClosed());f.time.advance(180);assertArrayEquals(old,a.sessions.sessionId(b.id));
        }
    }
    @Test void keyPersistenceCannotApplyAfterAdministratorStateChanges(){
        try(var a=f.new Node(1)){
            var c=t.coordinator(a);var r=t.revoked();c.receiveRevocations(r,t.hooks(()->{}));var ann=announcement(a,r,Crypto.blake2s(r.signedBytes()));
            var later=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin);
            assertEquals(KeyResult.STALE,c.applyGroupKey(ann,wrap(a,ann),a.id,a.secret,0,a.sessions.generation(),keyHooks(()->a.state.acceptRevocations(later))));
            assertEquals(State.STORAGE_FAILED,c.state());assertEquals(StopReason.COMMITTED_NOT_APPLIED,c.stopReason());
            assertTrue(a.sessions.isClosed());assertEquals("",c.statusText());assertEquals(0,a.sessions.keyVersion());
        }
    }
}
