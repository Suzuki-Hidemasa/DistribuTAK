// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class PersistenceContractTest {
    final KeyRotationConflictTest t=new KeyRotationConflictTest();
    @Test void receivedRequestIncludesExactBodyAndUnionCandidateOutsideLocks(){
        try(var a=t.f.new Node(1)){
            var c=t.t.coordinator(a);var body=t.t.revoked(key(85));var order=new ArrayList<String>();
            assertTrue(c.receiveRevocations(body,new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail("request overload required");}
                public void active(PersistenceRequest r){
                    assertFalse(Thread.holdsLock(a.sessions));assertFalse(Thread.holdsLock(a.state));
                    assertTrue(r.received());assertFalse(r.recovery());assertNull(r.requirement());
                    assertArrayEquals(body.encode(),r.revocations().encode());order.add("active");
                }
                public void save(PersistenceRequest r){
                    assertEquals(1,r.management().revocationVersion());order.add("save");
                }
                public void clear(PersistenceRequest r){order.add("clear");}
            }));assertEquals(List.of("active","save","clear"),order);
        }
    }
    @Test void keyAndAnnouncementArePassedToOnePersistenceCall(){
        try(var a=t.f.new Node(1)){
            var c=t.t.coordinator(a);var ann=t.ann(a,1,key(73));
            var wrap=GroupKeyEnvelope.wrap(t.f.group,a.id,Crypto.x25519Public(a.secret),1,t.f.time.millis(),key(73),t.f.admin,Crypto.blake2s(ann.signedBytes()));
            int[] calls={0};
            assertEquals(KeyResult.APPLIED,c.applyGroupKey(ann,wrap,a.id,a.secret,0,a.sessions.generation(),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail();}
                public void saveKey(byte[] k,long version){fail("atomic candidate required");}
                public void saveAcceptedKey(AdminRecordStore.Snapshot s,byte[] k,long version){
                    calls[0]++;assertFalse(Thread.holdsLock(a.sessions));assertFalse(Thread.holdsLock(a.state));
                    assertArrayEquals(ann.encode(),s.announcement());assertArrayEquals(key(73),k);assertEquals(1,version);
                }
            }));assertEquals(1,calls[0]);
        }
    }
    @Test void rotationReservationAndSaveDoNotHoldCoordinatorMonitor(){
        try(var a=t.f.new Node(1);var rotation=t.rotation(a,0)){
            var order=new ArrayList<String>();
            assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(List.of(),List.of(a.cert),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail();}
                public void reserveRotationVersions(long keyVersion,long revocationVersion){
                    assertFalse(Thread.holdsLock(rotation));assertFalse(Thread.holdsLock(a.sessions));assertFalse(Thread.holdsLock(a.state));
                    assertEquals(1,keyVersion);assertEquals(1,revocationVersion);assertNull(rotation.publication());order.add("reserve");
                }
                public void saveRotation(KeyRotationCoordinator.SavedRotation r,byte[] k){
                    assertFalse(Thread.holdsLock(rotation));assertFalse(Thread.holdsLock(a.sessions));assertFalse(Thread.holdsLock(a.state));order.add("save");
                }
            }));assertEquals(List.of("reserve","save"),order);
        }
    }
    @Test void failedReservationDoesNotCreateOrPublishCandidateOrReuseNumber(){
        try(var a=t.f.new Node(1);var rotation=t.rotation(a,0)){
            assertEquals(KeyRotationCoordinator.Result.CANCELLED,rotation.manual(List.of(),List.of(a.cert),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail();}
                public void reserveRotationVersions(long k,long r){throw new IllegalStateException("injected reservation failure");}
            }));assertNull(rotation.publication());assertEquals(0,a.sessions.keyVersion());
            t.f.time.advance(5);assertEquals(KeyRotationCoordinator.Result.PUBLISHED,rotation.manual(List.of(),List.of(a.cert),t.hooks()));
            assertEquals(2,rotation.publication().announcement().keyVersion());
        }
    }
    @Test void higherVersionObservedDuringReservationCancelsBeforeCandidateSave(){
        try(var a=t.f.new Node(1);var rotation=t.rotation(a,0)){
            assertEquals(KeyRotationCoordinator.Result.CANCELLED,rotation.manual(List.of(),List.of(a.cert),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail("stale candidate must not be saved");}
                public void saveRotation(KeyRotationCoordinator.SavedRotation r,byte[] k){fail("stale candidate must not be saved");}
                public void reserveRotationVersions(long k,long r){rotation.observe(t.ann(a,5,key(75)),a.state.revocations());}
            }));assertNull(rotation.publication());assertEquals(0,a.sessions.keyVersion());assertEquals(5,rotation.reservedKeyVersion());
        }
    }
    @Test void successfulKeySaveFollowedByGenerationChangeStopsWithoutStorageMessage(){
        try(var a=t.f.new Node(1)){
            var c=t.t.coordinator(a);var ann=t.ann(a,1,key(73));
            var wrap=GroupKeyEnvelope.wrap(t.f.group,a.id,Crypto.x25519Public(a.secret),1,t.f.time.millis(),key(73),t.f.admin,Crypto.blake2s(ann.signedBytes()));
            int[] saved={0},stopped={0};
            assertEquals(KeyResult.STALE,c.applyGroupKey(ann,wrap,a.id,a.secret,0,a.sessions.generation(),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail();}
                public void saveAcceptedKey(AdminRecordStore.Snapshot s,byte[] k,long v){saved[0]++;a.sessions.forgetAllVolatile();}
                public void stopped(StopReason reason){assertEquals(StopReason.COMMITTED_NOT_APPLIED,reason);stopped[0]++;}
            }));assertEquals(1,saved[0]);assertEquals(1,stopped[0]);assertTrue(a.sessions.isClosed());
            assertEquals(State.STORAGE_FAILED,c.state());assertEquals(StopReason.COMMITTED_NOT_APPLIED,c.stopReason());assertEquals("",c.statusText());
            for(var op:Operation.values())assertFalse(c.permits(op));
        }
    }
    @Test void failedKeySaveCancelsWithoutClosingOldSessions(){
        try(var a=t.f.new Node(1);var b=t.f.new Node(2)){
            t.f.connect(a,b);byte[] session=a.sessions.sessionId(b.id);var c=t.t.coordinator(a);var ann=t.ann(a,1,key(73));
            var wrap=GroupKeyEnvelope.wrap(t.f.group,a.id,Crypto.x25519Public(a.secret),1,t.f.time.millis(),key(73),t.f.admin,Crypto.blake2s(ann.signedBytes()));
            assertEquals(KeyResult.CANCELLED,c.applyGroupKey(ann,wrap,a.id,a.secret,0,a.sessions.generation(),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){fail();}
                public void saveAcceptedKey(AdminRecordStore.Snapshot s,byte[] k,long v){throw new IllegalStateException("injected save failure");}
            }));assertEquals(State.RUNNING,c.state());assertEquals(StopReason.NONE,c.stopReason());
            assertArrayEquals(session,a.sessions.sessionId(b.id));assertFalse(a.sessions.isClosed());
        }
    }
    @Test void ordinarySaveRetainsSessionAndRunsIoOutsideLocks(){
        try(var a=t.f.new Node(1);var b=t.f.new Node(2)){
            t.f.connect(a,b);var c=t.t.coordinator(a);byte[] session=a.sessions.sessionId(b.id);
            c.saveUnchanged(()->{
                assertFalse(Thread.holdsLock(a.sessions));assertFalse(Thread.holdsLock(a.state));
                assertEquals(State.PERSISTING,c.state());assertFalse(c.permits(Operation.COT_SEND));
                assertArrayEquals(session,a.sessions.sessionId(b.id));
            });
            assertEquals(State.RUNNING,c.state());assertArrayEquals(session,a.sessions.sessionId(b.id));
        }
    }
    @Test void ordinarySaveDoesNotExtendSessionLifetime(){
        try(var a=t.f.new Node(1);var b=t.f.new Node(2)){
            t.f.connect(a,b);var c=t.t.coordinator(a);
            c.saveUnchanged(()->{t.f.time.advance(181);a.sessions.refresh();});
            assertFalse(a.sessions.isEstablished(b.id));assertEquals(State.RUNNING,c.state());
        }
    }
    @Test void ordinarySaveFailureRetainsOldSessionAndResumes(){
        try(var a=t.f.new Node(1);var b=t.f.new Node(2)){
            t.f.connect(a,b);var c=t.t.coordinator(a);byte[] session=a.sessions.sessionId(b.id);
            assertThrows(IllegalStateException.class,()->c.saveUnchanged(()->{throw new IllegalStateException("injected");}));
            assertEquals(State.RUNNING,c.state());assertArrayEquals(session,a.sessions.sessionId(b.id));
        }
    }

    @Test void rotationCanShareExistingPersistenceCoordinator(){
        try(var a=t.f.new Node(1)){
            var union=t.t.union(a);var coordinator=new CorePersistenceCoordinator(a.state,a.sessions,union,t.f.time,t.t.deadlines());
            try(var rotation=new KeyRotationCoordinator(a.state,a.sessions,union,t.f.admin,t.f.time,t.t.deadlines(),new java.security.SecureRandom(),null,()->true,coordinator)){
                assertSame(coordinator,rotation.persistence());
            }
        }
    }

}
