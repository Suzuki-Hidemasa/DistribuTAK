// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class CorePersistenceCoordinatorTest {
    static final class FailingClock extends Clock {
        final Clock base;
        boolean fail;
        FailingClock(Clock base){this.base=base;}
        public ZoneId getZone(){return base.getZone();}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return Instant.ofEpochMilli(millis());}
        public long millis(){
            if(fail){fail=false;throw new DateTimeException("injected clock failure");}
            return base.millis();
        }
    }
    static final class BlockingStore implements AdminRecordStore {
        final InMemoryAdminRecordStore delegate=new InMemoryAdminRecordStore();
        final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
        volatile boolean block;
        Runnable beforeSave=()->{};
        public Snapshot load(){return delegate.load();}
        public void clear(){delegate.clear();}
        public void save(Snapshot snapshot){
            if(block){
                entered.countDown();
                try{if(!release.await(5,TimeUnit.SECONDS))throw new IllegalStateException("test timeout");}
                catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}
            }
            beforeSave.run();delegate.save(snapshot);
        }
    }
    final SessionManagerTest f=new SessionManagerTest();
    Clock deadlines(){return new MonotonicClock(()->f.time.nanos);}
    RevocationUnion union(SessionManagerTest.Node n){
        var r=new RevocationUnion(f.group,new AdminStateTrust(n.state));r.add(n.state.revocations());return r;
    }
    CorePersistenceCoordinator coordinator(SessionManagerTest.Node n){
        return new CorePersistenceCoordinator(n.state,n.sessions,union(n),f.time,deadlines());
    }
    AdminRecords.Record revoked(byte[]... ids){
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,1,f.time.millis(),List.of(ids),f.admin);
    }
    PersistenceHooks hooks(Runnable during){return new PersistenceHooks(){public void save(AdminRecordStore.Snapshot s){during.run();}};}
    @Test void noticeClockFailureStopsReceivedPersistenceAndReleasesBothReservations(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var union=union(a);var clock=new FailingClock(deadlines());
            var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,clock);clock.fail=true;
            assertAll(
                ()->assertFalse(c.receiveRevocations(revoked(b.id),hooks(()->fail("save reached")))),
                ()->assertEquals(State.STORAGE_FAILED,c.state()),
                ()->assertTrue(a.sessions.isClosed()),
                ()->assertTrue(a.state.acceptRevocations(revoked(b.id))),
                ()->assertTrue(union.add(revoked(b.id)))
            );
        }
    }
    @Test void saveClockFailureCancelsLocalCandidateAndReleasesBothReservations(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var union=union(a);var clock=new FailingClock(deadlines());
            var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,clock);clock.fail=true;
            assertFalse(c.persistLocalRevocations(revoked(b.id),hooks(clock::millis)));
            assertEquals(State.RUNNING,c.state());assertFalse(a.sessions.isClosed());
            assertEquals(0,a.state.revocations().version());assertFalse(union.contains(b.id));
            assertTrue(a.state.acceptRevocations(revoked(b.id)));assertTrue(union.add(revoked(b.id)));
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void afterCommitSelfHookFailureKeepsSavedAndMemoryVersionsEqualAndReleasesReservations(boolean local)throws Exception{
        try(var a=f.new Node(1)){
            var union=union(a);var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,deadlines());
            int[] stopped={0};var hooks=new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){}
                public void selfRevoked(){throw new IllegalStateException("injected erase failure");}
                public void stopped(){stopped[0]++;}
            };
            assertFalse(local?c.persistLocalRevocations(revoked(a.id),hooks):c.receiveRevocations(revoked(a.id),hooks));
            var store=(AdminRecordStore)SessionManagerTest.field(a.state,"store");
            assertEquals(1,store.load().revocationVersion());assertEquals(store.load().revocationVersion(),a.state.revocations().version());
            assertEquals(State.STORAGE_FAILED,c.state());assertTrue(a.sessions.isClosed());assertEquals(1,stopped[0]);
            assertTrue(union.add(revoked(key(62))));assertDoesNotThrow(a.state::clear);
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void afterCommitRefreshFailureKeepsSavedAndMemoryVersionsEqualAndReleasesReservations(boolean local){
        var store=new BlockingStore();
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var admin=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,store);
            var admins=a.state.administrators();admin.bootstrap(admins,AdminRecords.signAnchor(admins,f.admin));
            admin.acceptRevocations(a.state.revocations());boolean[] fail={false};
            try(var sessions=new SessionManager(admin,a.cert,a.secret,f.psk,0,f.time,()->{
                if(fail[0]){fail[0]=false;throw new IllegalStateException("injected ticker failure");}
                return f.time.nanos;
            },256)){
                var union=new RevocationUnion(f.group,new AdminStateTrust(admin));union.add(admin.revocations());
                var c=new CorePersistenceCoordinator(admin,sessions,union,f.time,deadlines());
                store.beforeSave=()->fail[0]=true;int[] stopped={0};var hooks=new PersistenceHooks(){
                    public void save(AdminRecordStore.Snapshot s){}
                    public void stopped(){stopped[0]++;}
                };
                assertFalse(local?c.persistLocalRevocations(revoked(b.id),hooks):c.receiveRevocations(revoked(b.id),hooks));
                assertEquals(1,store.load().revocationVersion());assertEquals(store.load().revocationVersion(),admin.revocations().version());
                assertEquals(State.STORAGE_FAILED,c.state());assertTrue(sessions.isClosed());assertEquals(1,stopped[0]);
                assertTrue(union.add(revoked(key(62))));assertDoesNotThrow(admin::clear);
            }
        }
    }
    @Test void oldSessionSurvives179Seconds999MillisAndClosesAt180Seconds(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);coordinator(a);a.sessions.rotateGroupKey(key(40),1);
            f.time.nanos=179_999_000_000L;assertTrue(a.sessions.isEstablished(b.id));
            f.time.nanos=180_000_000_000L;assertFalse(a.sessions.isEstablished(b.id));
        }
    }
    @Test void consecutiveRotationsDoNotExtend180Seconds(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);coordinator(a);a.sessions.rotateGroupKey(key(40),1);f.time.advance(179);
            a.sessions.rotateGroupKey(key(41),2);f.time.advance(1);assertFalse(a.sessions.isEstablished(b.id));
        }
    }
    @Test void rotationDuringPersistenceIsRejectedWithoutExtendingDeadline(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);a.sessions.rotateGroupKey(key(40),1);f.time.advance(179);
            assertTrue(c.receiveRevocations(revoked(),hooks(()->{
                assertThrows(IllegalStateException.class,()->a.sessions.rotateGroupKey(key(41),2));
                f.time.advance(1);assertFalse(a.sessions.isEstablished(b.id));
            })));assertFalse(a.sessions.isEstablished(b.id));
        }
    }
    @Test void expirationDuringPersistenceIsNeverResurrectedBySuccessfulSave(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);a.sessions.rotateGroupKey(key(40),1);
            c.receiveRevocations(revoked(),hooks(()->{f.time.advance(180);c.poll();assertFalse(a.sessions.isEstablished(b.id));}));
            assertEquals(State.RUNNING,c.state());assertFalse(a.sessions.isEstablished(b.id));assertFalse(a.sessions.isClosed());
        }
    }
    @Test void nonRevokedPairUsesSameOldSessionAfterPersistenceThenMovesToNewKey(){
        try(var a=f.new Node(1);var b=f.new Node(2);var removed=f.new Node(3)){
            f.connect(a,b);f.connect(a,removed);var c=coordinator(a);byte[] old=a.sessions.sessionId(b.id);
            var r=revoked(removed.id);
            c.receiveRevocations(r,hooks(()->{
                assertArrayEquals(old,a.sessions.sessionId(b.id));assertFalse(a.sessions.isClosed());
                assertFalse(a.sessions.isEstablished(removed.id));assertEquals(0,a.state.revocations().version());
            }));
            assertArrayEquals(old,a.sessions.sessionId(b.id));
            var admins=a.state.administrators();byte[] next=key(40);
            var announcement=KeyAnnouncement.issue(f.group,f.admin,1,f.time.millis(),r.version(),Crypto.blake2s(r.signedBytes()),
                    KeyAnnouncement.commitment(f.group,1,next),admins.version(),Crypto.blake2s(admins.signedBytes()));
            var wrap=GroupKeyEnvelope.wrap(f.group,a.id,Crypto.x25519Public(a.secret),1,f.time.millis(),next,f.admin,Crypto.blake2s(announcement.signedBytes()));
            assertArrayEquals(announcement.encode(),a.sessions.receive(b.sessions.send(a.id,announcement.encode()).get(0).packet()).plaintext());
            assertArrayEquals(wrap.encode(),a.sessions.receive(b.sessions.send(a.id,wrap.encode()).get(0).packet()).plaintext());
            assertEquals(KeyResult.APPLIED,c.applyGroupKey(announcement,wrap,a.id,a.secret,0,a.sessions.generation(),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){}
                public void saveKey(byte[] saved,long version){assertArrayEquals(next,saved);assertEquals(1,version);}
            }));
            assertArrayEquals(old,a.sessions.sessionId(b.id));b.sessions.rotateGroupKey(next,1);f.time.advance(5);
            var reply=b.sessions.receive(a.sessions.start(b.id).packet());
            b.sessions.receive(a.sessions.receive(reply.outbound().get(0).packet()).outbound().get(0).packet());
            assertFalse(Arrays.equals(old,a.sessions.sessionId(b.id)));assertArrayEquals(new byte[]{7},b.sessions.receive(f.data(a,b,7)).plaintext());
        }
    }
    @Test void persistenceBlocksHandshakeSendReceiveAndKeyApplication(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);byte[] data=f.data(b,a,1);
            c.receiveRevocations(revoked(),hooks(()->{
                assertEquals(State.PERSISTING,c.state());
                assertThrows(IllegalStateException.class,()->a.sessions.start(b.id));
                assertThrows(IllegalStateException.class,()->a.sessions.send(b.id,new byte[]{1}));
                assertThrows(IllegalStateException.class,()->a.sessions.receive(data));
                assertThrows(IllegalStateException.class,()->a.sessions.rotateGroupKey(key(40),1));
                assertTrue(a.sessions.poll().isEmpty());
                for(var op:Operation.values())assertFalse(c.permits(op));
            }));assertArrayEquals(new byte[]{1},a.sessions.receive(data).plaintext());
        }
    }
    @Test void revokedPeerIsRejectedBeforePersistenceAndCannotReturn(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);byte[] old=f.data(b,a,1);
            c.receiveRevocations(revoked(b.id),hooks(()->assertFalse(a.sessions.isEstablished(b.id))));
            assertThrows(SecurityException.class,()->a.sessions.receive(old));
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(b.cert));
            f.time.advance(5);assertThrows(SecurityException.class,()->a.sessions.receive(b.sessions.start(a.id).packet()));
        }
    }
    @Test void receivedSaveFailureStopsGroupAndKeepsLearnedRevocation(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);
            assertFalse(c.receiveRevocations(revoked(b.id),hooks(()->{throw new IllegalStateException("test");})));
            assertEquals(State.STORAGE_FAILED,c.state());assertEquals("保存がいっぱい",c.statusText());
            assertTrue(a.sessions.isClosed());assertTrue(c.isRevoked(b.id));assertEquals(0,a.state.revocations().version());
            for(var op:Operation.values())assertFalse(c.permits(op));
        }
    }
    @Test void ownCandidateSaveFailureCancelsAndPreservesOldState(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);byte[] old=a.sessions.sessionId(b.id);
            assertFalse(c.persistLocalRevocations(revoked(b.id),hooks(()->{throw new IllegalStateException("test");})));
            assertEquals(State.RUNNING,c.state());assertArrayEquals(old,a.sessions.sessionId(b.id));
            assertFalse(c.isRevoked(b.id));assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void ownCandidateStaleBeforeStoreDoesNotWriteNewRevocations()throws Exception{
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var c=coordinator(a);var store=(AdminRecordStore)SessionManagerTest.field(a.state,"store");
            assertFalse(c.persistLocalRevocations(revoked(b.id),hooks(a.sessions::forgetAllVolatile)));
            assertEquals(0,store.load().revocationVersion());assertEquals(0,a.state.revocations().version());
            assertFalse(c.isRevoked(b.id));assertEquals(State.STORAGE_FAILED,c.state());
            assertEquals(StopReason.COMMITTED_NOT_APPLIED,c.stopReason());assertTrue(a.sessions.isClosed());assertEquals("",c.statusText());
        }
    }
    @Test void ownCandidateGenerationChangeDuringStoreStillPublishesCommittedRevocation(){
        var store=new BlockingStore();
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var admin=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,store);
            var admins=a.state.administrators();admin.bootstrap(admins,AdminRecords.signAnchor(admins,f.admin));
            admin.acceptRevocations(a.state.revocations());
            try(var sessions=new SessionManager(admin,a.cert,a.secret,f.psk,0,f.time,()->f.time.nanos,256)){
                var union=new RevocationUnion(f.group,new AdminStateTrust(admin));union.add(admin.revocations());
                var c=new CorePersistenceCoordinator(admin,sessions,union,f.time,deadlines());
                store.beforeSave=sessions::forgetAllVolatile;
                assertTrue(c.persistLocalRevocations(revoked(b.id),hooks(()->{})));
                assertEquals(1,store.load().revocationVersion());assertEquals(1,admin.revocations().version());
                assertTrue(c.isRevoked(b.id));assertEquals(State.RUNNING,c.state());
                assertThrows(SecurityException.class,()->sessions.rememberPeer(b.cert));
            }
        }
    }
    @Test void ownCandidateReservesAdminBaseBeforeActualStore(){
        var store=new BlockingStore();
        try(var a=f.new Node(1)){
            var admin=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,store);
            var admins=a.state.administrators();admin.bootstrap(admins,AdminRecords.signAnchor(admins,f.admin));
            admin.acceptRevocations(a.state.revocations());
            try(var sessions=new SessionManager(admin,a.cert,a.secret,f.psk,0,f.time,()->f.time.nanos,256)){
                var union=new RevocationUnion(f.group,new AdminStateTrust(admin));union.add(admin.revocations());
                var c=new CorePersistenceCoordinator(admin,sessions,union,f.time,deadlines());
                var other=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,2,f.time.millis(),List.of(),f.admin);
                store.beforeSave=()->{store.beforeSave=()->{};assertThrows(IllegalStateException.class,()->admin.acceptRevocations(other));};
                assertTrue(c.persistLocalRevocations(revoked(),hooks(()->{})));
                assertEquals(1,store.load().revocationVersion());assertEquals(1,admin.revocations().version());
            }
        }
    }
    @Test void ownCandidateReservesUnionWithoutPublishingBeforeSave(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var union=union(a);var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,deadlines());
            assertTrue(c.persistLocalRevocations(revoked(b.id),hooks(()->{
                assertFalse(c.isRevoked(b.id));assertEquals(0,a.state.revocations().version());
                assertThrows(IllegalStateException.class,()->union.add(revoked(key(62))));
            })));
            assertTrue(c.isRevoked(b.id));assertTrue(union.add(revoked(key(62))));
        }
    }
    @Test void cancelledOwnCandidateReleasesAdminAndUnionReservations(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var union=union(a);var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,deadlines());
            assertFalse(c.persistLocalRevocations(revoked(b.id),hooks(()->{throw new IllegalStateException("test");})));
            assertFalse(c.isRevoked(b.id));assertTrue(union.add(revoked(key(62))));
            assertTrue(a.state.acceptRevocations(revoked(key(62))));assertEquals(State.RUNNING,c.state());
        }
    }
    RevocationUnion fullUnion(SessionManagerTest.Node a){
        var union=union(a);var entries=new ArrayList<byte[]>();
        for(int i=0;i<AdminRecords.MAX_ENTRIES;i++){
            byte[] subject=new byte[32];java.nio.ByteBuffer.wrap(subject).putInt(i);subject[31]=(byte)0xEE;entries.add(subject);
        }
        union.add(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,f.group,0,f.time.millis(),entries,f.admin));return union;
    }
    @Test void ownCandidateOverUnionLimitIsRejectedBeforeAnySave()throws Exception{
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var union=fullUnion(a);var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,deadlines());
            var store=(AdminRecordStore)SessionManagerTest.field(a.state,"store");
            assertThrows(AdminRecords.RevocationLimitException.class,()->c.persistLocalRevocations(revoked(b.id),hooks(()->fail("save reached"))));
            assertEquals(0,store.load().revocationVersion());assertEquals(0,a.state.revocations().version());
            assertEquals(State.RUNNING,c.state());assertFalse(c.isRevoked(b.id));
        }
    }
    @Test void receivedOverUnionLimitDoesNotQueueFinalNoticeOrSave(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);byte[] session=a.sessions.sessionId(b.id);var union=fullUnion(a);
            var c=new CorePersistenceCoordinator(a.state,a.sessions,union,f.time,deadlines());var r=revoked(b.id);
            var page=ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],f.group,r.encode(),1).get(0);
            assertThrows(AdminRecords.RevocationLimitException.class,()->c.receiveRevocations(r,hooks(()->fail("save reached"))));
            assertFalse(c.maySendFinalNotice(b.id,session,a.sessions.generation(),page.envelope()));
            assertTrue(a.sessions.isEstablished(b.id));assertEquals(0,a.state.revocations().version());assertEquals(State.RUNNING,c.state());
        }
    }
    @Test void activeSaveClearAndApplyHaveFixedOrder(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);var order=new ArrayList<String>();
            c.receiveRevocations(revoked(),new PersistenceHooks(){
                public void active(AdminRecordStore.Snapshot s){order.add("active");}
                public void save(AdminRecordStore.Snapshot s){order.add("save");assertEquals(0,a.state.revocations().version());}
                public void clear(AdminRecordStore.Snapshot s){order.add("clear");assertEquals(0,a.state.revocations().version());}
            });assertEquals(List.of("active","save","clear"),order);assertEquals(1,a.state.revocations().version());
        }
    }
    @Test void activeFailureStopsBeforeSave(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);assertFalse(c.receiveRevocations(revoked(),new PersistenceHooks(){
                public void active(AdminRecordStore.Snapshot s){throw new IllegalStateException("test");}
                public void save(AdminRecordStore.Snapshot s){fail();}
            }));assertEquals(State.STORAGE_FAILED,c.state());
        }
    }
    @Test void clearFailureDoesNotPublishCandidate(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);assertFalse(c.receiveRevocations(revoked(),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){}
                public void clear(AdminRecordStore.Snapshot s){throw new IllegalStateException("test");}
            }));assertEquals(State.STORAGE_FAILED,c.state());assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void savedSelfRevocationClosesCommunicationAndCallsEraseHookAfterClear(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);var order=new ArrayList<String>();
            assertTrue(c.receiveRevocations(revoked(a.id),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){order.add("save");}
                public void clear(AdminRecordStore.Snapshot s){order.add("clear");}
                public void selfRevoked(){assertFalse(Thread.holdsLock(a.sessions));assertTrue(a.sessions.isClosed());order.add("erase");}
            }));assertEquals(List.of("save","clear","erase"),order);
            for(var op:Operation.values())assertFalse(c.permits(op));
        }
    }
    @Test void savedSelfRevocationReleasesAdminReservationBeforeEraseHook(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);boolean[] erased={false};
            assertTrue(c.receiveRevocations(revoked(a.id),new PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot s){}
                public void selfRevoked(){a.state.clear();erased[0]=true;}
            }));assertTrue(erased[0]);assertTrue(a.sessions.isClosed());
        }
    }
    @Test void duplicateRevocationsDoNotRepeatPersistence(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);var r=revoked();assertTrue(c.receiveRevocations(r,hooks(()->{})));
            assertFalse(c.receiveRevocations(r,hooks(()->fail())));assertEquals(State.RUNNING,c.state());
        }
    }
    @Test void generationChangeDuringPersistenceCannotResumeOldOperation(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);assertFalse(c.receiveRevocations(revoked(),hooks(()->a.sessions.forgetAllVolatile())));
            assertEquals(State.STORAGE_FAILED,c.state());assertEquals(0,a.state.revocations().version());
        }
    }
    @Test void persistenceIoDoesNotHoldSessionMonitor()throws Exception{
        try(var a=f.new Node(1)){
            var c=coordinator(a);var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
            var pool=Executors.newSingleThreadExecutor();
            try{
                var result=pool.submit(()->c.receiveRevocations(revoked(),hooks(()->{
                    entered.countDown();try{assertTrue(release.await(5,TimeUnit.SECONDS));}catch(InterruptedException e){throw new AssertionError(e);}
                })));
                assertTrue(entered.await(5,TimeUnit.SECONDS));assertEquals(State.PERSISTING,c.state());assertDoesNotThrow(c::poll);
                release.countDown();assertTrue(result.get(5,TimeUnit.SECONDS));
            }finally{release.countDown();pool.shutdownNow();}
        }
    }
    @Test void actualAdminStoreIoAllowsPollRefreshAndReceiveToReturnBeforeSaveCompletes()throws Exception{
        var store=new BlockingStore();
        try(var a=f.new Node(1);var b=f.new Node(2)){
            var admin=new AdminState(f.group,Crypto.ed25519Public(f.admin),f.time,store);
            var admins=a.state.administrators();admin.bootstrap(admins,AdminRecords.signAnchor(admins,f.admin));
            admin.acceptRevocations(a.state.revocations());
            try(var sessions=new SessionManager(admin,a.cert,a.secret,f.psk,0,f.time,()->f.time.nanos,256)){
                sessions.rememberPeer(b.cert);b.remember(a);
                var second=b.sessions.receive(sessions.start(b.id).packet());
                b.sessions.receive(sessions.receive(second.outbound().get(0).packet()).outbound().get(0).packet());
                var union=new RevocationUnion(f.group,new AdminStateTrust(admin));union.add(admin.revocations());
                var c=new CorePersistenceCoordinator(admin,sessions,union,f.time,deadlines());
                byte[] packet=f.data(b,a,1);sessions.rotateGroupKey(key(40),1);
                var pool=Executors.newFixedThreadPool(2);store.block=true;
                try{
                    var saved=pool.submit(()->c.receiveRevocations(revoked(),hooks(()->{})));
                    assertTrue(store.entered.await(2,TimeUnit.SECONDS));f.time.advance(180);
                    var processed=pool.submit(()->{
                        assertTrue(sessions.poll().isEmpty());c.poll();sessions.refresh();
                        assertFalse(sessions.isEstablished(b.id));
                        assertThrows(IllegalStateException.class,()->sessions.receive(packet));
                    });
                    processed.get(1,TimeUnit.SECONDS);
                    assertFalse(saved.isDone());store.release.countDown();assertTrue(saved.get(2,TimeUnit.SECONDS));
                }finally{store.release.countDown();pool.shutdownNow();}
            }
        }
    }
    @Test void oldGroupKeyCannotCreateNewSessionAfterRotation(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);coordinator(a);a.sessions.rotateGroupKey(key(40),1);f.time.advance(5);
            assertThrows(SecurityException.class,()->a.sessions.receive(b.sessions.start(a.id).packet()));
        }
    }
    @Test void commonOperationGateExecutesOnlyWhileRunning(){
        try(var a=f.new Node(1)){
            var c=coordinator(a);int[] called={0};
            for(var op:Operation.values())c.execute(op,()->called[0]++);
            assertEquals(Operation.values().length,called[0]);
            c.receiveRevocations(revoked(),hooks(()->{
                for(var op:Operation.values())assertThrows(IllegalStateException.class,()->c.execute(op,()->fail()));
            }));
        }
    }
    @Test void wallClockJumpsCannotExtendRotationOrRecoveryDeadlines(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);coordinator(a);a.sessions.rotateGroupKey(key(40),1);
            f.time.millis+=100_000;f.time.nanos=180_000_000_000L;assertFalse(a.sessions.isEstablished(b.id));
            Clock clock=deadlines();long now=clock.millis();f.time.millis-=200_000;assertEquals(now,clock.millis());
        }
    }
    @Test void finalNotificationIsTheOnlyRevokedPeerException(){
        try(var a=f.new Node(1);var b=f.new Node(2)){
            f.connect(a,b);var c=coordinator(a);byte[] session=a.sessions.sessionId(b.id);
            var r=revoked(b.id);var pages=ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],f.group,r.encode(),1);
            c.receiveRevocations(r,hooks(()->{
                assertTrue(c.maySendFinalNotice(b.id,session,a.sessions.generation(),pages.get(0).envelope()));
                assertFalse(c.maySendFinalNotice(b.id,session,a.sessions.generation(),new byte[]{1}));
                f.time.advance(1);assertFalse(c.maySendFinalNotice(b.id,session,a.sessions.generation(),pages.get(0).envelope()));
            }));
        }
    }
    @Test void udpReceptionContinuesWithoutDeliveringCotDuringPersistence()throws Exception{
        var fixture=new UdpEndpointTest();
        try(var a=fixture.new Node(1,"localhost");var b=fixture.new Node(2,"localhost")){
            fixture.connect(a,b);var r=new RevocationUnion(fixture.group,new AdminStateTrust(a.state));r.add(a.state.revocations());
            var c=new CorePersistenceCoordinator(a.state,a.sessions,r,fixture.clock,new MonotonicClock(fixture.ticks::get));
            byte[] old=a.sessions.sessionId(b.id);
            var list=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,fixture.group,1,fixture.clock.millis(),List.of(),fixture.admin);
            assertTrue(c.receiveRevocations(list,hooks(()->{
                long before=a.endpoint.rejectedPackets();assertTrue(b.endpoint.send(a.id,new byte[]{1}));
                try{UdpEndpointTest.await(()->a.endpoint.rejectedPackets()>before);}catch(Exception e){throw new AssertionError(e);}
                assertTrue(a.inbox.isEmpty());assertFalse(a.socket.isClosed());assertFalse(a.sessions.isClosed());
            })));
            assertArrayEquals(old,a.sessions.sessionId(b.id));assertTrue(b.endpoint.send(a.id,new byte[]{2}));
            assertArrayEquals(new byte[]{2},UdpEndpointTest.take(a));
        }
    }
}
