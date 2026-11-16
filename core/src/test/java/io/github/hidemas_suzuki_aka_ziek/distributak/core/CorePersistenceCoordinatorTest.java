// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.*;

class CorePersistenceCoordinatorTest {
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
