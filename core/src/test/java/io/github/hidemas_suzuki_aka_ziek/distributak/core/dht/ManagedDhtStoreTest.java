// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static org.junit.jupiter.api.Assertions.*;

class ManagedDhtStoreTest {
    static final class Fixture {
        long now=NOW;
        final Clock wall=new Clock(){public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return Instant.ofEpochMilli(now);}};
        final AdminState state=new AdminState(GROUP,pub(1),wall,new InMemoryAdminRecordStore());
        final RevocationUnion union;
        final List<ManagedDhtRecord> delivered=new ArrayList<>();
        final List<AdminRecords.Record> bodies=new ArrayList<>();
        final DhtRecordBudget budget=new DhtRecordBudget();
        final ManagedDhtStore store;
        Fixture(){
            var first=AdminProofFixtures.list(GROUP,0,NOW-2000,List.of(pub(1),pub(2)),secret(1),secret(1),secret(2));
            state.bootstrap(first,AdminRecords.signAnchor(first,secret(1)));union=new RevocationUnion(GROUP,new AdminStateTrust(state));
            store=new ManagedDhtStore(GROUP,wall,wall,new AdminStateTrust(state),union,id->true,budget,new ManagedDependencies(){
                public KeyAnnouncement announcement(byte[] digest){return null;}
                public AdminRecords.Record revocations(long v,byte[] d){return bodies.stream().filter(r->r.version()==v&&Crypto.equal(Crypto.blake2s(r.signedBytes()),d)).findFirst().orElse(null);}
            },delivered::add);
        }
        ManagedDhtRecord rev(long v,int n){return ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),revocations(v,NOW,n),1,0,Crypto.blake2s(state.administrators().signedBytes()),NOW,null);}
        ManagedDhtRecord announcement(AdminRecords.Record body,long version,int key){
            var a=KeyAnnouncement.issue(GROUP,secret(1),version,NOW,body.version(),Crypto.blake2s(body.signedBytes()),digest(key),0,Crypto.blake2s(state.administrators().signedBytes()));
            return ManagedDhtRecord.issue(GROUP,secret(1),a,1,0,Crypto.blake2s(state.administrators().signedBytes()),NOW);
        }
    }
    @Test void oldRevocationsAreDeliveredWithoutReplacingTheDhtWinner(){
        var f=new Fixture();var latest=f.rev(3,1);var old=f.rev(2,2);
        assertEquals(DhtWire.StoreStatus.ACCEPTED,f.store.accept(null,latest,false));
        assertEquals(DhtWire.StoreStatus.OLD,f.store.accept(null,old,false));
        assertEquals(2,f.delivered.size());assertEquals(3,f.store.get(latest.key()).version());
    }
    @Test void announcementsWaitForTheExactBodyAndRetryWithinTheOriginalPendingSlot(){
        var f=new Fixture();var body=revocations(1,NOW,0);var a=f.announcement(body,3,8);
        f.store.accept(null,a,false);assertTrue(f.delivered.isEmpty());assertEquals(1,f.store.pendingCount());
        f.bodies.add(body);f.store.retry();assertEquals(1,f.delivered.size());assertEquals(0,f.store.pendingCount());
    }
    @Test void validSameVersionConflictsAndMissingUnionAreObservedWithoutApplyingKeys(){
        var f=new Fixture();var body=revocations(1,NOW,0);f.bodies.add(body);
        f.union.add(revocations(2,NOW,1));
        var a=f.announcement(body,3,8);var b=f.announcement(body,3,9);
        f.store.accept(null,a,false);f.store.accept(null,b,false);
        assertEquals(2,f.delivered.size());assertNull(f.state.announcement());assertEquals(1,f.union.subjects().size());
    }
    @Test void pendingConflictsAreBothObservedAfterTheirBodyArrives(){
        var f=new Fixture();var body=revocations(1,NOW,0);
        f.store.accept(null,f.announcement(body,3,8),false);f.store.accept(null,f.announcement(body,3,9),false);
        assertEquals(2,f.store.pendingCount());f.bodies.add(body);f.store.retry();
        assertEquals(2,f.delivered.size());assertEquals(0,f.store.pendingCount());
    }
    @Test void fullCacheRetainsTheOriginalPendingDeadlineUntilCapacityBecomesAvailable(){
        var f=new Fixture();var body=revocations(1,NOW,0);f.store.accept(null,f.announcement(body,3,8),false);
        assertTrue(f.budget.replace(0,DhtRecordBudget.MAX_BYTES));f.bodies.add(body);f.store.retry();
        assertEquals(1,f.store.pendingCount());assertTrue(f.delivered.isEmpty());
        assertTrue(f.budget.replace(DhtRecordBudget.MAX_BYTES,0));f.store.retry();assertEquals(1,f.delivered.size());assertEquals(0,f.store.pendingCount());
    }
    @Test void nonWinnerCallbackFailureRestoresOnlyTheFailedEntryWithItsOriginalDeadline(){
        var f=new Fixture();var body=revocations(1,NOW,0);var a=f.announcement(body,3,8);var b=f.announcement(body,3,9);
        var verifier=new ManagedVerifier(new AdminStateTrust(f.state),f.wall,f.union,f.store).observingAnnouncements();
        var pending=new ManagedPending(f.wall,verifier,id->true);
        pending.offer(a,ManagedVerdict.NEEDS_ANNOUNCEMENT);pending.offer(b,ManagedVerdict.NEEDS_ANNOUNCEMENT);f.bodies.add(body);
        var winner=KeyAnnouncement.compare(a.announcement(),b.announcement())>0?a:b;
        var successful=new ArrayList<ManagedDhtRecord>();int[] calls={0};
        assertThrows(IllegalStateException.class,()->pending.retry(verifier,key->winner,checked->{
            if(++calls[0]==2)throw new IllegalStateException("injected callback failure");successful.add(checked.record());
        },true));
        assertEquals(1,successful.size());assertEquals(1,pending.size());
        pending.retry(verifier,key->winner,checked->successful.add(checked.record()),true);assertEquals(2,successful.size());assertEquals(0,pending.size());
        assertFalse(Arrays.equals(successful.get(0).encode(),successful.get(1).encode()));
        var expiring=new ManagedPending(f.wall,verifier,id->true);expiring.offer(a,ManagedVerdict.NEEDS_ANNOUNCEMENT);
        f.now+=119999;assertThrows(IllegalStateException.class,()->expiring.retry(verifier,key->winner,checked->{throw new IllegalStateException("injected callback failure");},true));
        f.now++;assertEquals(0,expiring.size());
    }
    @Test void productionStoreRequiresCurrentAuthorityAndSenderQualification(){
        var f=new Fixture();
        assertThrows(NullPointerException.class,()->new ManagedDhtStore(GROUP,f.wall,f.wall,null,f.union,id->true,new DhtRecordBudget(),f.store,f.delivered::add));
        assertThrows(NullPointerException.class,()->new ManagedDhtStore(GROUP,f.wall,f.wall,new AdminStateTrust(f.state),f.union,null,new DhtRecordBudget(),f.store,f.delivered::add));
    }
    @Test void invalidSignersAndMismatchedBodiesDoNotReachTheConsumer(){
        var f=new Fixture();var body=revocations(1,NOW,0);f.bodies.add(body);
        var a=f.announcement(body,3,8);byte[] bad=a.encode();bad[bad.length-1]^=1;
        assertEquals(DhtWire.StoreStatus.INVALID,f.store.acceptBytes(null,bad,false));
        var wrong=ManagedDhtRecord.issue(GROUP,secret(3),a.announcement(),1,0,Crypto.blake2s(f.state.administrators().signedBytes()),NOW);
        assertEquals(DhtWire.StoreStatus.INVALID,f.store.accept(null,wrong,false));assertTrue(f.delivered.isEmpty());
    }
    @Test void storeRequiresTheAuthenticatedAdministratorBinding(){
        var f=new Fixture();assertEquals(DhtWire.StoreStatus.INVALID,f.store.accept(new byte[32],f.rev(1,1),true));
        assertTrue(f.delivered.isEmpty());assertEquals(0,f.store.size());
    }
    @Test void sharedBudgetRejectsWithoutDeletingThePreviousWinnerAndReleasesOnClear(){
        var f=new Fixture();var first=f.rev(1,1);assertEquals(DhtWire.StoreStatus.ACCEPTED,f.store.accept(null,first,false));
        int held=first.encode().length;assertTrue(f.budget.replace(0,DhtRecordBudget.MAX_BYTES-held));
        assertEquals(DhtWire.StoreStatus.FULL,f.store.accept(null,f.rev(2,2),false));
        assertEquals(1,f.store.get(first.key()).version());assertEquals(1,f.delivered.size());
        f.store.clear();assertEquals(DhtRecordBudget.MAX_BYTES-held,f.budget.bytes());
    }
    @Test void pendingExpiresAndStorageExpiresAtTheOriginalWallDeadline(){
        var f=new Fixture();var a=f.announcement(revocations(1,NOW,0),3,8);f.store.accept(null,a,false);
        f.now+=120000;f.bodies.add(revocations(1,NOW,0));f.store.retry();assertTrue(f.delivered.isEmpty());
        var record=f.rev(2,1);f.store.accept(null,record,false);f.now=record.expiresAt();assertNull(f.store.get(record.key()));assertEquals(0,f.budget.bytes());
    }
    @Test void retryPurgesSharedExpiredCopiesAtTheExactBoundaryBeforeAdmittingPending(){
        var f=new Fixture();var old=f.rev(1,100);assertEquals(DhtWire.StoreStatus.ACCEPTED,f.store.accept(null,old,false));
        assertTrue(f.budget.replace(0,DhtRecordBudget.MAX_BYTES-old.encode().length));
        f.now=old.expiresAt()-60000;var body=revocations(2,f.now,0);var admins=f.state.administrators();
        var notice=KeyAnnouncement.issue(GROUP,secret(1),4,f.now,body.version(),Crypto.blake2s(body.signedBytes()),digest(8),admins.version(),Crypto.blake2s(admins.signedBytes()));
        var record=ManagedDhtRecord.issue(GROUP,secret(1),notice,1,admins.version(),Crypto.blake2s(admins.signedBytes()),f.now);
        f.store.accept(null,record,false);assertEquals(1,f.store.pendingCount());f.bodies.add(body);
        f.now=old.expiresAt()-1;f.store.retry();assertEquals(1,f.store.pendingCount());assertEquals(1,f.delivered.size());
        f.now++;f.store.retry();assertEquals(0,f.store.pendingCount());assertEquals(2,f.delivered.size());
        assertNull(f.store.get(old.key()));assertNotNull(f.store.get(record.key()));
    }

    @Test void retryOnlyAbsorbsExplicitUncommittedFailureAndPreservesItsDeadline(){
        var f=new Fixture();boolean[] deferred={true};
        var store=new ManagedDhtStore(GROUP,f.wall,f.wall,new AdminStateTrust(f.state),f.union,id->true,f.budget,f.store,record->{
            if(deferred[0])throw new ManagedDhtStore.PersistenceDeferred();throw new IllegalStateException("Injected invariant failure");
        });
        var body=revocations(1,NOW,0);store.accept(null,f.announcement(body,3,8),false);f.bodies.add(body);
        f.now+=119999;assertDoesNotThrow(store::retry);assertEquals(1,store.pendingCount());assertEquals(0,f.budget.bytes());
        deferred[0]=false;assertThrows(IllegalStateException.class,store::retry);assertEquals(1,store.pendingCount());
        f.now++;store.retry();assertEquals(0,store.pendingCount());assertEquals(0,f.budget.bytes());
    }

}
