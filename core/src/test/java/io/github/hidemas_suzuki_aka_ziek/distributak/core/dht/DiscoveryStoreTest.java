// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.HashSet;
import java.util.Set;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecordTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryStatus.*;
import static org.junit.jupiter.api.Assertions.*;

class DiscoveryStoreTest {
    static final long DAY_NANOS=DhtLimits.RECORD_LIFETIME_MILLIS*1_000_000L;
    static AuthenticatedPeer publisher(DiscoveryRecord record){return AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(record.nodeId()));}
    static final class Fixture {
        final DhtNodeTest.Wall wall=new DhtNodeTest.Wall();final AtomicLong nanos=new AtomicLong();
        final Set<DhtId> revoked=new HashSet<>();final DiscoveryStore store;
        Fixture(){this(DiscoveryStore.MAX_ENCODED_BYTES);}
        Fixture(int bytes){wall.millis=NOW;store=new DiscoveryStore(GROUP,wall,nanos::get,revoked::contains,bytes);}
        DiscoveryStatus put(DiscoveryRecord record){return store.put(publisher(record),record.encode());}
        void expire(){wall.millis=NOW+DhtLimits.RECORD_LIFETIME_MILLIS;store.purge();}
    }
    @Test void acceptedCopiesAreOwnedByTheirPublisherAndEncodedBytesAreCounted() {
        var f=new Fixture();var r=record(1,1,NOW);assertEquals(ACCEPTED,f.put(r));
        assertEquals(1,f.store.size());assertEquals(1,f.store.maximumSize());assertEquals(r.encode().length,f.store.encodedBytes());
        assertArrayEquals(r.encode(),f.store.get(r.key()).orElseThrow().encode());
        assertEquals(SENDER_MISMATCH,f.store.put(publisher(record(2,1,NOW)),record(3,1,NOW).encode()));
        assertEquals(1,f.store.size());assertEquals(1,f.store.maximumSize());
    }
    @Test void oldAndConflictingVersionsCannotDisplaceTheFirstCopy() {
        var f=new Fixture();var r=record(1,2,NOW);f.put(r);
        assertEquals(OLD_VERSION,f.put(record(1,1,NOW)));assertEquals(DUPLICATE,f.put(r));
        var conflict=DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,IP,50001,2,NOW);
        assertEquals(CONFLICT,f.put(conflict));assertArrayEquals(r.encode(),f.store.get(r.key()).orElseThrow().encode());
        assertEquals(ACCEPTED,f.put(record(1,3,NOW)));assertEquals(3,f.store.get(r.key()).orElseThrow().version());
    }
    @Test void expiredCopiesLeaveTheirMaximumForExactlyTwentyFourMonotonicHours() {
        var f=new Fixture();var r=record(1,2,NOW);f.put(r);f.expire();
        assertEquals(0,f.store.size());assertEquals(1,f.store.maximumSize());
        assertEquals(OLD_VERSION,f.put(record(1,1,f.wall.millis)));
        f.nanos.set(DAY_NANOS-1);f.store.purge();assertEquals(1,f.store.maximumSize());
        f.nanos.incrementAndGet();f.store.purge();assertEquals(0,f.store.maximumSize());
        assertEquals(ACCEPTED,f.put(record(1,1,f.wall.millis)));
    }
    @Test void duplicateReceptionDoesNotExtendCopyOrMaximumLifetime() {
        var f=new Fixture();var r=record(1,2,NOW);f.put(r);
        f.wall.millis=r.expiresAt()-1;f.nanos.set(DAY_NANOS-1);assertEquals(DUPLICATE,f.put(r));
        assertEquals(r.expiresAt(),f.store.get(r.key()).orElseThrow().expiresAt());
        f.wall.millis=r.expiresAt();f.nanos.incrementAndGet();f.store.purge();assertEquals(0,f.store.size());
        f.wall.millis=NOW+1;assertEquals(DUPLICATE,f.put(r));assertEquals(0,f.store.size());
        f.nanos.set(2*DAY_NANOS);f.store.purge();assertEquals(0,f.store.maximumSize());
    }
    @Test void aNewVersionStartsRetentionOnlyWhenItsOwnCopyIsRemoved() {
        var f=new Fixture();f.put(record(1,1,NOW));f.nanos.set(DAY_NANOS);f.expire();
        var newer=record(1,2,f.wall.millis);assertEquals(ACCEPTED,f.put(newer));
        f.nanos.set(2*DAY_NANOS);f.wall.millis=newer.expiresAt();f.store.purge();assertEquals(1,f.store.maximumSize());
        f.nanos.set(3*DAY_NANOS-1);f.store.purge();assertEquals(1,f.store.maximumSize());
        f.nanos.incrementAndGet();f.store.purge();assertEquals(0,f.store.maximumSize());
    }
    @Test void monotonicClockResetRebasesRetentionWithoutShorteningIt() {
        var f=new Fixture();f.put(record(1,1,NOW));f.nanos.set(1000);f.expire();
        f.nanos.set(500);f.store.purge();f.nanos.set(500+DAY_NANOS-1);f.store.purge();assertEquals(1,f.store.maximumSize());
        f.nanos.incrementAndGet();f.store.purge();assertEquals(0,f.store.maximumSize());
    }
    @Test void revokedCopiesAreRemovedButTheirMaximumIsRetained() {
        var f=new Fixture();var a=record(1,1,NOW);var b=record(2,1,NOW);f.put(a);f.put(b);
        f.revoked.add(a.nodeId());f.store.removeRevoked();assertTrue(f.store.get(a.key()).isEmpty());
        assertEquals(1,f.store.size());assertEquals(2,f.store.maximumSize());assertEquals(REVOKED,f.put(record(1,2,NOW)));
        f.nanos.set(DAY_NANOS);f.store.purge();assertEquals(1,f.store.maximumSize());
    }
    @Test void clearRemovesUnexpiredCopiesAndCountsButStillAcceptsNewRecords() {
        var f=new Fixture();var a=record(1,2,NOW);var b=record(2,1,NOW);
        assertEquals(ACCEPTED,f.put(a));assertEquals(ACCEPTED,f.put(b));
        f.store.purge();assertEquals(2,f.store.size());// 期限内なので purge では消えない
        f.store.clear();
        assertEquals(0,f.store.size());assertEquals(0,f.store.encodedBytes());
        assertTrue(f.store.get(a.key()).isEmpty());assertTrue(f.store.get(b.key()).isEmpty());
        // 版の巻き戻しを防ぐ検査は今までどおり（期限・失効で消したときと同じ）
        assertEquals(2,f.store.maximumSize());assertEquals(OLD_VERSION,f.put(record(1,1,NOW)));
        // 新しい記録は今までどおり受ける。別の発行者の記録も受ける
        assertEquals(ACCEPTED,f.put(record(1,3,NOW)));assertEquals(ACCEPTED,f.put(record(3,1,NOW)));
        assertEquals(2,f.store.size());
        // 空の表に clear しても壊れない
        f.store.clear();f.store.clear();assertEquals(0,f.store.size());
        f.nanos.set(DAY_NANOS);f.store.purge();assertEquals(0,f.store.maximumSize());
        assertEquals(ACCEPTED,f.put(record(1,1,NOW)));
    }
    @Test void defaultRecordAndMaximumLimitsAre4096WithoutEvictingAnyValidCopy() {
        var f=new Fixture();assertEquals(4096,DiscoveryStore.MAX_RECORDS);
        for(int n=1;n<=4096;n++)assertEquals(ACCEPTED,f.put(record(n,1,NOW)));
        var extra=record(4097,1,NOW);assertEquals(CAPACITY,f.put(extra));assertEquals(4096,f.store.size());
        assertTrue(f.store.get(record(1,1,NOW).key()).isPresent());assertTrue(f.store.encodedBytes()<=DiscoveryStore.MAX_ENCODED_BYTES);
        f.expire();assertEquals(0,f.store.size());assertEquals(4096,f.store.maximumSize());
        var fresh=record(4097,1,f.wall.millis);assertEquals(CAPACITY,f.put(fresh));
        f.nanos.set(DAY_NANOS-1);assertEquals(CAPACITY,f.put(fresh));
        f.nanos.incrementAndGet();f.store.purge();assertEquals(ACCEPTED,f.put(fresh));assertEquals(1,f.store.maximumSize());
    }
    @Test void encodedByteQuotaUsesActualSizesAndExpiresCopiesBeforeAdmission() {
        var a=record(1,1,NOW);var b=record(2,1,NOW);int budget=a.encode().length+b.encode().length;
        var f=new Fixture(budget);assertEquals(ACCEPTED,f.put(a));assertEquals(ACCEPTED,f.put(b));
        assertEquals(budget,f.store.encodedBytes());assertEquals(CAPACITY,f.put(record(3,1,NOW)));
        assertEquals(CAPACITY,f.put(record(1,128,NOW)));assertEquals(1,f.store.get(a.key()).orElseThrow().version());
        f.wall.millis=a.expiresAt();assertEquals(ACCEPTED,f.put(record(3,1,f.wall.millis)));assertEquals(1,f.store.size());
    }
    @Test void fourMiBArithmeticIsInclusiveAndCannotOverflow() {
        long limit=4*1024*1024;assertEquals(limit,DiscoveryStore.MAX_ENCODED_BYTES);
        assertTrue(DiscoveryStore.hasByteCapacity(limit,0,0,limit));assertFalse(DiscoveryStore.hasByteCapacity(limit,0,1,limit));
        assertTrue(DiscoveryStore.hasByteCapacity(limit,1,1,limit));assertFalse(DiscoveryStore.hasByteCapacity(Long.MAX_VALUE,0,1,limit));
        assertFalse(DiscoveryStore.hasByteCapacity(0,1,1,limit));
        assertEquals(1,DiscoveryStore.class.getConstructors().length);
    }
    @Test void rejectedUpdatesDoNotAdvanceMaximumOrDestroyTheOldCopy() {
        var old=record(1,1,NOW);var f=new Fixture(old.encode().length);f.put(old);
        assertEquals(CAPACITY,f.put(record(1,128,NOW)));assertEquals(ACCEPTED,f.put(record(1,2,NOW)));
        assertEquals(2,f.store.get(old.key()).orElseThrow().version());assertEquals(1,f.store.maximumSize());
    }
    @Test void refusalCountersSeparateAllReasonsAndDuplicatesAreNotRejections() {
        var value=record(1,2,NOW);var f=new Fixture(value.encode().length);f.put(value);assertEquals(DUPLICATE,f.put(value));
        assertEquals(INVALID,f.store.put(publisher(value),new byte[0]));
        var revoked=record(3,1,NOW);f.revoked.add(revoked.nodeId());assertEquals(REVOKED,f.put(revoked));
        assertEquals(EXPIRED,f.put(record(4,1,NOW-DhtLimits.RECORD_LIFETIME_MILLIS-1)));
        assertEquals(SENDER_MISMATCH,f.store.put(publisher(record(5,1,NOW)),record(6,1,NOW).encode()));
        assertEquals(OLD_VERSION,f.put(record(1,1,NOW)));
        assertEquals(CONFLICT,f.put(DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,IP,50001,2,NOW)));
        assertEquals(CAPACITY,f.put(record(7,1,NOW)));
        for(var status:new DiscoveryStatus[]{INVALID,REVOKED,EXPIRED,SENDER_MISMATCH,OLD_VERSION,CONFLICT,CAPACITY})assertEquals(1,f.store.counts().count(status));
        assertEquals(2,f.store.counts().screenRejected());assertEquals(0,f.store.counts().count(DUPLICATE));
        assertEquals("DHT discovery counters",f.store.counts().toString());
    }
    @Test void lookupValidationReadsStoreMaximumButNeverPopulatesItsTables() {
        var f=new Fixture();var stored=record(1,3,NOW);f.put(stored);var policy=f.store.newLookupVerifier();
        reject(OLD_VERSION,()->policy.verify(stored.key(),record(1,2,NOW).encode(),f.wall));
        var unknown=record(2,1,NOW);assertNotNull(policy.verify(unknown.key(),unknown.encode(),f.wall));
        assertEquals(1,f.store.size());assertEquals(1,f.store.maximumSize());assertTrue(f.store.get(unknown.key()).isEmpty());
        reject(INVALID,()->policy.verify(DhtIdTest.id(99),unknown.encode(),f.wall));
        assertEquals(1,policy.counts().count(OLD_VERSION));assertEquals(0,f.store.counts().count(OLD_VERSION));
    }
    @Test void everyLookupKeepsItsOwnFirstPayloadForEachVersion() {
        var f=new Fixture();var a=record(1,1,NOW);var b=DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,IP,50001,1,NOW);
        var first=f.store.newLookupVerifier();assertNotNull(first.verify(a.key(),a.encode(),f.wall));
        reject(CONFLICT,()->first.verify(b.key(),b.encode(),f.wall));assertNotNull(first.verify(a.key(),a.encode(),f.wall));
        assertNotNull(f.store.newLookupVerifier().verify(b.key(),b.encode(),f.wall));
        assertEquals(0,f.store.size());assertEquals(0,f.store.maximumSize());
    }
    @Test void lookupHistoryCannotGrowBeyondTheQueryBudget() {
        var f=new Fixture();var policy=f.store.newLookupVerifier();
        for(int n=1;n<=128;n++){var value=record(1,n,NOW);assertNotNull(policy.verify(value.key(),value.encode(),f.wall));}
        var extra=record(1,129,NOW);reject(CAPACITY,()->policy.verify(extra.key(),extra.encode(),f.wall));
        assertEquals(0,f.store.maximumSize());
    }
    /** 核 C1 手順 1: STORE と FIND_VALUE のどちらでも、偽署名で期限切れ・失効を名のる記録は INVALID。 */
    @Test void forgedSignatureIsInvalidForStoreAndFindValueEvenWhenExpiredOrRevoked() {
        var f=new Fixture();var value=record(1,1,NOW);byte[] bad=value.signature();bad[0]^=1;byte[] forged=envelope(value.payload(),bad);
        f.wall.millis=value.expiresAt();assertEquals(INVALID,f.store.put(publisher(value),forged));
        f.wall.millis=NOW;f.revoked.add(value.nodeId());assertEquals(INVALID,f.store.put(publisher(value),forged));
        assertEquals(2,f.store.counts().count(INVALID));assertEquals(0,f.store.counts().count(EXPIRED));assertEquals(0,f.store.counts().count(REVOKED));
        assertEquals(0,f.store.counts().screenRejected()-2);
        var policy=f.store.newLookupVerifier();
        reject(INVALID,()->policy.verify(value.key(),forged,f.wall));
        f.wall.millis=value.expiresAt();reject(INVALID,()->policy.verify(value.key(),forged,f.wall));
        assertEquals(2,policy.counts().count(INVALID));assertEquals(0,policy.counts().count(EXPIRED));assertEquals(0,policy.counts().count(REVOKED));
    }
    /** 核 C1 手順 1: 失効の判定が例外を出しても外へ出さず、判定できない記録は除く。 */
    @Test void purgeContainsRevocationCheckerExceptionsAndDropsUnjudgeableCopies() {
        var wall=new DhtNodeTest.Wall();wall.millis=NOW;var nanos=new AtomicLong();var broken=new java.util.concurrent.atomic.AtomicBoolean();
        var store=new DiscoveryStore(GROUP,wall,nanos::get,id->{if(broken.get())throw new IllegalStateException("secret-detail");return false;},DiscoveryStore.MAX_ENCODED_BYTES);
        var a=record(1,1,NOW);var b=record(2,1,NOW);
        assertEquals(ACCEPTED,store.put(publisher(a),a.encode()));assertEquals(ACCEPTED,store.put(publisher(b),b.encode()));
        broken.set(true);assertDoesNotThrow(store::purge);assertDoesNotThrow(store::removeRevoked);
        assertEquals(0,store.size());assertEquals(0,store.encodedBytes());assertTrue(store.get(a.key()).isEmpty());
        assertEquals(2,store.maximumSize());
        broken.set(false);assertEquals(OLD_VERSION,store.put(publisher(a),record(1,0,NOW).encode()));
        assertEquals(ACCEPTED,store.put(publisher(a),record(1,2,NOW).encode()));
        assertEquals(0,store.counts().screenRejected());
    }
    /** 核 C1 手順 1: 時計が例外を出しても外へ出さず、期限を判定できない記録は除く。 */
    @Test void purgeAndGetContainWallClockExceptions() {
        var broken=new java.util.concurrent.atomic.AtomicBoolean();var wall=new java.time.Clock(){
            @Override public java.time.ZoneId getZone(){return java.time.ZoneOffset.UTC;}
            @Override public java.time.Clock withZone(java.time.ZoneId zone){return this;}
            @Override public java.time.Instant instant(){return java.time.Instant.ofEpochMilli(millis());}
            @Override public long millis(){if(broken.get())throw new IllegalStateException("secret-detail");return NOW;}};
        var store=new DiscoveryStore(GROUP,wall,new AtomicLong()::get,id->false,DiscoveryStore.MAX_ENCODED_BYTES);
        var a=record(1,1,NOW);assertEquals(ACCEPTED,store.put(publisher(a),a.encode()));
        broken.set(true);assertDoesNotThrow(store::purge);assertEquals(0,store.size());
        assertTrue(store.get(a.key()).isEmpty());assertEquals(INVALID,store.put(publisher(a),a.encode()));
    }
    @Test void lookupClockMaintenanceDoesNotWriteToMaximumEntries() throws Exception {
        var f=new Fixture();f.put(record(1,1,NOW));f.nanos.set(1000);f.expire();
        var maxima=DiscoveryStore.class.getDeclaredField("maxima");maxima.setAccessible(true);
        var entry=((java.util.Map<?,?>)maxima.get(f.store)).values().iterator().next();
        var removedAt=entry.getClass().getDeclaredField("removedAt");removedAt.setAccessible(true);
        f.nanos.set(500);var other=record(2,1,f.wall.millis);var policy=f.store.newLookupVerifier();
        assertNotNull(policy.verify(other.key(),other.encode(),f.wall));
        assertEquals(1000,removedAt.getLong(entry));assertEquals(0,f.store.size());assertEquals(1,f.store.maximumSize());
        f.nanos.set(500+DAY_NANOS-1);f.store.purge();assertEquals(1,f.store.maximumSize());
        f.nanos.incrementAndGet();f.store.purge();assertEquals(0,f.store.maximumSize());
    }
    /** 核 B 引き継ぎ: 探索ごとの件数は、探索が終わるとき 1 回だけ預かりの表の件数へ足す。 */
    @Test void lookupCountsAreAddedToTheStoreOnlyOnceWhenTheLookupFinishes() {
        var f=new Fixture();var stored=record(1,3,NOW);f.put(stored);var policy=f.store.newLookupVerifier();
        reject(OLD_VERSION,()->policy.verify(stored.key(),record(1,2,NOW).encode(),f.wall));
        reject(INVALID,()->policy.verify(DhtIdTest.id(99),record(2,1,NOW).encode(),f.wall));
        assertEquals(0,f.store.counts().count(OLD_VERSION));assertEquals(0,f.store.counts().count(INVALID));
        policy.finished();policy.finished();
        assertEquals(1,f.store.counts().count(OLD_VERSION));assertEquals(1,f.store.counts().count(INVALID));
        assertEquals(1,f.store.counts().screenRejected());
        // 終わったあとに増えた件数は、二度目の通知では足さない（一探索で一度だけ）。
        reject(INVALID,()->policy.verify(DhtIdTest.id(98),record(2,1,NOW).encode(),f.wall));
        policy.finished();assertEquals(1,f.store.counts().count(INVALID));
    }
    /** 失効の判定や時計の中から預かりの表を呼ぶと断る。表の状態は壊れず、その後も使える。 */
    @Test void reenteringTheStoreFromTheRevocationCheckIsRefused() {
        var wall=new DhtNodeTest.Wall();wall.millis=NOW;var nanos=new AtomicLong();
        var seen=new java.util.ArrayList<RuntimeException>();var storeRef=new java.util.concurrent.atomic.AtomicReference<DiscoveryStore>();
        var a=record(1,1,NOW);var b=record(2,1,NOW);
        var store=new DiscoveryStore(GROUP,wall,nanos::get,id->{
            var inner=storeRef.get();
            try{inner.put(publisher(b),b.encode());}catch(IllegalStateException e){seen.add(e);}
            try{inner.get(a.key());}catch(IllegalStateException e){seen.add(e);}
            try{inner.purge();}catch(IllegalStateException e){seen.add(e);}
            return false;
        },DiscoveryStore.MAX_ENCODED_BYTES);
        storeRef.set(store);
        assertEquals(ACCEPTED,store.put(publisher(a),a.encode()));
        assertEquals(3,seen.size());
        for(var e:seen){assertEquals("DHTの預かりの表は呼び出しの途中で使えません",e.getMessage());}
        assertEquals(1,store.size());assertEquals(1,store.maximumSize());assertEquals(a.encode().length,store.encodedBytes());
        seen.clear();assertTrue(store.get(a.key()).isPresent());assertEquals(3,seen.size());
        seen.clear();store.purge();assertEquals(3,seen.size());assertEquals(1,store.size());
        // 例外のあとも、押さえた印が残らず通常どおり使える。
        // 判定の中で別の例外が出ても、押さえた印が残らず（再入の例外にならず）、除く側に倒れる。
        storeRef.set(null);assertDoesNotThrow(()->store.get(a.key()));assertTrue(store.get(a.key()).isEmpty());assertEquals(0,store.size());
    }
    /** 期限切れのコピーで 4096 件が埋まっていても、期限が来たあとの新しい正しい記録を預かれる。 */
    @Test void expiredCopiesFillingTheTableDoNotBlockNewValidRecords() {
        var f=new Fixture();
        for(int n=1;n<=DiscoveryStore.MAX_RECORDS;n++)assertEquals(ACCEPTED,f.put(record(n,1,NOW)));
        assertEquals(DiscoveryStore.MAX_RECORDS,f.store.size());
        var fresh=record(DiscoveryStore.MAX_RECORDS+1,1,NOW);
        // 満杯のあいだは断る。
        assertEquals(CAPACITY,f.put(fresh));
        // 期限が来たあとは purge を明示せず、put の先頭の purge だけで空き、同じ発行者の新しい版を預かれる。
        f.wall.millis=NOW+DhtLimits.RECORD_LIFETIME_MILLIS;
        assertEquals(ACCEPTED,f.put(record(1,2,f.wall.millis)));
        assertEquals(1,f.store.size());assertEquals(DiscoveryStore.MAX_VERSIONS,f.store.maximumSize());
        // 除いたあとの最大版は 24 時間（単調時計）残る設計なので、初めての発行者はその間は最大版の表の上限で断る。24 時間たてば預かれる。
        assertEquals(CAPACITY,f.put(record(DiscoveryStore.MAX_RECORDS+1,1,f.wall.millis)));
        f.nanos.set(DAY_NANOS);
        assertEquals(ACCEPTED,f.put(record(DiscoveryStore.MAX_RECORDS+1,1,f.wall.millis)));
        assertEquals(2,f.store.size());
    }
    /** get は、間引きのあとすぐに期限が来た記録・失効した記録を返さない。 */
    @Test void getNeverReturnsAnExpiredOrRevokedRecordEvenRightAfterAPurge() {
        var f=new Fixture();var a=record(1,1,NOW);var b=record(2,1,NOW);f.put(a);f.put(b);
        assertTrue(f.store.get(a.key()).isPresent());
        // 時計の進め方: a・b は同じ時刻に作ったので、期限の 1 ミリ秒前までは返し、
        // 期限ちょうどの時刻に進めると get が期限切れを掃除して返さない（a と b の両方が消える）。
        f.wall.millis=a.expiresAt()-1;assertTrue(f.store.get(a.key()).isPresent());
        f.wall.millis=a.expiresAt();assertTrue(f.store.get(a.key()).isEmpty());assertEquals(0,f.store.size());
        // 掃除の直後（時計は期限の時刻のまま）に新しい記録 c を入れ、あとで失効の一覧に入れると get は返さない。
        var c=record(3,1,f.wall.millis);f.put(c);assertTrue(f.store.get(c.key()).isPresent());
        f.revoked.add(c.nodeId());assertTrue(f.store.get(c.key()).isEmpty());assertEquals(0,f.store.size());
    }

    // ---- 自分の記録（核 D の直し 推奨 4）。送り手の認証つきの型を使わず、同じ検査の道を通す。 ----
    @Test void anOwnRecordGoesThroughTheSameChecksAndIsCountedApartFromRejections() {
        var f=new Fixture();var r=record(1,2,NOW);
        assertEquals(ACCEPTED,f.store.putOwn(r.nodeId(),r.encode()));
        assertEquals(1,f.store.size());assertArrayEquals(r.encode(),f.store.get(r.key()).orElseThrow().encode());
        assertEquals(DUPLICATE,f.store.putOwn(r.nodeId(),r.encode()));
        assertEquals(OLD_VERSION,f.store.putOwn(r.nodeId(),record(1,1,NOW).encode()));
        var conflict=DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,IP,50001,2,NOW);
        assertEquals(CONFLICT,f.store.putOwn(r.nodeId(),conflict.encode()));
        assertEquals(SENDER_MISMATCH,f.store.putOwn(record(2,1,NOW).nodeId(),record(3,1,NOW).encode()));
        assertEquals(SENDER_MISMATCH,f.store.putOwn(null,r.encode()));
        assertEquals(INVALID,f.store.putOwn(r.nodeId(),new byte[]{1,2,3}));
        var c=f.store.counts();
        assertEquals(2,c.ownAccepted(),"ACCEPTED と DUPLICATE");assertEquals(5,c.ownRejected());
        for(var status:DiscoveryStatus.values())assertEquals(0,c.count(status),"他の相手から受けた拒否の件数には混ぜない: "+status);
        assertEquals(0,c.screenRejected());
    }
    @Test void anOwnRecordFollowsTheCapacityAndLifetimeRulesOfTheStore() {
        var f=new Fixture(1);var r=record(1,1,NOW);
        assertEquals(CAPACITY,f.store.putOwn(r.nodeId(),r.encode()));assertEquals(0,f.store.size());assertEquals(1,f.store.counts().ownRejected());
        var g=new Fixture();var old=record(1,1,NOW);g.wall.millis=old.expiresAt();
        assertEquals(EXPIRED,g.store.putOwn(old.nodeId(),old.encode()),"期限の切れた記録は預からない");
        var h=new Fixture();var revokedRecord=record(1,1,NOW);h.revoked.add(revokedRecord.nodeId());
        assertEquals(REVOKED,h.store.putOwn(revokedRecord.nodeId(),revokedRecord.encode()));assertEquals(0,h.store.size());
    }
    @Test void anOtherPeersRejectionStillCountsAsBeforeAndOwnCountsStayZero() {
        var f=new Fixture();f.put(record(1,2,NOW));
        assertEquals(OLD_VERSION,f.put(record(1,1,NOW)));assertEquals(SENDER_MISMATCH,f.store.put(publisher(record(2,1,NOW)),record(3,1,NOW).encode()));
        assertEquals(DUPLICATE,f.put(record(1,2,NOW)));
        var c=f.store.counts();
        assertEquals(1,c.count(OLD_VERSION));assertEquals(1,c.count(SENDER_MISMATCH));assertEquals(0,c.count(DUPLICATE));assertEquals(0,c.count(ACCEPTED));
        assertEquals(0,c.ownAccepted());assertEquals(0,c.ownRejected());
    }
    @Test void aReentrantOwnPutIsRefusedLikeAnyOtherPut() {
        var f=new Fixture();
        // 失効の判定の中から putOwn を呼ぶと、途中の状態を壊すので断る。
        var cell=new DiscoveryStore[1];var seen=new boolean[1];
        cell[0]=new DiscoveryStore(GROUP,f.wall,f.nanos::get,id->{
            seen[0]=true;
            assertThrows(IllegalStateException.class,()->cell[0].putOwn(id,record(1,1,NOW).encode()));
            return false;
        });
        var r=record(1,1,NOW);assertEquals(ACCEPTED,cell[0].put(publisher(r),r.encode()));
        cell[0].purge();
        assertTrue(seen[0]);
    }
}
