// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedDhtRecordTest.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.ManagedVerdict.Status.*;
import static org.junit.jupiter.api.Assertions.*;

class ManagedKeyVerifierTest {
    private final Clock clock=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
    private AdminState state;
    private RevocationUnion union;
    private ManagedVerifier verifier;
    private final List<KeyAnnouncement> announcements=new ArrayList<>();
    private final List<AdminRecords.Record> revocations=new ArrayList<>();
    private AdminRecords.Record certificate;
    private byte[] member,handshake;
    @BeforeEach void setUp() {
        state=new AdminState(GROUP,pub(1),clock,new InMemoryAdminRecordStore());
        var admins=AdminProofFixtures.list(GROUP,0,NOW-10000,List.of(pub(1),pub(2)),secret(1),secret(1),secret(2));
        state.bootstrap(admins,AdminRecords.signAnchor(admins,secret(1)));
        var trust=new AdminStateTrust(state);union=new RevocationUnion(GROUP,trust);
        verifier=new ManagedVerifier(trust,clock,union,new ManagedDependencies(){
            public KeyAnnouncement announcement(byte[] digest){return announcements.stream().filter(a->Crypto.equal(Crypto.blake2s(a.signedBytes()),digest)).findFirst().orElse(null);}
            public AdminRecords.Record revocations(long version,byte[] digest){return revocations.stream().filter(r->r.version()==version&&Crypto.equal(Crypto.blake2s(r.signedBytes()),digest)).findFirst().orElse(null);}
        });
        member=Crypto.blake2s(pub(7));handshake=Crypto.x25519Public(secret(8));
        certificate=cert(NOW-1000,1,handshake);
        revocations.add(AdminRecords.initialRevocations(GROUP,NOW-2000,secret(1)));
    }
    AdminRecords.Record cert(long issued,int signer,byte[] handshakeKey) {
        return AdminRecords.certificate(GROUP,pub(7),handshakeKey,SignaturePurpose.identityProof(secret(7),GROUP,handshakeKey),issued,secret(signer));
    }
    byte[] adminDigest(){return Crypto.blake2s(state.administratorsAt(0).signedBytes());}
    KeyAnnouncement announce(long version,long time,int signer,AdminRecords.Record rev) {
        var a=KeyAnnouncement.issue(GROUP,secret(signer),version,time,rev.version(),Crypto.blake2s(rev.signedBytes()),digest(8),0,adminDigest());
        announcements.add(a);return a;
    }
    KeyAnnouncement announce(long version,long time){return announce(version,time,1,revocations.get(0));}
    ManagedDhtRecord outer(KeyAnnouncement a,int signer){return ManagedDhtRecord.issue(GROUP,secret(signer),a,1,0,adminDigest(),NOW);}
    ManagedDhtRecord wrap(KeyAnnouncement a,AdminRecords.Record cert,long time,int signer) {
        var w=AdminRecords.wrapped(GROUP,a.keyVersion(),time,member,cert.field(1),digest(3),new byte[48],secret(signer),Crypto.blake2s(a.signedBytes()));
        return ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(signer),w,1,0,adminDigest(),NOW,cert.encode());
    }
    void expect(ManagedVerdict.Status wanted,ManagedDhtRecord candidate,ManagedDhtRecord held){
        assertEquals(wanted,verifier.judge(ManagedDhtRecord.verifyStructure(candidate.encode(),GROUP),held).status());
    }
    @Test void threePartiesCanStoreAndFetchUsingOnlyTheAttachedRecipientCertificate() {
        var announcement=announce(3,NOW);
        var byA=wrap(announcement,certificate,NOW,1);
        var snapshot=state.snapshot();
        expect(ACCEPTED,byA,null);
        var heldByC=ManagedDhtRecord.verifyStructure(byA.encode(),GROUP);
        expect(DUPLICATE,heldByC,heldByC);
        assertArrayEquals(member,heldByC.subject());
        assertEquals(snapshot.administratorVersion(),state.snapshot().administratorVersion());
        assertEquals(snapshot.records().size(),state.snapshot().records().size());
        assertNull(state.snapshot().revocations());
    }
    @Test void announcementsRequireTheRevocationBodyAndCoverTheWholeUnion() {
        var a=announce(3,NOW);expect(ACCEPTED,outer(a,1),null);
        revocations.clear();expect(NEEDS_ANNOUNCEMENT,outer(a,1),null);
        revocations.add(AdminRecords.initialRevocations(GROUP,NOW-2000,secret(1)));
        union.add(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,1,NOW,List.of(member),secret(1)));
        expect(INVALID,outer(a,1),null);
    }
    @Test void wrappingWaitsForTheExactAnnouncementAndRevocationBody() {
        var a=announce(3,NOW);var w=wrap(a,certificate,NOW,1);
        announcements.clear();expect(NEEDS_ANNOUNCEMENT,w,null);
        announcements.add(a);revocations.clear();expect(NEEDS_ANNOUNCEMENT,w,null);
    }
    @Test void aRevokedRecipientIsRefusedEvenWhenTheWinnerOmitsIt() {
        var a=announce(3,NOW);var w=wrap(a,certificate,NOW,1);
        union.add(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,1,NOW,List.of(member),secret(1)));
        expect(INVALID,w,null);
    }
    @Test void certificatesFromAnUnknownOrRemovedAdministratorAreRefused() {
        var a=announce(3,NOW);expect(INVALID,wrap(a,cert(NOW-1000,3,handshake),NOW,1),null);
        var next=AdminProofFixtures.list(GROUP,1,NOW-100,List.of(pub(2)),secret(1),secret(2));
        assertTrue(state.acceptAdministrators(next,v->fail()));
        expect(INVALID,wrap(a,certificate,NOW,2),null);
    }
    @Test void expiredAndTooFarFutureCertificatesAreRefused() {
        var a=announce(3,NOW);
        expect(INVALID,wrap(a,cert(NOW-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,1,handshake),NOW,1),null);
        expect(INVALID,wrap(a,cert(NOW+ManagedVerifier.FUTURE_SKEW_MILLIS+1,1,handshake),NOW,1),null);
        expect(ACCEPTED,wrap(a,cert(NOW+ManagedVerifier.FUTURE_SKEW_MILLIS,1,handshake),NOW,1),null);
    }
    @Test void invalidIdentityProofIsRefused() {
        var a=announce(3,NOW);
        var bad=AdminRecords.certificate(GROUP,pub(7),handshake,new byte[64],NOW-1000,secret(1));
        expect(INVALID,wrap(a,bad,NOW,1),null);
    }
    @Test void recipientAndCertificateIdentityMustMatch() {
        var a=announce(3,NOW);member=digest(55);expect(INVALID,wrap(a,certificate,NOW,1),null);
    }
    @Test void handshakeMustMatchTheAttachedCertificate() {
        var a=announce(3,NOW);var valid=wrap(a,certificate,NOW,1);
        var wrong=cert(NOW-1000,1,Crypto.x25519Public(secret(9)));
        var w=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),valid.inner(),1,0,adminDigest(),NOW,wrong.encode());
        expect(INVALID,w,null);
    }
    @Test void announcementRankingPrecedesCertificateAndWrappedTime() {
        var older=announce(3,NOW-1);var newer=announce(4,NOW-2);
        var held=wrap(older,certificate,NOW,1);
        var candidate=wrap(newer,cert(NOW-2000,1,handshake),NOW-1,1);
        expect(ACCEPTED,candidate,held);expect(OLD,held,candidate);
        expect(ACCEPTED,outer(newer,1),outer(older,1));
        expect(OLD,outer(older,1),outer(newer,1));
    }
    @Test void newerRecipientCertificateWinsInBothArrivalOrders() {
        var a=announce(3,NOW);
        var old=wrap(a,cert(NOW-2000,1,handshake),NOW,1);
        var fresh=wrap(a,certificate,NOW-1,2);
        expect(ACCEPTED,fresh,old);expect(OLD,old,fresh);
    }
    @Test void sameIssuedAtDifferentCertificatesAreRefused() {
        var a=announce(3,NOW);var held=wrap(a,certificate,NOW,1);
        var alternate=wrap(a,cert(certificate.issuedAt(),2,handshake),NOW,2);
        expect(INVALID,alternate,held);expect(INVALID,held,alternate);
    }
    @Test void wrappedTimeThenPayloadBreakTiesAndOuterCannotReverseThem() {
        var a=announce(3,NOW);var held=wrap(a,certificate,NOW-1,1);var candidate=wrap(a,certificate,NOW,2);
        expect(ACCEPTED,candidate,held);expect(OLD,held,candidate);
        var same=wrap(a,certificate,NOW,1);
        int c=AdminRecords.compareBytes(same.inner().signedBytes(),candidate.inner().signedBytes());
        expect(c>0?ACCEPTED:c<0?OLD:DUPLICATE,same,candidate);
        var republished=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(2),held.inner(),100,0,adminDigest(),NOW+1,certificate.encode());
        expect(OLD,republished,candidate);
    }
    @Test void removedAdministratorCannotSendAnnouncementsOrWraps() {
        var a=announce(3,NOW);var w=wrap(a,certificate,NOW,1);
        var next=AdminProofFixtures.list(GROUP,1,NOW-100,List.of(pub(2)),secret(1),secret(2));
        assertTrue(state.acceptAdministrators(next,v->fail()));
        expect(INVALID,outer(a,1),null);expect(INVALID,w,null);
    }
    @Test void announcementAndWrappedSigningTimesMustBeWithinTheClockLimit() {
        var a=announce(3,NOW+ManagedVerifier.FUTURE_SKEW_MILLIS+1);
        expect(INVALID,outer(a,1),null);
        var valid=announce(3,NOW);
        expect(INVALID,wrap(valid,certificate,NOW+ManagedVerifier.FUTURE_SKEW_MILLIS+1,1),null);
    }
    @Test void pendingWrapIsRecheckedAfterTheDependencyArrives() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);announcements.clear();
        var verdict=verifier.judge(record,null);assertEquals(NEEDS_ANNOUNCEMENT,verdict.status());
        var pending=new ManagedPending(clock);assertTrue(pending.offer(record,verdict));
        assertTrue(pending.retry(verifier,key->null,c->{}).isEmpty());
        announcements.add(a);var resolved=pending.retry(verifier,key->null,c->{});
        assertEquals(1,resolved.size());assertEquals(ACCEPTED,resolved.get(0).verdict().status());
        assertEquals(0,pending.size());
    }
    @Test void pendingStoreRetainsTheAuthenticatedIdentityForRechecking() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);announcements.clear();
        byte[] sender=state.administrators().binding(pub(1)).memberId();
        var verdict=verifier.judgeStore(record,null,sender);assertEquals(NEEDS_ANNOUNCEMENT,verdict.status());
        var pending=new ManagedPending(clock);assertTrue(pending.offer(record,verdict,sender));sender[0]^=1;
        announcements.add(a);var resolved=pending.retry(verifier,key->record,c->{});
        assertEquals(DUPLICATE,resolved.get(0).verdict().status());
    }
    @Test void pendingWrapIsRefusedWhenTheRecipientIsRevokedWhileWaiting() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);announcements.clear();
        var pending=new ManagedPending(clock);assertTrue(pending.offer(record,verifier.judge(record,null)));
        union.add(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,1,NOW,List.of(member),secret(1)));
        announcements.add(a);var resolved=pending.retry(verifier,key->null,c->{});
        assertEquals(INVALID,resolved.get(0).verdict().status());assertEquals(0,pending.size());
    }
    @Test void certificatesForAnotherGroupAreRefused() {
        var a=announce(3,NOW);
        var wrong=AdminRecords.certificate(digest(99),pub(7),handshake,SignaturePurpose.identityProof(secret(7),digest(99),handshake),NOW-1000,secret(1));
        expect(INVALID,wrap(a,wrong,NOW,1),null);
    }
    @Test void certificateSignatureIsCheckedIndependentlyOfTheOuter() {
        var a=announce(3,NOW);byte[] cert=certificate.encode();cert[cert.length-1]^=1;
        var valid=wrap(a,certificate,NOW,1);
        var candidate=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),valid.inner(),1,0,adminDigest(),NOW,cert);
        expect(INVALID,candidate,null);
    }
    @Test void announcementAdminReferenceAndDigestAreChecked() {
        var a=KeyAnnouncement.issue(GROUP,secret(1),3,NOW,0,Crypto.blake2s(revocations.get(0).signedBytes()),digest(8),0,digest(99));
        expect(INVALID,outer(a,1),null);
        var future=KeyAnnouncement.issue(GROUP,secret(1),3,NOW,0,Crypto.blake2s(revocations.get(0).signedBytes()),digest(8),2,adminDigest());
        expect(NEEDS_VERSION,outer(future,1),null);
    }
    @Test void pendingCandidatesApplyTheHigherKeyVersionFirstInBothArrivalOrders() {
        var low=announce(3,NOW);var high=announce(4,NOW);
        var older=wrap(low,certificate,NOW,1);var newer=wrap(high,certificate,NOW,1);
        for(boolean reversed:new boolean[]{false,true}){
            var pending=new ManagedPending(clock);announcements.clear();
            for(var r:reversed?List.of(older,newer):List.of(newer,older))
                assertTrue(pending.offer(r,verifier.judge(r,null)));
            announcements.add(low);announcements.add(high);
            var held=new java.util.HashMap<DhtId,ManagedDhtRecord>();
            var results=pending.retry(verifier,held::get,c->held.put(c.record().key(),c.record()));
            assertEquals(4,held.get(newer.key()).inner().version());
            assertEquals(List.of(ACCEPTED,OLD),results.stream().map(c->c.verdict().status()).toList());
            assertEquals(0,pending.size());
        }
    }
    @Test void differentKeyVersionsDoNotNeedTheHeldAnnouncement() {
        var old=announce(3,NOW);var high=announce(4,NOW);
        var held=wrap(old,certificate,NOW,1);var candidate=wrap(high,certificate,NOW,1);
        announcements.remove(old);expect(ACCEPTED,candidate,held);
        announcements.add(old);announcements.remove(high);expect(OLD,held,candidate);
    }
    @Test void equalKeyVersionsStillNeedTheHeldAnnouncement() {
        var old=announce(3,NOW-1);var high=announce(3,NOW);
        var held=wrap(old,certificate,NOW,1);var candidate=wrap(high,certificate,NOW,1);
        announcements.remove(old);expect(NEEDS_ANNOUNCEMENT,candidate,held);
    }
    @Test void checkedRevocationBodyIsReadOnlyOnce() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);
        var reads=new java.util.concurrent.atomic.AtomicInteger();
        verifier=new ManagedVerifier(new AdminStateTrust(state),clock,union,new ManagedDependencies(){
            public KeyAnnouncement announcement(byte[] digest){return a;}
            public AdminRecords.Record revocations(long version,byte[] digest){return reads.incrementAndGet()==1?revocations.get(0):null;}
        });
        expect(ACCEPTED,record,null);assertEquals(1,reads.get());
    }
    @Test void newAdministratorOuterWaitsForTheMissingVersionForBothKeyKinds() {
        var next=AdminProofFixtures.list(GROUP,1,NOW-100,List.of(pub(1),pub(2),pub(3)),secret(1),secret(1),secret(2),secret(3));
        var a=KeyAnnouncement.issue(GROUP,secret(3),3,NOW,0,Crypto.blake2s(revocations.get(0).signedBytes()),digest(8),1,Crypto.blake2s(next.signedBytes()));
        announcements.add(a);
        var announcement=ManagedDhtRecord.issue(GROUP,secret(3),a,1,1,Crypto.blake2s(next.signedBytes()),NOW);
        var w=wrap(a,certificate,NOW,3);
        var wrapped=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(3),w.inner(),1,1,Crypto.blake2s(next.signedBytes()),NOW,certificate.encode());
        expect(NEEDS_VERSION,announcement,null);expect(NEEDS_VERSION,wrapped,null);
        assertTrue(state.acceptAdministrators(next,v->fail()));
        expect(ACCEPTED,announcement,null);expect(ACCEPTED,wrapped,null);
    }
    @Test void newAdministratorInnerAnnouncementWaitsBeforeCheckingItsAuthority() {
        var next=AdminProofFixtures.list(GROUP,1,NOW-100,List.of(pub(1),pub(2),pub(3)),secret(1),secret(1),secret(2),secret(3));
        var a=KeyAnnouncement.issue(GROUP,secret(3),3,NOW,0,Crypto.blake2s(revocations.get(0).signedBytes()),digest(8),1,Crypto.blake2s(next.signedBytes()));
        announcements.add(a);expect(NEEDS_VERSION,outer(a,1),null);
        expect(NEEDS_VERSION,wrap(a,certificate,NOW,1),null);
        assertTrue(state.acceptAdministrators(next,v->fail()));
        expect(ACCEPTED,outer(a,1),null);expect(ACCEPTED,wrap(a,certificate,NOW,1),null);
    }

    @Test void wrongStoreIdentityDoesNotSuppressTheSignersStoreAfterTheVersionArrives() {
        var next=AdminProofFixtures.list(GROUP,1,NOW-100,List.of(pub(1),pub(2)),secret(1),secret(1),secret(2));
        var a=announce(3,NOW);
        var record=ManagedDhtRecord.issue(GROUP,secret(1),a,1,1,Crypto.blake2s(next.signedBytes()),NOW);
        var pending=new ManagedPending(clock);
        byte[] correct=state.administrators().binding(pub(1)).memberId();
        byte[] wrong=state.administrators().binding(pub(2)).memberId();
        assertTrue(pending.offer(record,verifier.judgeStore(record,null,wrong),wrong));
        assertTrue(pending.offer(record,verifier.judgeStore(record,null,correct),correct));
        assertEquals(2,pending.size());
        assertTrue(state.acceptAdministrators(next,v->fail()));
        var applied=new ArrayList<ManagedDhtRecord>();
        var results=pending.retry(verifier,key->null,c->applied.add(c.record()));
        assertEquals(List.of(INVALID,ACCEPTED),results.stream().map(c->c.verdict().status()).toList());
        assertEquals(1,applied.size());assertEquals(0,pending.size());
    }

    @Test void badDependencySignatureIsInvalidEvenWhenItsAdministratorVersionIsMissing() {
        var a=KeyAnnouncement.issue(GROUP,secret(3),3,NOW,0,Crypto.blake2s(revocations.get(0).signedBytes()),digest(8),1,digest(9));
        byte[] bad=a.encode();bad[bad.length-1]^=1;
        var damaged=KeyAnnouncement.decode(bad);announcements.add(damaged);
        expect(INVALID,wrap(damaged,certificate,NOW,1),null);
    }
    @Test void tooFarFutureInnerIsInvalidBeforeTheMissingOuterVersion() {
        var a=announce(3,NOW+ManagedVerifier.FUTURE_SKEW_MILLIS+1);
        var candidate=ManagedDhtRecord.issue(GROUP,secret(3),a,1,1,digest(9),NOW);
        expect(INVALID,candidate,null);
    }
    @Test void retryRemovesDuplicateWithoutCallingTheApplication() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);announcements.clear();
        var pending=new ManagedPending(clock);assertTrue(pending.offer(record,verifier.judge(record,null)));
        announcements.add(a);
        var resolved=pending.retry(verifier,key->record,c->fail());
        assertEquals(DUPLICATE,resolved.get(0).verdict().status());assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }
    @Test void pendingRevocationCandidatesUseTheirInnerRankBeforeArrivalOrder() {
        var low=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,1,NOW,List.of(),secret(1)),1,0,adminDigest(),NOW,null);
        var high=ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,2,NOW,List.of(),secret(1)),1,0,adminDigest(),NOW,null);
        for(var order:List.of(List.of(low,high),List.of(high,low))){
            var pending=new ManagedPending(clock);
            for(var r:order)assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
            var held=new java.util.HashMap<DhtId,ManagedDhtRecord>();
            var resolved=pending.retry(verifier,held::get,c->held.put(c.record().key(),c.record()));
            assertEquals(List.of(ACCEPTED,OLD),resolved.stream().map(c->c.verdict().status()).toList());
            assertEquals(2,held.get(high.key()).version());assertEquals(0,pending.size());
        }
    }

    @Test void partiallyAvailableAnnouncementsHaveOneOrderForAllSixArrivals() {
        var high=announce(3,NOW);var missing=announce(3,NOW-1);var low=announce(3,NOW-2);
        var a=wrap(high,certificate,NOW-2,1);
        var b=wrap(missing,certificate,NOW-1,1);
        var c=wrap(low,cert(certificate.issuedAt(),2,handshake),NOW,2);
        announcements.remove(missing);
        for(var order:List.of(List.of(a,b,c),List.of(a,c,b),List.of(b,a,c),
                List.of(b,c,a),List.of(c,a,b),List.of(c,b,a))){
            var pending=new ManagedPending(clock);
            for(var r:order)assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
            var held=new java.util.HashMap<DhtId,ManagedDhtRecord>();
            var applied=new ArrayList<ManagedDhtRecord>();
            var checked=pending.retry(verifier,held::get,result->{
                applied.add(result.record());held.put(result.record().key(),result.record());
            });
            assertEquals(List.of(a),applied);
            assertSame(a,held.get(a.key()));
            assertEquals(List.of(a,c),checked.stream().map(ManagedPending.Checked::record).toList());
            assertEquals(List.of(ACCEPTED,INVALID),checked.stream().map(r->r.verdict().status()).toList());
            assertEquals(1,pending.size());assertEquals(b.encode().length,pending.bytes());
        }
    }
    @Test void sortingReadsEachAnnouncementOnceBeforeJudging() {
        var a=wrap(announce(3,NOW),certificate,NOW-2,1);
        var b=wrap(announce(3,NOW-1),certificate,NOW-1,1);
        var c=wrap(announce(3,NOW-2),certificate,NOW,1);
        var reads=new java.util.HashMap<KeyAnnouncement,Integer>();
        verifier=new ManagedVerifier(new AdminStateTrust(state),clock,union,new ManagedDependencies(){
            public KeyAnnouncement announcement(byte[] digest){
                var found=announcements.stream().filter(value->Crypto.equal(Crypto.blake2s(value.signedBytes()),digest)).findFirst().orElse(null);
                reads.merge(found,1,Integer::sum);return found;
            }
            public AdminRecords.Record revocations(long version,byte[] digest){return revocations.get(0);}
        });
        var pending=new ManagedPending(clock);
        for(var r:List.of(c,b,a))assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        var first=new java.util.concurrent.atomic.AtomicBoolean(true);
        var held=new java.util.HashMap<DhtId,ManagedDhtRecord>();
        pending.retry(verifier,key->{
            if(first.getAndSet(false)){
                assertEquals(3,reads.size());assertTrue(reads.values().stream().allMatch(count->count==1));
            }
            return held.get(key);
        },result->held.put(result.record().key(),result.record()));
        assertSame(a,held.get(a.key()));assertEquals(0,pending.size());
    }
    @Test void applicationCannotReenterAnyPendingOperation() {
        var a=announce(3,NOW);var r=wrap(a,certificate,NOW,1);
        var pending=new ManagedPending(clock);assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        var checked=pending.retry(verifier,key->null,result->{
            assertThrows(IllegalStateException.class,()->pending.retry(verifier,key->null,c->fail()));
            assertThrows(IllegalStateException.class,()->pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
            assertThrows(IllegalStateException.class,()->pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT,member));
            assertThrows(IllegalStateException.class,pending::size);
            assertThrows(IllegalStateException.class,pending::bytes);
        });
        assertEquals(1,checked.size());assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }
    @Test void expiryDuringApplicationCannotSubtractCapacityTwice() {
        var time=new java.util.concurrent.atomic.AtomicLong(NOW);
        Clock moving=new Clock(){
            public java.time.ZoneId getZone(){return ZoneOffset.UTC;}
            public Clock withZone(java.time.ZoneId zone){return this;}
            public Instant instant(){return Instant.ofEpochMilli(time.get());}
        };
        var a=announce(3,NOW);var r=wrap(a,certificate,NOW,1);
        var pending=new ManagedPending(moving);assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        pending.retry(verifier,key->null,result->{
            time.addAndGet(ManagedPending.MAX_AGE_MILLIS);
            assertThrows(IllegalStateException.class,pending::size);
            assertThrows(IllegalStateException.class,pending::bytes);
            assertThrows(IllegalStateException.class,()->pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        });
        assertEquals(0,pending.size());assertEquals(0,pending.bytes());
        assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        assertEquals(r.encode().length,pending.bytes());
    }
    @Test void applicationFailureRestoresOnlyTheFailedEntryWithItsOriginalDeadline() {
        var time=new java.util.concurrent.atomic.AtomicLong(NOW);
        Clock moving=new Clock(){
            public java.time.ZoneId getZone(){return ZoneOffset.UTC;}
            public Clock withZone(java.time.ZoneId zone){return this;}
            public Instant instant(){return Instant.ofEpochMilli(time.get());}
        };
        var first=wrap(announce(5,NOW),certificate,NOW,1);
        var failed=wrap(announce(4,NOW),certificate,NOW,1);
        var last=wrap(announce(3,NOW),certificate,NOW,1);
        var pending=new ManagedPending(moving);
        for(var r:List.of(last,failed,first))assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        time.addAndGet(60000);
        var failure=new IllegalArgumentException("application failure");
        var applied=new ArrayList<ManagedDhtRecord>();
        assertSame(failure,assertThrows(IllegalArgumentException.class,()->pending.retry(verifier,key->null,result->{
            if(result.record()==failed)throw failure;
            applied.add(result.record());
        })));
        assertEquals(List.of(first),applied);assertEquals(2,pending.size());
        assertEquals(failed.encode().length+last.encode().length,pending.bytes());
        var checked=pending.retry(verifier,key->null,result->applied.add(result.record()));
        assertEquals(List.of(failed,last),checked.stream().map(ManagedPending.Checked::record).toList());
        assertEquals(0,pending.bytes());
        var deadlinePending=new ManagedPending(moving);
        assertTrue(deadlinePending.offer(failed,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        time.addAndGet(60000);
        assertThrows(IllegalArgumentException.class,()->deadlinePending.retry(verifier,key->null,result->{throw failure;}));
        time.addAndGet(59999);assertEquals(1,deadlinePending.size());
        time.incrementAndGet();assertEquals(0,deadlinePending.size());assertEquals(0,deadlinePending.bytes());
    }
    @Test void wrappedKeyAndAdministratorDependencyResolveInOneRetry() {
        var next=AdminProofFixtures.list(GROUP,1,NOW-100,List.of(pub(1),pub(2)),secret(1),secret(1),secret(2));
        var listRecord=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),next,1,0,adminDigest(),NOW,null);
        var a=announce(3,NOW);var w=wrap(a,certificate,NOW,1);
        var wrapped=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),w.inner(),1,1,Crypto.blake2s(next.signedBytes()),NOW,certificate.encode());
        assertTrue(AdminRecords.compareBytes(wrapped.key().bytes(),listRecord.key().bytes())<0);
        var pending=new ManagedPending(clock);
        for(var r:List.of(wrapped,listRecord))assertTrue(pending.offer(r,ManagedVerdict.needsVersion(1)));
        var held=new java.util.HashMap<DhtId,ManagedDhtRecord>();
        var checked=pending.retry(verifier,held::get,result->{
            if(result.record().kind()==DhtKeys.LATEST_ADMINS)assertTrue(state.acceptAdministrators(next,v->fail()));
            held.put(result.record().key(),result.record());
        });
        assertEquals(List.of(listRecord,wrapped),checked.stream().map(ManagedPending.Checked::record).toList());
        assertTrue(checked.stream().allMatch(r->r.verdict().status()==ACCEPTED));
        assertEquals(0,pending.size());assertEquals(0,pending.bytes());
    }
    @Test void retryWithoutProgressStopsAfterOnePass() {
        var a=announce(3,NOW);var r=wrap(a,certificate,NOW,1);announcements.clear();
        var pending=new ManagedPending(clock);assertTrue(pending.offer(r,ManagedVerdict.NEEDS_ANNOUNCEMENT));
        var reads=new java.util.concurrent.atomic.AtomicInteger();
        assertTimeoutPreemptively(java.time.Duration.ofSeconds(2),()->{
            assertTrue(pending.retry(verifier,key->{reads.incrementAndGet();return null;},c->fail()).isEmpty());
        });
        assertEquals(1,reads.get());assertEquals(1,pending.size());assertEquals(r.encode().length,pending.bytes());
    }
}
