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
        assertTrue(pending.retry(verifier,key->null).isEmpty());
        announcements.add(a);var resolved=pending.retry(verifier,key->null);
        assertEquals(1,resolved.size());assertEquals(ACCEPTED,resolved.get(0).verdict().status());
        assertEquals(0,pending.size());
    }
    @Test void pendingStoreRetainsTheAuthenticatedIdentityForRechecking() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);announcements.clear();
        byte[] sender=state.administrators().binding(pub(1)).memberId();
        var verdict=verifier.judgeStore(record,null,sender);assertEquals(NEEDS_ANNOUNCEMENT,verdict.status());
        var pending=new ManagedPending(clock);assertTrue(pending.offer(record,verdict,sender));sender[0]^=1;
        announcements.add(a);var resolved=pending.retry(verifier,key->record);
        assertEquals(DUPLICATE,resolved.get(0).verdict().status());
    }
    @Test void pendingWrapIsRefusedWhenTheRecipientIsRevokedWhileWaiting() {
        var a=announce(3,NOW);var record=wrap(a,certificate,NOW,1);announcements.clear();
        var pending=new ManagedPending(clock);assertTrue(pending.offer(record,verifier.judge(record,null)));
        union.add(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,1,NOW,List.of(member),secret(1)));
        announcements.add(a);var resolved=pending.retry(verifier,key->null);
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
}
