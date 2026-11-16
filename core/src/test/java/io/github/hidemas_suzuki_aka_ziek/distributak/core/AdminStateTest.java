// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class AdminStateTest {
    final long now=10_000_000_000L;
    final byte[] group=key(9), a=key(1), b=key(2), c=key(3), identity=key(4), handshake=key(5);
    final byte[] ap=Crypto.ed25519Public(a), bp=Crypto.ed25519Public(b), cp=Crypto.ed25519Public(c);
    final Clock clock=Clock.fixed(Instant.ofEpochMilli(now),ZoneOffset.UTC);
    AdminRecords.Record admins(long version, long time, List<byte[]> keys, byte[] signer) {
        return AdminProofFixtures.list(group,version,time,keys,signer,a,b,c,key(10));
    }
    AdminRecords.Record revocations(long version, long time, List<byte[]> ids, byte[] signer) {
        return AdminRecords.list(REVOCATIONS,group,version,time,ids,signer);
    }
    AdminRecords.Record certificate(byte[] signer, long issued, byte[] binding) {
        return AdminRecords.certificate(group,Crypto.ed25519Public(identity),Crypto.x25519Public(handshake),binding,issued,signer);
    }
    AdminRecords.Record certificate() { return certificate(a,now,SignaturePurpose.identityProof(identity,group,Crypto.x25519Public(handshake))); }
    AdminState fresh() { return fresh(new InMemoryAdminRecordStore()); }
    AdminState fresh(AdminRecordStore store) {
        var state=new AdminState(group,ap,clock,store);
        var first=admins(0,now,List.of(ap,bp),b);
        state.bootstrap(first,AdminRecords.signAnchor(first,a));
        state.acceptRevocations(revocations(0,now,List.of(),a));
        return state;
    }
    @Test void validCertificate() { fresh().verifyCertificate(certificate(),Crypto.x25519Public(handshake)); }
    @Test void certificateRejectsNonAdministratorSignatureAlone() {
        assertThrows(SecurityException.class,()->fresh().verifyCertificate(certificate(c,now,SignaturePurpose.identityProof(identity,group,Crypto.x25519Public(handshake))),Crypto.x25519Public(handshake)));
    }
    @Test void certificateRejectsRevocationAlone() {
        var s=fresh();s.acceptRevocations(revocations(1,now,List.of(Crypto.blake2s(Crypto.ed25519Public(identity))),a));
        assertThrows(SecurityException.class,()->s.verifyCertificate(certificate(),Crypto.x25519Public(handshake)));
    }
    @Test void certificateRejectsExpiredAlone() {
        var expired=certificate(a,now-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,SignaturePurpose.identityProof(identity,group,Crypto.x25519Public(handshake)));
        assertThrows(SecurityException.class,()->fresh().verifyCertificate(expired,Crypto.x25519Public(handshake)));
    }
    @Test void certificateRejectsPeerHandshakeMismatchAlone() {
        assertThrows(SecurityException.class,()->fresh().verifyCertificate(certificate(),Crypto.x25519Public(key(6))));
    }
    @Test void certificateRejectsIdentitySignatureAlone() {
        assertThrows(SecurityException.class,()->fresh().verifyCertificate(certificate(a,now,Crypto.sign(c,Crypto.x25519Public(handshake))),Crypto.x25519Public(handshake)));
    }
    @Test void certificateRejectsIssuanceMoreThanFiveMinutesAhead() {
        assertThrows(SecurityException.class,()->fresh().verifyCertificate(certificate(a,now+300001,SignaturePurpose.identityProof(identity,group,Crypto.x25519Public(handshake))),Crypto.x25519Public(handshake)));
    }
    @Test void administratorChainRejectsGapAndRequestsMissingVersions() {
        var s=fresh();List<Long> missing=new ArrayList<>();
        var second=admins(2,now,List.of(ap,cp),c);
        assertFalse(s.acceptAdministrators(second,missing::add));
        assertEquals(List.of(1L),missing);assertEquals(0,s.administrators().version());
        assertTrue(s.acceptAdministrators(admins(1,now,List.of(ap,cp),a),missing::add));
        assertTrue(s.acceptAdministrators(second,missing::add));
        assertFalse(s.acceptAdministrators(admins(0,now,List.of(ap,bp),b),missing::add));
    }
    @Test void removedAdministratorCannotSignNextListOrOldCertificates() {
        var s=fresh();var old=certificate(b,now,SignaturePurpose.identityProof(identity,group,Crypto.x25519Public(handshake)));
        s.acceptAdministrators(admins(1,now,List.of(ap),a),v->fail());
        assertThrows(SecurityException.class,()->s.verifyCertificate(old,Crypto.x25519Public(handshake)));
        assertThrows(SecurityException.class,()->s.acceptAdministrators(admins(2,now,List.of(bp),b),v->fail()));
        assertThrows(SecurityException.class,()->s.acceptRevocations(revocations(1,now,List.of(),b)));
    }
    @Test void concurrentListsConvergeInEitherOrderAndFutureIsNotRemembered() {
        var low=admins(1,now,List.of(ap,bp),a);var high=admins(1,now+1,List.of(ap,cp),a);
        for(boolean reverse:new boolean[]{false,true}) {
            var s=fresh();s.acceptAdministrators(reverse ? high : low,v->fail());s.acceptAdministrators(reverse ? low : high,v->fail());
            assertArrayEquals(high.encode(),s.administrators().encode());
        }
        var s=fresh();
        assertThrows(SecurityException.class,()->s.acceptAdministrators(admins(1,now+300001,List.of(ap),a),v->fail()));
        assertTrue(s.acceptAdministrators(admins(1,now+300000,List.of(ap),a),v->fail()));
    }
    @Test void equalTimestampUsesUnsignedSignedBytesForBothLists() {
        var one=admins(1,now,List.of(ap),a);var two=admins(1,now,List.of(ap,cp),b);
        var winner=AdminRecords.compare(one,two)>0 ? one : two;
        for(boolean reverse:new boolean[]{false,true}) {
            var s=fresh();s.acceptAdministrators(reverse ? one : two,v->fail());s.acceptAdministrators(reverse ? two : one,v->fail());
            assertArrayEquals(winner.encode(),s.administrators().encode());
        }
        var r1=revocations(1,now,List.of(key(127)),a);var r2=revocations(1,now,List.of(key(128)),a);
        for(boolean reverse:new boolean[]{false,true}) {
            var s=fresh();s.acceptRevocations(reverse ? r1 : r2);s.acceptRevocations(reverse ? r2 : r1);
            assertArrayEquals(r2.encode(),s.revocations().encode());
            assertFalse(s.acceptRevocations(revocations(0,now,List.of(),a)));
            assertThrows(SecurityException.class,()->s.acceptRevocations(revocations(2,now+300001,List.of(),a)));
        }
    }
    @Test void reissueAppliesDeltaToWinnerOrLaterBaseOnlyIfStillAdministrator() {
        var s=fresh();var previous=s.administrators();var own=admins(1,now,List.of(ap,cp),a);
        s.acceptAdministrators(admins(1,now+1,List.of(ap,bp,Crypto.ed25519Public(key(10))),b),v->fail());
        var merged=s.reissue(previous,own,a);
        assertEquals(2,merged.version());assertTrue(AdminRecords.contains(merged.entries(),cp));
        assertFalse(AdminRecords.contains(merged.entries(),bp));assertTrue(AdminRecords.contains(merged.entries(),Crypto.ed25519Public(key(10))));
        s.acceptAdministrators(merged,v->fail());assertEquals(3,s.reissue(previous,own,a).version());
        assertThrows(SecurityException.class,()->s.reissue(previous,own,b));
    }
    @Test void administratorsAtReturnsOnlyTheTrustedVersions() {
        var s=fresh();
        assertArrayEquals(s.administrators().encode(),s.administratorsAt(0).encode());
        assertNull(s.administratorsAt(1));
        s.acceptAdministrators(admins(1,now,List.of(ap,cp),a),v->fail());
        assertEquals(1,s.administratorsAt(1).version());assertEquals(0,s.administratorsAt(0).version());
        assertNull(s.administratorsAt(2));assertNull(s.administratorsAt(-1));
    }
    @Test void continuesChainOnlyLooksAndNeverChangesTheTrustedState() {
        var s=fresh();
        // 次の版で、署名者が今の管理者なら鎖がつながる。見るだけで、信頼済みの版は進まない。
        // The next version signed by a current administrator chains; it only looks, so the trusted version stays.
        assertTrue(s.continuesChain(admins(1,now,List.of(ap,cp),a)));
        assertEquals(0,s.administrators().version());assertNull(s.administratorsAt(1));
        // 署名者が管理者でない・2 つ先・種類が違うものはつながらない。
        // A non-administrator signer, a version two ahead, or the wrong kind does not chain.
        assertFalse(s.continuesChain(admins(1,now,List.of(ap,cp),c)));
        assertFalse(s.continuesChain(admins(2,now,List.of(ap,cp),a)));
        assertFalse(s.continuesChain(revocations(1,now,List.of(),a)));
        // 同じ版の競合は、直前の版から鎖でつながるときだけ。
        // A same-version competitor chains only from the previous version.
        s.acceptAdministrators(admins(1,now,List.of(ap,cp),a),v->fail());
        assertTrue(s.continuesChain(admins(1,now+1,List.of(ap,bp),b)));
        assertFalse(s.continuesChain(admins(1,now+1,List.of(ap,bp),c)));
        assertEquals(1,s.administrators().version());
    }
    @Test void bootstrapRequiresUrlAdministratorsAttachedSignature() {
        var first=admins(20,now,List.of(ap,bp),c);var s=new AdminState(group,ap,clock,new InMemoryAdminRecordStore());
        assertThrows(SecurityException.class,()->s.bootstrap(first,first.signature()));
        s.bootstrap(first,AdminRecords.signAnchor(first,a));
        assertEquals(20,s.administrators().version());
        s.acceptAdministrators(admins(21,now,List.of(ap),b),v->fail());
        assertEquals(21,s.administrators().version());
    }
    @Test void storageRestoresAndReverifiesAndClearErases() {
        var store=new InMemoryAdminRecordStore();var s=fresh(store);
        s.acceptAdministrators(admins(1,now,List.of(ap),b),v->fail());
        var restored=new AdminState(group,ap,clock,store);restored.restore();
        assertEquals(1,restored.administrators().version());restored.verifyCertificate(certificate(),Crypto.x25519Public(handshake));
        var snapshot=store.load();var chain=new ArrayList<>(snapshot.records());byte[] changed=chain.get(1).clone();changed[changed.length-1]^=1;chain.set(1,changed);
        store.save(new AdminRecordStore.Snapshot(chain,snapshot.anchorSignature(),snapshot.revocations(),snapshot.administratorVersion(),snapshot.revocationVersion()));
        assertThrows(SecurityException.class,()->new AdminState(group,ap,clock,store).restore());
        restored.clear();assertNull(store.load());assertThrows(IllegalStateException.class,restored::administrators);
    }
    @Test void wrappedKeyOpensOnlyForCorrectRecipientAndNewVersion() {
        var s=fresh();byte[] id=Crypto.blake2s(Crypto.ed25519Public(identity)), psk=key(12);
        byte[] original=psk.clone();var wrapped=GroupKeyEnvelope.wrap(group,id,Crypto.x25519Public(handshake),1,now,psk,a);
        assertArrayEquals(original,psk); // 呼び出し元の配列の所有権は渡さない。
        try(var opened=s.openGroupKey(wrapped,id,handshake,0)) { assertArrayEquals(original,opened.copy()); }
        assertThrows(SecurityException.class,()->s.openGroupKey(wrapped,key(90),handshake,0));
        assertThrows(SecurityException.class,()->s.openGroupKey(wrapped,id,key(90),0));
        assertThrows(SecurityException.class,()->s.openGroupKey(wrapped,id,handshake,1));
        s.acceptAdministrators(admins(1,now,List.of(bp),a),v->fail());
        assertThrows(SecurityException.class,()->s.openGroupKey(wrapped,id,handshake,0));
    }
    @Test void removedSignerRevocationsRemainAcrossRestartAndNewerValidLists() {
        var store=new InMemoryAdminRecordStore();var s=fresh(store);
        byte[] id=Crypto.blake2s(Crypto.ed25519Public(identity));
        s.acceptRevocations(revocations(1,now,List.of(id),b));
        s.acceptAdministrators(admins(1,now,List.of(ap),a),v->fail());
        assertThrows(SecurityException.class,()->s.verifyCertificate(certificate(),Crypto.x25519Public(handshake)));
        var restarted=new AdminState(group,ap,clock,store);restarted.restore();
        assertThrows(SecurityException.class,()->restarted.verifyCertificate(certificate(),Crypto.x25519Public(handshake)));
        assertThrows(SecurityException.class,()->restarted.acceptRevocations(revocations(2,now,List.of(),b)));
        restarted.acceptRevocations(revocations(2,now,List.of(),a));
        assertThrows(SecurityException.class,()->restarted.verifyCertificate(certificate(),Crypto.x25519Public(handshake)));
    }
    @Test void joinRequiresRevocationsAndAcceptsChainAndEmptyInitialListTogether() {
        var s=new AdminState(group,ap,clock,new InMemoryAdminRecordStore());
        var first=admins(7,now,List.of(ap,bp),b);
        s.bootstrap(first,AdminRecords.signAnchor(first,a));
        assertThrows(SecurityException.class,()->s.verifyCertificate(certificate(),Crypto.x25519Public(handshake)));
        var joined=new AdminState(group,ap,clock,new InMemoryAdminRecordStore());
        joined.join(List.of(first,admins(8,now,List.of(ap),b)),AdminRecords.signAnchor(first,a),AdminRecords.initialRevocations(group,now,a));
        joined.verifyCertificate(certificate(),Crypto.x25519Public(handshake));
    }
    @Test void joinAndRestoreRejectAlteredRecordsWithoutPartiallyAdoptingState() {
        var s=new AdminState(group,ap,clock,new InMemoryAdminRecordStore());var first=admins(0,now,List.of(ap),a);
        assertThrows(SecurityException.class,()->s.join(List.of(first,admins(2,now,List.of(ap),a)),AdminRecords.signAnchor(first,a),revocations(0,now,List.of(),a)));
        assertThrows(IllegalStateException.class,s::administrators);
        assertThrows(SecurityException.class,()->s.join(List.of(first),AdminRecords.signAnchor(first,a),revocations(0,now,List.of(),b)));
        assertThrows(IllegalStateException.class,s::administrators);
    }
    @Test void hpkeContextBindsGroupRecipientAndVersionAndOpenedKeyIsWiped() throws Exception {
        var s=fresh();byte[] id=key(55);
        var w=GroupKeyEnvelope.wrap(group,id,Crypto.x25519Public(handshake),1,now,key(88),a);
        var opened=s.openGroupKey(w,id,handshake,0);byte[] held=SecretAssertions.bytes(opened,"value");opened.close();
        SecretAssertions.zero(held);assertThrows(IllegalStateException.class,opened::copy);
        var changedVersion=AdminRecords.wrapped(group,2,now,id,w.field(1),w.field(2),w.field(3),a);
        assertThrows(SecurityException.class,()->s.openGroupKey(changedVersion,id,handshake,0));
        var changedRecipient=AdminRecords.wrapped(group,1,now,key(56),w.field(1),w.field(2),w.field(3),a);
        assertThrows(SecurityException.class,()->s.openGroupKey(changedRecipient,key(56),handshake,0));
        var changedGroup=AdminRecords.wrapped(key(57),1,now,id,w.field(1),w.field(2),w.field(3),a);
        assertThrows(SecurityException.class,()->GroupKeyEnvelope.open(changedGroup,id,handshake,0));
    }
    @Test void anchorIsFixedAndAnUnconnectedSuccessorIsRejected() {
        var s=fresh();
        var alternative=admins(0,now+1,List.of(ap,cp),a);
        assertThrows(SecurityException.class,()->s.acceptAdministrators(alternative,v->fail()));
        assertThrows(SecurityException.class,()->s.acceptAdministrators(admins(1,now,List.of(ap,cp),c),v->fail()));
        assertEquals(0,s.administrators().version());
        assertThrows(IllegalStateException.class,s::restore);
    }
    @Test void revocationReissueAppliesOwnDeltaToNewerVersion() {
        var s=fresh();var previous=s.revocations();var own=revocations(1,now,List.of(key(20)),a);
        s.acceptRevocations(revocations(2,now,List.of(key(21)),b));
        var merged=s.reissue(previous,own,a);
        assertEquals(3,merged.version());assertTrue(AdminRecords.contains(merged.entries(),key(20)));
        assertTrue(AdminRecords.contains(merged.entries(),key(21)));
        s.acceptRevocations(merged);
    }
}
