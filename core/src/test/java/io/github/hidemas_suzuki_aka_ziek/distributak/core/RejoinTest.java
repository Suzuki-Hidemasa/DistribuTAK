// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
class RejoinTest {
    final JoinHandshakeTest f=new JoinHandshakeTest();
    final byte[] identity=Crypto.ed25519Public(f.f.identity);
    AdminState saved() {
        var state=f.f.fresh();state.acceptAdministrators(f.chain().get(1),v->fail());return state;
    }
    @Test void sameKeyVersionRejoinsWithSameIdentityAndFreshHandshakeAndIdenticalRetry() {
        var saved=saved();var r=saved.revocations();var a=saved.administrators();
        var announcement=KeyAnnouncement.issue(f.f.group,f.f.a,0,f.f.now,r.version(),Crypto.blake2s(r.signedBytes()),
            KeyAnnouncement.commitment(f.f.group,0,f.groupKey),a.version(),Crypto.blake2s(a.signedBytes()));
        saved.recordGroupKey(announcement,f.groupKey,0);var before=saved.snapshot();
        try(var invite=f.invitation();var admin=f.admin(invite);
            var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,saved,f.f.certificate(),0,f.groupKey,announcement,saved.revokedSubjects());
            var material=JoinHandshake.Materials.verified(saved,f.chain(),0,f.groupKey,identity)) {
            byte[] request=joiner.request(),reply=admin.respond(request,f.adminX,f.f.a,material);
            assertArrayEquals(reply,admin.respond(joiner.retry(),f.adminX,f.f.a,material));
            try(var result=joiner.receive(reply)) {
                assertArrayEquals(identity,result.certificate().field(0));
                assertFalse(Arrays.equals(Crypto.x25519Public(f.f.handshake),result.certificate().field(1)));
                assertEquals(0,result.groupKeyVersion());assertArrayEquals(f.groupKey,result.groupKey());
            }
            assertEquals(before.administratorVersion(),saved.administrators().version());
            assertArrayEquals(before.revocations(),saved.snapshot().revocations());
            assertEquals(before.records().size(),saved.snapshot().records().size());
            for(int n=0;n<before.records().size();n++)assertArrayEquals(before.records().get(n),saved.snapshot().records().get(n));
        }
    }
    @Test void expiredSavedCertificateCanRejoinWithNewerKeyVersion() {
        var saved=saved();var issuer=saved();var r=issuer.revocations();var a=issuer.administrators();
        var announcement=KeyAnnouncement.issue(f.f.group,f.f.a,1,f.f.now,r.version(),Crypto.blake2s(r.signedBytes()),
            KeyAnnouncement.commitment(f.f.group,1,f.groupKey),a.version(),Crypto.blake2s(a.signedBytes()));
        issuer.recordGroupKey(announcement,f.groupKey,1);
        var expired=AdminRecords.certificate(f.f.group,identity,Crypto.x25519Public(f.f.handshake),SignaturePurpose.identityProof(f.f.identity,f.f.group,Crypto.x25519Public(f.f.handshake)),f.f.now-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,f.f.a);
        try(var invite=f.invitation();var admin=f.admin(invite);
            var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,saved,expired,0);
            var material=JoinHandshake.Materials.verified(issuer,f.chain(),1,f.groupKey,identity)) {
            try(var result=joiner.receive(admin.respond(joiner.request(),f.adminX,f.f.a,material))) {
                assertEquals(1,result.groupKeyVersion());assertArrayEquals(identity,result.certificate().field(0));
            }
        }
    }
    @Test void oldOverloadRejectsUnannouncedLargerVersion(){
        var saved=saved();
        try(var invite=f.invitation();var admin=f.admin(invite);
            var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,saved,f.f.certificate(),0);
            var material=JoinHandshake.Materials.rejoin(f.chain(),f.f.revocations(0,f.f.now,List.of(),f.f.a),1,f.groupKey,identity)){
            byte[] reply=admin.respond(joiner.request(),f.adminX,f.f.a,material);
            assertThrows(SecurityException.class,()->joiner.receive(reply));
        }
    }
    @Test void rejoinRejectsOldHandshakeAndDifferentIdentityBeforeRequest() {
        try(var invite=f.invitation()) {
            assertThrows(SecurityException.class,()->JoinHandshake.Joiner.rejoin(invite,f.f.identity,f.f.handshake,f.f.clock,saved(),f.f.certificate(),0));
            assertThrows(SecurityException.class,()->JoinHandshake.Joiner.rejoin(invite,key(90),key(73),f.f.clock,saved(),f.f.certificate(),0));
        }
    }
    @Test void expectedIdentityRequiredAndMismatchDoesNotConsume() {
        assertThrows(IllegalArgumentException.class,()->JoinHandshake.Materials.rejoin(f.chain(),f.f.revocations(0,f.f.now,List.of(),f.f.a),0,f.groupKey,null));
        assertThrows(IllegalArgumentException.class,()->JoinHandshake.Materials.rejoin(f.chain(),f.f.revocations(0,f.f.now,List.of(),f.f.a),0,f.groupKey,new byte[31]));
        try(var invite=f.invitation();var admin=f.admin(invite);var joiner=f.joiner(invite);
            var material=JoinHandshake.Materials.rejoin(f.chain(),f.f.revocations(0,f.f.now,List.of(),f.f.a),0,f.groupKey,key(90))) {
            assertThrows(SecurityException.class,()->admin.respond(joiner.request(),f.adminX,f.f.a,material));assertFalse(admin.isConsumed());
        }
    }
    @Test void differentInvitationAdministratorRejectedBeforeRequest() {
        try(var invite=new Invitation(new byte[]{127,0,0,1},50000,Crypto.x25519Public(f.adminX),f.f.cp,f.secret, f.f.group)) {
            assertThrows(SecurityException.class,()->JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,saved(),f.f.certificate(),0));
        }
    }
    @Test void olderKeyAdministratorsOrRevocationsAndOtherGroupRejectedWithoutSavedChanges() {
        for(int scenario=0;scenario<4;scenario++) {
            var saved=saved();long version=scenario==0 ? 1 : 0;
            if(scenario==1)saved.acceptAdministrators(f.f.admins(2,f.f.now,List.of(f.f.ap),f.f.a),v->fail());
            if(scenario==2)saved.acceptRevocations(f.f.revocations(1,f.f.now,List.of(),f.f.a));
            if(scenario==3) {
                saved=new AdminState(key(90),f.f.ap,f.f.clock,new InMemoryAdminRecordStore());
                var anchor=AdminRecords.list(AdminRecords.Kind.ADMINS,key(90),0,f.f.now,List.of(f.f.ap),f.f.a);
                saved.bootstrap(anchor,AdminRecords.signAnchor(anchor,f.f.a));
                saved.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,key(90),0,f.f.now,List.of(),f.f.a));
            }
            var before=saved.snapshot();
            // 保存した証明書も保存側のグループに属するものを渡す。
            var old=AdminRecords.certificate(saved.administrators().group(),identity,Crypto.x25519Public(f.f.handshake),SignaturePurpose.identityProof(f.f.identity,saved.administrators().group(),Crypto.x25519Public(f.f.handshake)),f.f.now,f.f.a);
            if(!Crypto.equal(saved.administrators().group(),f.f.group)) {
                long savedVersion=version;var savedState=saved;try(var invite=f.invitation()){assertThrows(SecurityException.class,()->JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,savedState,old,savedVersion));}
                continue;
            }
            try(var invite=f.invitation();var admin=f.admin(invite);
                var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,saved,old,version);var material=f.material()) {
                var reply=admin.respond(joiner.request(),f.adminX,f.f.a,material);
                assertThrows(SecurityException.class,()->joiner.receive(reply));
                assertEquals(before.administratorVersion(),saved.administrators().version());assertArrayEquals(before.revocations(),saved.snapshot().revocations());
                assertEquals(before.records().size(),saved.snapshot().records().size());
                for(int n=0;n<before.records().size();n++)assertArrayEquals(before.records().get(n),saved.snapshot().records().get(n));
            }
        }
    }
    @Test void revokedIdentityCannotRejoin() {
        try(var invite=f.invitation();var admin=f.admin(invite);
            var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,saved(),f.f.certificate(),0);
            var material=JoinHandshake.Materials.rejoin(f.chain(),f.f.revocations(1,f.f.now,List.of(Crypto.blake2s(identity)),f.f.a),0,f.groupKey,identity)) {
            assertThrows(SecurityException.class,()->admin.respond(joiner.request(),f.adminX,f.f.a,material));assertFalse(admin.isConsumed());
        }
    }
}
