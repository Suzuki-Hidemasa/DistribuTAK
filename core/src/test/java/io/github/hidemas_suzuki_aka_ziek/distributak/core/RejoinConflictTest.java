// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class RejoinConflictTest {
    final RejoinTest t=new RejoinTest();final JoinHandshakeTest f=t.f;
    KeyAnnouncement announcement(AdminState state,byte[] value,long time){
        var r=state.revocations();var a=state.administrators();
        return KeyAnnouncement.issue(f.f.group,f.f.a,0,time,r.version(),Crypto.blake2s(r.signedBytes()),KeyAnnouncement.commitment(f.f.group,0,value),a.version(),Crypto.blake2s(a.signedBytes()));
    }
    byte[] reply(Invitation invite,byte[] request,byte[] value,KeyAnnouncement announcement){
        var state=t.saved();byte[] handshake=Crypto.x25519Public(key(73));
        var certificate=AdminRecords.certificate(f.f.group,t.identity,handshake,SignaturePurpose.identityProof(f.f.identity,f.f.group,handshake),f.f.now,f.f.a);
        var wrap=announcement==null?GroupKeyEnvelope.wrap(f.f.group,Crypto.blake2s(t.identity),handshake,0,f.f.now,value,f.f.a)
            :GroupKeyEnvelope.wrap(f.f.group,Crypto.blake2s(t.identity),handshake,0,f.f.now,value,f.f.a,Crypto.blake2s(announcement.signedBytes()));
        var response=new JoinMessages.Response(f.f.group,f.chain().stream().map(AdminRecords.Record::encode).toList(),AdminRecords.signAnchor(f.chain().get(0),f.f.a),state.revocations().encode(),certificate.encode(),wrap.encode(),announcement==null?null:announcement.encode());
        try(var packet=JoinMessages.packet(request,false)){
            return JoinHandshake.sealReply(response,packet.invitation,f.replyFingerprint(request),handshake,f.f.a);
        }
    }
    @Test void sameVersionSameKeyWithFreshHandshakeAndValidResignatureSucceeds(){
        var state=t.saved();var previous=announcement(state,f.groupKey,f.f.now-1);state.recordGroupKey(previous,f.groupKey,0);
        try(var invite=f.invitation();var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0,f.groupKey,previous,state.revokedSubjects())){
            try(var joined=joiner.receive(reply(invite,joiner.request(),f.groupKey,announcement(state,f.groupKey,f.f.now)))){
                assertArrayEquals(f.groupKey,joined.groupKey());assertEquals(0,joined.groupKeyVersion());
                assertFalse(Crypto.equal(f.f.certificate().field(1),joined.certificate().field(1)));
            }
        }
    }
    @ParameterizedTest @ValueSource(ints={0,1,2,3})
    void differentCommitmentOpenedKeyMissingAnnouncementOrLowerRankRejectsWithoutSavedChanges(int scenario){
        var state=t.saved();var previous=announcement(state,f.groupKey,f.f.now);state.recordGroupKey(previous,f.groupKey,0);var before=state.snapshot();
        try(var invite=f.invitation();var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0,f.groupKey,previous,state.revokedSubjects())){
            var next=scenario==0?announcement(state,key(89),f.f.now):scenario==2?null:announcement(state,f.groupKey,scenario==3?f.f.now-1:f.f.now);
            byte[] value=scenario==1?key(89):f.groupKey;
            assertThrows(SecurityException.class,()->joiner.receive(reply(invite,joiner.request(),value,next)));
            assertTrue(AdminState.sameSnapshot(before,state.snapshot()));assertTrue(joiner.isClosed());state.checkRestoredGroupKey(f.groupKey,0);
        }
    }
    @Test void firstAnnouncementMatchesRetainedVersionFiveKeyWithoutInitializingSavedState(){
        var state=t.saved();var before=state.snapshot();assertNull(state.announcement());
        try(var invite=f.invitation();var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0,f.groupKey,null,state.revokedSubjects())){
            try(var joined=joiner.receive(reply(invite,joiner.request(),f.groupKey,announcement(state,f.groupKey,f.f.now)))){
                assertArrayEquals(f.groupKey,joined.groupKey());assertNotNull(joined.state().announcement());
            }
        }
        assertTrue(AdminState.sameSnapshot(before,state.snapshot()));assertNull(state.announcement());
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void unsavedAnnouncementCannotInitializeVersionFiveComparison(boolean unknownSigner){
        var state=t.saved();var before=state.snapshot();var r=state.revocations();var a=state.administrators();
        var unsaved=KeyAnnouncement.issue(f.f.group,unknownSigner?key(99):f.f.a,0,f.f.now,r.version(),Crypto.blake2s(r.signedBytes()),
            KeyAnnouncement.commitment(f.f.group,0,f.groupKey),a.version(),Crypto.blake2s(a.signedBytes()));
        try(var invite=f.invitation()){
            assertThrows(SecurityException.class,()->JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0,f.groupKey,unsaved,state.revokedSubjects()));
        }
        assertTrue(AdminState.sameSnapshot(before,state.snapshot()));assertNull(state.announcement());
    }
    @Test void suppliedAnnouncementCannotRegressOrReplaceSavedComparison(){
        var state=t.saved();var retained=announcement(state,f.groupKey,f.f.now);state.recordGroupKey(retained,f.groupKey,0);var before=state.snapshot();
        try(var invite=f.invitation()){
            assertThrows(SecurityException.class,()->JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0,f.groupKey,
                announcement(state,f.groupKey,f.f.now-1),state.revokedSubjects()));
        }
        var supplied=announcement(state,f.groupKey,f.f.now+1);
        try(var invite=f.invitation();var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0,f.groupKey,supplied,state.revokedSubjects());
            var joined=joiner.receive(reply(invite,joiner.request(),f.groupKey,retained))){
            assertArrayEquals(f.groupKey,joined.groupKey());
        }
        assertTrue(AdminState.sameSnapshot(before,state.snapshot()));assertArrayEquals(retained.encode(),state.announcement().encode());
    }
    @Test void oldRejoinApiCannotAcceptEqualVersionWithoutRetainedKey(){
        var state=t.saved();try(var invite=f.invitation();var joiner=JoinHandshake.Joiner.rejoin(invite,f.f.identity,key(73),f.f.clock,state,f.f.certificate(),0)){
            assertThrows(SecurityException.class,()->joiner.receive(reply(invite,joiner.request(),f.groupKey,announcement(state,f.groupKey,f.f.now))));
        }
    }
    @Test void sameVersionDifferentSavedKeyIsRejectedOnRestore(){
        var state=t.saved();var previous=announcement(state,f.groupKey,f.f.now);state.recordGroupKey(previous,f.groupKey,0);
        var store=new InMemoryAdminRecordStore();store.save(state.snapshot());var restored=new AdminState(f.f.group,f.f.ap,f.f.clock,store);restored.restore();
        assertThrows(SecurityException.class,()->restored.checkRestoredGroupKey(key(89),0));
        assertDoesNotThrow(()->restored.checkRestoredGroupKey(f.groupKey,0));
        assertThrows(SecurityException.class,()->new SessionManager(restored,f.f.certificate(),f.f.handshake,key(89),0,f.f.clock,()->0,256));
    }
    @Test void joinResponseRejectsUnknownDuplicateAndOutOfOrderAnnouncementFields(){
        var state=t.saved();var a=announcement(state,f.groupKey,f.f.now);
        byte[] valid=new JoinMessages.Response(f.f.group,f.chain().stream().map(AdminRecords.Record::encode).toList(),AdminRecords.signAnchor(f.chain().get(0),f.f.a),state.revocations().encode(),f.f.certificate().encode(),new byte[]{1},a.encode()).encode();
        assertNotNull(JoinMessages.response(valid).announcement);
        for(byte[] suffix:List.of(new byte[]{74,0},new byte[]{66,0},new byte[]{58,0})){
            assertThrows(IllegalArgumentException.class,()->JoinMessages.response(Crypto.concat(valid,suffix)));
        }
    }
    @Test void savedAnnouncementFromUnauthorizedSignerCannotInitializeRestoredState(){
        var state=t.saved();var r=state.revocations();var a=state.administrators();
        var forged=KeyAnnouncement.issue(f.f.group,key(99),0,f.f.now,r.version(),Crypto.blake2s(r.signedBytes()),
            KeyAnnouncement.commitment(f.f.group,0,f.groupKey),a.version(),Crypto.blake2s(a.signedBytes()));
        var before=state.snapshot();var store=new InMemoryAdminRecordStore();
        store.save(new AdminRecordStore.Snapshot(before.records(),before.anchorSignature(),before.revocations(),before.administratorVersion(),before.revocationVersion(),forged.encode()));
        var restored=new AdminState(f.f.group,f.f.ap,f.f.clock,store);assertThrows(SecurityException.class,restored::restore);
    }
}
