// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;
import static org.junit.Assert.*;
public class RejoinedStorageTest {
    final GroupStateStorageTest f=new GroupStateStorageTest();
    static final class Fixture implements AutoCloseable {
        final LanGroup admin,member;
        Fixture()throws Exception {
            admin=LanGroup.create(54321,StorageGroupTest.CLOCK,new SecureRandom());
            try(var invite=invitation();var issuer=issuer(invite,StorageGroupTest.CLOCK);
                var joiner=new JoinHandshake.Joiner(invite,StoredUpdatesTest.key(71),StoredUpdatesTest.key(72),StorageGroupTest.CLOCK);var material=materials()) {
                try(var joined=joiner.receive(issuer.respond(joiner.request(),admin.handshakeSecret,admin.administratorSecret,material))) {
                    member=LanGroup.joined(54322,StoredUpdatesTest.key(71),StoredUpdatesTest.key(72),admin.urlAdmin,joined,StorageGroupTest.CLOCK);
                }
            }
            member.peerCertificate=admin.certificate;member.peerAddress=new InetSocketAddress("192.168.1.10",54321);member.syncInitialized=true;member.renewalCount=4;
        }
        Invitation invitation(){return new Invitation(new byte[]{(byte)192,(byte)168,1,10},54321,Crypto.x25519Public(admin.handshakeSecret),admin.urlAdmin,StoredUpdatesTest.key(73), admin.groupId);}
        JoinHandshake.Admin issuer(Invitation invite,Clock clock){return new JoinHandshake.Admin(invite,admin.state.administrators(),admin.state.snapshot().anchorSignature(),clock,()->0);}
        JoinHandshake.Materials materials(){return materials(null);}
        JoinHandshake.Materials materials(byte[] expected){
            try(var service=new GroupAdministration(admin.state,admin.certificate,admin.identitySecret,admin.handshakeSecret,
                    admin.administratorSecret,StorageGroupTest.CLOCK,()->0,new SecureRandom())){
                return service.invitationMaterials(admin.groupKey,admin.keyVersion,expected);
            }
        }
        LanGroup rejoin(Clock clock)throws Exception {
            byte[] handshake=StoredUpdatesTest.key(74);
            try(var invite=invitation();var issuer=issuer(invite,clock);
                var joiner=JoinHandshake.Joiner.rejoin(invite,member.identitySecret,handshake,clock,member.state,member.certificate,member.keyVersion,member.groupKey,member.state.announcement(),member.state.revokedSubjects());
                var material=materials(Crypto.ed25519Public(member.identitySecret))) {
                try(var joined=joiner.receive(issuer.respond(joiner.request(),admin.handshakeSecret,admin.administratorSecret,material))) {
                    return LanGroup.rejoined(member,handshake,admin.urlAdmin,joined,clock);
                }
            }
        }
        public void close(){member.close();admin.close();}
    }
    LanRuntime.Pending stage(LanGroup candidate)throws Exception {
        return f.storage().stage(candidate,f.temporary,()->f.temporary.value.clone(),()->f.temporary.value=null);
    }
    @Test public void rejoinAtomicallyPreservesIdentityPortPeerSyncFlagAndCount()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);byte[] old=f.state.value.clone();
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1));
            try(var candidate=pair.rejoin(later)) {
                var staged=stage(candidate);assertArrayEquals(old,f.state.value);
                f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged);
                assertNull(f.temporary.value);
                try(var restored=f.storage().load(later)) {
                    assertEquals(2,restored.saveSeq);assertEquals(4,restored.renewalCount);assertTrue(restored.syncInitialized);
                    assertEquals(pair.member.port,restored.port);assertArrayEquals(pair.member.id(),restored.id());
                    assertArrayEquals(pair.member.peerCertificate.encode(),restored.peerCertificate.encode());
                    assertArrayEquals(candidate.handshakeSecret,restored.handshakeSecret);assertFalse(Arrays.equals(pair.member.handshakeSecret,restored.handshakeSecret));
                }
            }
        }
    }
    @Test public void syncAndExternalBytesRemainReadableAndIdenticalAfterRejoin()throws Exception {
        try(var pair=new Fixture()) {
            var disk=new SyncStateStorageTest.Disk();var sync=SyncStateStorageTest.storage(disk);
            pair.member.syncInitialized=false;var records=sync.load(pair.member,()->{});
            var marks=new ExternalStateStorage(new StateEnvelope(new StateEnvelopeTest.TestCipher()),disk.external,disk.external);
            var external=marks.load(pair.member);external.add("fixture-external");marks.save(pair.member,external);
            byte[] oldSync=disk.value.clone(),oldExternal=disk.external.value.clone();f.storage().save(pair.member);
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1));
            try(var candidate=pair.rejoin(later)) {
                f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),stage(candidate));
                assertArrayEquals(oldSync,disk.value);assertArrayEquals(oldExternal,disk.external.value);
                assertEquals(records.uidCount(),sync.load(candidate,()->fail()).uidCount());assertTrue(marks.load(candidate).contains("fixture-external"));
            }
        }
    }
    @Test public void settingsOnlyFailureDoesNotUndoCommittedRejoin()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1));
            try(var candidate=pair.rejoin(later)) {
                var staged=stage(candidate);f.settings.fail=true;
                f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged);assertEquals(2,candidate.saveSeq);
                assertEquals(1,StateSettings.decode(f.settings.value).saveSeq);f.settings.fail=false;
                try(var loaded=f.storage().load(later)){assertEquals(2,loaded.saveSeq);assertArrayEquals(candidate.certificate.encode(),loaded.certificate.encode());}
                assertEquals(2,StateSettings.decode(f.settings.value).saveSeq);
            }
        }
    }
    @Test public void rejoinWriteFailureRestoresSequenceAndLeavesPreviousBytes()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);byte[] old=f.state.value.clone(),config=f.settings.value.clone();
            try(var candidate=pair.rejoin(Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1)))) {
                var staged=stage(candidate);f.state.fail=true;
                assertThrows(Exception.class,()->f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged));
                assertEquals(1,candidate.saveSeq);assertArrayEquals(old,f.state.value);assertArrayEquals(config,f.settings.value);staged.abort();
            }
        }
    }
    @Test public void rejoinRejectsOtherGroupBeforeCommittingAndAbortRestoresSequence()throws Exception {
        try(var pair=new Fixture();var other=LanGroup.create(54322,StorageGroupTest.CLOCK,new SecureRandom())) {
            f.storage().save(pair.member);byte[] old=f.state.value.clone();var staged=stage(other);
            assertThrows(SecurityException.class,()->f.storage().acceptRejoined(pair.member,other,CompletableFuture.completedFuture(null),staged));
            assertArrayEquals(old,f.state.value);assertEquals(0,other.saveSeq);staged.abort();
        }
    }
    @Test public void corruptedStagedEnvelopeNeverReplacesPreviousState()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);byte[] old=f.state.value.clone();
            try(var candidate=pair.rejoin(Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1)))) {
                var staged=stage(candidate);f.temporary.value[f.temporary.value.length-1]^=1;
                assertThrows(Exception.class,()->f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged));
                assertArrayEquals(old,f.state.value);assertEquals(1,candidate.saveSeq);staged.abort();
            }
        }
    }
    @Test public void rejoinCannotSilentlyDropSavedPeer()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);byte[] old=f.state.value.clone();
            try(var candidate=pair.rejoin(Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1)))) {
                candidate.peerCertificate=null;candidate.peerAddress=null;var staged=stage(candidate);
                assertThrows(SecurityException.class,()->f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged));
                assertArrayEquals(old,f.state.value);staged.abort();
            }
        }
    }
    @Test public void candidateCannotChangeAfterStaging()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);byte[] old=f.state.value.clone();
            var later=Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1));
            try(var candidate=pair.rejoin(later)) {
                var staged=stage(candidate);byte[] pub=Crypto.x25519Public(candidate.handshakeSecret);
                candidate.certificate=AdminRecords.certificate(candidate.groupId,Crypto.ed25519Public(candidate.identitySecret),pub,SignaturePurpose.identityProof(candidate.identitySecret,candidate.groupId,pub),later.millis()+1,pair.admin.administratorSecret);
                assertThrows(SecurityException.class,()->f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged));
                assertArrayEquals(old,f.state.value);staged.abort();
            }
        }
    }
    @Test public void savingRechecksIdentityBothListVersionsAndKeyVersion()throws Exception {
        for(int scenario=0;scenario<4;scenario++)try(var pair=new Fixture()) {
            f.state.fail=false;f.storage().save(pair.member);byte[] old=f.state.value.clone();
            try(var candidate=pair.rejoin(Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(1)))) {
                var staged=stage(candidate);
                if(scenario==0)candidate.identitySecret=StoredUpdatesTest.key(75);
                if(scenario==1)pair.member.state.acceptAdministrators(AdminRecords.administrators(pair.member.groupId,1,StorageGroupTest.NOW,pair.member.state.administrators().bindings(),pair.admin.administratorSecret),v->fail());
                if(scenario==2)pair.member.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,pair.member.groupId,1,StorageGroupTest.NOW,List.of(),pair.admin.administratorSecret));
                if(scenario==3)pair.member.keyVersion=1;
                assertThrows(SecurityException.class,()->f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),staged));
                assertArrayEquals(old,f.state.value);staged.abort();
            }
        }
    }
    @Test public void rejoinCanPersistEarlierCertificateTimeWithoutFalseRollback()throws Exception {
        try(var pair=new Fixture()) {
            f.storage().save(pair.member);var earlier=Clock.offset(StorageGroupTest.CLOCK,Duration.ofSeconds(-1));
            try(var candidate=pair.rejoin(earlier)) {
                assertTrue(candidate.certificate.issuedAt()<pair.member.certificate.issuedAt());
                f.storage().acceptRejoined(pair.member,candidate,CompletableFuture.completedFuture(null),stage(candidate));
                try(var loaded=f.storage().load(earlier)){assertEquals(2,loaded.saveSeq);assertEquals(candidate.certificate.issuedAt(),StateSettings.decode(f.settings.value).issuedAt);}
            }
        }
    }
}
