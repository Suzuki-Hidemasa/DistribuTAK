// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.nio.charset.StandardCharsets;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class JoinHandshakeTest {
    final AdminStateTest f=new AdminStateTest();
    final AtomicLong tick=new AtomicLong();
    final byte[] adminX=key(30), secret=key(31), groupKey=key(32);
    Invitation invitation() { return new Invitation(new byte[]{127,0,0,1},50000,Crypto.x25519Public(adminX),f.ap,secret, f.group); }
    List<AdminRecords.Record> chain() { return List.of(f.admins(0,f.now,List.of(f.ap,f.bp),f.b),f.admins(1,f.now,List.of(f.ap),f.b)); }
    JoinHandshake.Materials material() { return new JoinHandshake.Materials(chain(),f.revocations(0,f.now,List.of(),f.a),0,groupKey); }
    JoinHandshake.Admin admin(Invitation invitation) {
        return new JoinHandshake.Admin(invitation,chain().get(0),AdminRecords.signAnchor(chain().get(0),f.a),f.clock,tick::get);
    }
    JoinHandshake.Joiner joiner(Invitation invitation) { return new JoinHandshake.Joiner(invitation,f.identity,f.handshake,f.clock); }
    @Test void successfulJoinReturnsAllVerifiedStateAndKey() {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] response=admin.respond(joiner.request(),adminX,f.a,material);
            try(var joined=joiner.receive(response)) {
                assertArrayEquals(groupKey,joined.groupKey());assertEquals(1,joined.state().administrators().version());
                assertEquals(0,joined.state().revocations().version());
                joined.state().verifyCertificate(joined.certificate(),Crypto.x25519Public(f.handshake));
            }
            assertTrue(admin.isConsumed());
        }
    }
    @Test void retryGetsIdenticalReplyUntilTenSecondsAndNeverIssuesTwice() {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] request=joiner.request(), response=admin.respond(request,adminX,f.a,material);
            tick.set(9_999_999_999L);assertArrayEquals(response,admin.respond(joiner.retry(),adminX,f.a,material));
            try(var fresh=joiner(invite)) {
                byte[] randomized=fresh.request();assertFalse(Arrays.equals(request,randomized));
                byte[] same=admin.respond(randomized,adminX,f.a,material);assertArrayEquals(response,same);
                try(var result=fresh.receive(same)) { assertArrayEquals(groupKey,result.groupKey()); }
            }
            tick.set(10_000_000_000L);assertThrows(SecurityException.class,()->admin.respond(request,adminX,f.a,material));
        }
    }
    @Test void differentKeySameCodeIsRejected() {
        try(var invite=invitation();var admin=admin(invite);var first=joiner(invite);var other=new JoinHandshake.Joiner(invite,key(40),key(41),f.clock);var material=material()) {
            admin.respond(first.request(),adminX,f.a,material);
            assertThrows(SecurityException.class,()->admin.respond(other.request(),adminX,f.a,material));
        }
    }
    @Test void expiredRevokedAndBackwardsClockInvitationsAreRejected() {
        for(int scenario=0;scenario<3;scenario++) {
            tick.set(0);
            try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
                byte[] request=joiner.request();
                if(scenario==0) tick.set(Duration.ofHours(24).toNanos());
                else if(scenario==1) admin.revoke();
                else tick.set(-1);
                assertThrows(SecurityException.class,()->admin.respond(request,adminX,f.a,material));assertFalse(admin.isConsumed());
            }
        }
    }
    @Test void clocksOutsideOneTotpStepRejected() {
        try(var invite=invitation();var admin=admin(invite);var joiner=new JoinHandshake.Joiner(invite,f.identity,f.handshake,Clock.offset(f.clock,Duration.ofSeconds(60)));var material=material()) {
            assertThrows(SecurityException.class,()->admin.respond(joiner.request(),adminX,f.a,material));assertFalse(admin.isConsumed());
        }
    }
    byte[] requestPlain(byte[] packet) {
        var envelope=JoinMessages.packet(packet,false);
        byte[] info=Crypto.concat("DistribuTAK/join/request/v1".getBytes(StandardCharsets.US_ASCII),envelope.invitation);
        try(var hpke=Hpke.recipient(adminX,envelope.enc,info)) { return hpke.open(info,envelope.ciphertext); }
    }
    byte[] rewriteRequest(byte[] packet,byte[] proofKey,UnaryOperator<JoinMessages.Request> change) {
        var envelope=JoinMessages.packet(packet,false);byte[] plain=requestPlain(packet), encoded=null, unsigned=null, mac=null;
        try(var original=JoinMessages.request(plain);var altered=change.apply(original)) {
            unsigned=altered.unsigned();mac=Crypto.hmacSha256(proofKey,Crypto.concat("DistribuTAK/join/request-proof/v1".getBytes(StandardCharsets.US_ASCII),unsigned));
            byte[] signature;
            try(var withProof=new JoinMessages.Request(altered.invitation,altered.identity,altered.handshake,altered.binding,altered.code,mac)) {
                signature=Crypto.sign(f.identity,Crypto.concat("DistribuTAK/join/request-signature/v1".getBytes(StandardCharsets.US_ASCII),withProof.signedBytes()));
            }
            try(var signed=new JoinMessages.Request(altered.invitation,altered.identity,altered.handshake,altered.binding,altered.code,mac,signature)) {
                encoded=signed.encode();byte[] info=Crypto.concat("DistribuTAK/join/request/v1".getBytes(StandardCharsets.US_ASCII),envelope.invitation);
                try(var hpke=Hpke.sender(Crypto.x25519Public(adminX),info)) {
                    return new JoinMessages.Packet(false,envelope.invitation,hpke.encapsulation(),hpke.seal(info,encoded),new byte[0]).encode();
                }
            }
        } finally { Crypto.wipe(plain);Crypto.wipe(encoded);Crypto.wipe(unsigned);Crypto.wipe(mac); }
    }
    byte[] proofKey(JoinHandshake.Admin admin) throws Exception { return SecretAssertions.bytes(SecretAssertions.field(admin,"context"),"proofKey"); }
    @Test void incorrectTotpEvenWithValidProofDoesNotConsume() throws Exception {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] request=joiner.request();
            byte[] invalid=rewriteRequest(request,proofKey(admin),old->{byte[] code=old.code.clone();code[0]=code[0]==48 ? (byte)49 : (byte)48;
                return new JoinMessages.Request(old.invitation,old.identity,old.handshake,old.binding,code,old.proof);});
            assertThrows(SecurityException.class,()->admin.respond(invalid,adminX,f.a,material));assertFalse(admin.isConsumed());
            try(var result=joiner.receive(admin.respond(request,adminX,f.a,material))) { assertArrayEquals(groupKey,result.groupKey()); }
        }
    }
    @Test void correctTotpWithoutInvitationSecretProofDoesNotConsume() {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] request=joiner.request();byte[] invalid=rewriteRequest(request,key(99),old->new JoinMessages.Request(old.invitation,old.identity,old.handshake,old.binding,old.code,old.proof));
            assertThrows(SecurityException.class,()->admin.respond(invalid,adminX,f.a,material));assertFalse(admin.isConsumed());
        }
    }
    @Test void invalidIdentityBindingWithValidProofDoesNotConsume() throws Exception {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] invalid=rewriteRequest(joiner.request(),proofKey(admin),old->new JoinMessages.Request(old.invitation,old.identity,old.handshake,Crypto.sign(f.c,old.handshake),old.code,old.proof));
            assertThrows(SecurityException.class,()->admin.respond(invalid,adminX,f.a,material));assertFalse(admin.isConsumed());
        }
    }
    @Test void issuanceFailureHasNoPublishedCertificateOrConsumptionAndCanRetry() throws Exception {
        var fail=new AtomicBoolean(true);var held=new AtomicReference<byte[]>();
        try(var invite=invitation();var admin=new JoinHandshake.Admin(invite,chain().get(0),AdminRecords.signAnchor(chain().get(0),f.a),f.clock,tick::get,
                key->{held.set(key);if(fail.get()) throw new IllegalStateException("発行前の試験用の失敗");});var joiner=joiner(invite);var material=material()) {
            byte[] request=joiner.request();
            assertThrows(IllegalStateException.class,()->admin.respond(request,adminX,f.a,material));
            assertFalse(admin.isConsumed());assertNull(SecretAssertions.field(admin,"cachedReply"));SecretAssertions.zero(held.get());
            fail.set(false);byte[] response=admin.respond(request,adminX,f.a,material);SecretAssertions.zero(held.get());
            assertTrue(admin.isConsumed());try(var result=joiner.receive(response)) { assertArrayEquals(groupKey,result.groupKey()); }
        }
    }
    @Test void expiryDuringIssuanceCannotConsumeOrPublish() throws Exception {
        var held=new AtomicReference<byte[]>();
        try(var invite=invitation();var admin=new JoinHandshake.Admin(invite,chain().get(0),AdminRecords.signAnchor(chain().get(0),f.a),f.clock,tick::get,
                key->{held.set(key);tick.set(Duration.ofHours(24).toNanos());});var joiner=joiner(invite);var material=material()) {
            assertThrows(SecurityException.class,()->admin.respond(joiner.request(),adminX,f.a,material));
            assertFalse(admin.isConsumed());assertNull(SecretAssertions.field(admin,"cachedReply"));assertNull(SecretAssertions.field(admin,"anchor"));SecretAssertions.zero(held.get());
        }
    }
    byte[] replyFingerprint(byte[] request) {
        byte[] plain=requestPlain(request);try { return Crypto.blake2s(plain); } finally { Crypto.wipe(plain); }
    }
    JoinMessages.Response openResponse(byte[] reply,byte[] request) {
        var envelope=JoinMessages.packet(reply,true);
        byte[] info=Crypto.concat("DistribuTAK/join/response/v1".getBytes(StandardCharsets.US_ASCII),envelope.invitation,replyFingerprint(request)),plain=null;
        try(var hpke=Hpke.recipient(f.handshake,envelope.enc,info)) { plain=hpke.open(info,envelope.ciphertext);return JoinMessages.response(plain); }
        finally { Crypto.wipe(plain); }
    }
    @Test void eachIndependentlyReplacedResponseComponentFailsEvenWithAuthenticatedEnvelope() throws Exception {
        for(int component=0;component<5;component++) {
            try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
                byte[] request=joiner.request(), good=admin.respond(request,adminX,f.a,material);
                var body=openResponse(good,request);List<byte[]> history=new ArrayList<>(body.chain);
                byte[] revoked=body.revocations,cert=body.certificate,wrapped=body.wrapped,anchor=body.anchor;
                if(component==0) { byte[] changed=history.get(1).clone();changed[changed.length-1]^=1;history.set(1,changed); }
                if(component==1) revoked=f.revocations(0,f.now,List.of(),f.b).encode(); // 最新から外した管理者。
                if(component==2) cert=AdminRecords.certificate(f.group,f.cp,Crypto.x25519Public(f.handshake),SignaturePurpose.identityProof(f.c,f.group,Crypto.x25519Public(f.handshake)),f.now,f.a).encode();
                if(component==3) wrapped=GroupKeyEnvelope.wrap(f.group,key(55),Crypto.x25519Public(f.handshake),0,f.now,groupKey,f.a).encode();
                if(component==4) { anchor=anchor.clone();anchor[0]^=1; }
                var changed=new JoinMessages.Response(body.group,history,anchor,revoked,cert,wrapped);
                var outer=JoinMessages.packet(good,true);
                byte[] signed=JoinHandshake.sealReply(changed,outer.invitation,replyFingerprint(request),Crypto.x25519Public(f.handshake),f.a);
                byte[] held=SecretAssertions.bytes(joiner,"handshakeSecret");
                assertThrows(SecurityException.class,()->joiner.receive(signed));SecretAssertions.zero(held);
                assertThrows(IllegalStateException.class,()->joiner.receive(good));
            }
        }
    }
    @Test void tamperedOuterPacketAndOtherInvitationAreRejectedWithoutClosingReceiver() throws Exception {
        for(boolean otherInvite:new boolean[]{false,true}) {
            try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
                byte[] reply=admin.respond(joiner.request(),adminX,f.a,material), held=SecretAssertions.bytes(joiner,"handshakeSecret");
                if(otherInvite) {
                    try(var other=new Invitation(invite.adminAddress(),invite.udpPort(),invite.handshakePublicKey(),invite.adminPublicKey(),key(91), invite.groupId());var wrong=joiner(other)) {
                        byte[] wrongRequest=wrong.request(), wrongSecret=SecretAssertions.bytes(wrong,"handshakeSecret"), before=wrongSecret.clone();
                        assertThrows(SecurityException.class,()->wrong.receive(reply));assertArrayEquals(before,wrongSecret);assertArrayEquals(wrongRequest,wrong.retry());
                    }
                } else {
                    byte[] bad=reply.clone(), before=held.clone();bad[bad.length-1]^=1;
                    assertThrows(SecurityException.class,()->joiner.receive(bad));assertArrayEquals(before,held);assertDoesNotThrow(joiner::retry);
                }
                try(var joined=joiner.receive(reply)) { assertArrayEquals(groupKey,joined.groupKey()); }SecretAssertions.zero(held);
            }
        }
    }
    @Test void revokeExpiryAndConsumptionClearOwnedSecretsAnchorAndReply() throws Exception {
        for(int action=0;action<7;action++) {
            tick.set(0);
            try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
                byte[] anchor=SecretAssertions.bytes(admin,"anchor"), proof=proofKey(admin);
                Object verifier=SecretAssertions.field(admin,"verifier");byte[] secret=SecretAssertions.bytes(verifier,"secret");
                if(action==0 || action==4 || action==5) {
                    if(action==0) admin.revoke();
                    else { tick.set(action==4 ? Duration.ofHours(24).toNanos() : -1);admin.expire(); }
                    SecretAssertions.zero(anchor);SecretAssertions.zero(proof);SecretAssertions.zero(secret);assertNull(SecretAssertions.field(admin,"anchor"));continue;
                }
                admin.respond(joiner.request(),adminX,f.a,material);SecretAssertions.zero(anchor);SecretAssertions.zero(proof);SecretAssertions.zero(secret);
                assertNull(SecretAssertions.field(admin,"anchor"));byte[] cached=SecretAssertions.bytes(admin,"cachedReply");
                if(action==1) tick.set(Duration.ofSeconds(10).toNanos());
                else if(action==2) tick.set(-1);
                else if(action==6) admin.revoke();else admin.close();
                admin.expire();SecretAssertions.zero(cached);assertNull(SecretAssertions.field(admin,"cachedReply"));
                byte[] key=SecretAssertions.bytes(material,"groupKey");material.close();SecretAssertions.zero(key);assertTrue(((List<?>)SecretAssertions.field(material,"chain")).isEmpty());
            }
        }
    }
    @Test void joinedResultWipesOpenedKeyAndJoinerWipesSecretOnSuccess() throws Exception {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] held=SecretAssertions.bytes(joiner,"handshakeSecret");
            var result=joiner.receive(admin.respond(joiner.request(),adminX,f.a,material));SecretAssertions.zero(held);
            byte[] opened=SecretAssertions.bytes(SecretAssertions.field(result,"key"),"value");result.close();SecretAssertions.zero(opened);
            assertThrows(IllegalStateException.class,result::groupKey);
        }
    }
    @Test void retriesAreBoundedAndInvitationUrlRoundTrips() {
        try(var original=invitation();var invite=InvitationUrl.decode(InvitationUrl.encode(original));var joiner=joiner(invite)) {
            byte[] first=joiner.request();for(int i=0;i<5;i++) assertArrayEquals(first,joiner.retry());
            assertThrows(IllegalStateException.class,joiner::retry);assertEquals(1000,JoinHandshake.RETRY_INTERVAL_MILLIS);
        }
    }
    @Test void adjacentTotpStepsAreAcceptedAndDifferentCodeAfterConsumptionIsRejected() {
        for(long offset:new long[]{-30,30}) {
            tick.set(0);
            try(var invite=invitation();var admin=admin(invite);var joiner=new JoinHandshake.Joiner(invite,f.identity,f.handshake,Clock.offset(f.clock,Duration.ofSeconds(offset)));var material=material()) {
                try(var result=joiner.receive(admin.respond(joiner.request(),adminX,f.a,material))) { assertArrayEquals(groupKey,result.groupKey()); }
            }
        }
        try(var invite=invitation();var admin=admin(invite);var first=joiner(invite);
            var other=new JoinHandshake.Joiner(invite,f.identity,f.handshake,Clock.offset(f.clock,Duration.ofSeconds(30)));var material=material()) {
            admin.respond(first.request(),adminX,f.a,material);
            assertThrows(SecurityException.class,()->admin.respond(other.request(),adminX,f.a,material));
        }
    }
    @Test void revokedMemberAndRemovedAdministratorOrBrokenChainDoNotConsume() {
        for(int scenario=0;scenario<3;scenario++) {
            try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite)) {
                List<AdminRecords.Record> history=chain();var revoked=f.revocations(0,f.now,List.of(),f.a);
                if(scenario==0) revoked=f.revocations(0,f.now,List.of(Crypto.blake2s(Crypto.ed25519Public(f.identity))),f.a);
                if(scenario==1) { history=List.of(history.get(0),f.admins(1,f.now,List.of(f.bp),f.a));revoked=f.revocations(0,f.now,List.of(),f.b); }
                if(scenario==2) history=List.of(history.get(0),f.admins(2,f.now,List.of(f.ap),f.a));
                try(var material=new JoinHandshake.Materials(history,revoked,0,groupKey)) {
                    assertThrows(SecurityException.class,()->admin.respond(joiner.request(),adminX,f.a,material));assertFalse(admin.isConsumed());
                }
            }
        }
    }
    @Test void largeRevocationsAreEncryptedAndReceivedBeyondNoiseMessageSize() {
        List<byte[]> ids=new ArrayList<>();
        for(int i=0;i<65536;i++) ids.add(AdminRecordsFix1Test.id(i));
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);
            var material=new JoinHandshake.Materials(chain(),f.revocations(0,f.now,ids,f.a),0,groupKey)) {
            byte[] reply=admin.respond(joiner.request(),adminX,f.a,material);assertTrue(reply.length>65535);
            try(var result=joiner.receive(reply)) { assertEquals(65536,result.state().revocations().entries().size());assertArrayEquals(groupKey,result.groupKey()); }
        }
    }
    @Test void fullChainLimitRoundTripsAndOneMoreIsRejected() {
        List<AdminRecords.Record> history=new ArrayList<>();history.add(chain().get(0));
        for(int i=1;i<64;i++) history.add(f.admins(i,f.now,List.of(f.ap),f.a));
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);
            var material=new JoinHandshake.Materials(history,f.revocations(0,f.now,List.of(),f.a),0,groupKey)) {
            try(var result=joiner.receive(admin.respond(joiner.request(),adminX,f.a,material))) { assertEquals(63,result.state().administrators().version()); }
            history.add(f.admins(64,f.now,List.of(f.ap),f.a));
            assertThrows(IllegalArgumentException.class,()->new JoinHandshake.Materials(history,f.revocations(0,f.now,List.of(),f.a),0,groupKey));
        }
    }
    @Test void oversizedPacketsRejectedWithoutConsumptionOrClosingPendingJoiner() throws Exception {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            assertThrows(IllegalArgumentException.class,()->admin.respond(new byte[JoinHandshake.MAX_REQUEST_BYTES+1],adminX,f.a,material));assertFalse(admin.isConsumed());
            byte[] request=joiner.request(),held=SecretAssertions.bytes(joiner,"handshakeSecret"), before=held.clone();
            assertThrows(IllegalArgumentException.class,()->joiner.receive(new byte[JoinHandshake.MAX_RESPONSE_BYTES+1]));assertArrayEquals(before,held);
            assertArrayEquals(request,joiner.retry());
            try(var joined=joiner.receive(admin.respond(request,adminX,f.a,material))) { assertArrayEquals(groupKey,joined.groupKey()); }SecretAssertions.zero(held);
        }
    }
    @Test void invalidWholeRequestSignatureDoesNotConsume() {
        try(var invite=invitation();var admin=admin(invite);var joiner=joiner(invite);var material=material()) {
            byte[] original=joiner.request(),plain=requestPlain(original),encoded=null;
            try(var request=JoinMessages.request(plain)) {
                byte[] signature=request.signature.clone();signature[0]^=1;
                try(var bad=new JoinMessages.Request(request.invitation,request.identity,request.handshake,request.binding,request.code,request.proof,signature)) {
                    encoded=bad.encode();byte[] info=Crypto.concat("DistribuTAK/join/request/v1".getBytes(StandardCharsets.US_ASCII),request.invitation);
                    try(var hpke=Hpke.sender(invite.handshakePublicKey(),info)) {
                        byte[] packet=new JoinMessages.Packet(false,request.invitation,hpke.encapsulation(),hpke.seal(info,encoded),new byte[0]).encode();
                        assertThrows(SecurityException.class,()->admin.respond(packet,adminX,f.a,material));assertFalse(admin.isConsumed());
                        try(var joined=joiner.receive(admin.respond(original,adminX,f.a,material))) { assertArrayEquals(groupKey,joined.groupKey()); }
                    }
                }
            } finally { Crypto.wipe(plain);Crypto.wipe(encoded); }
        }
    }
    @Test void concurrentJoinersCanOnlyConsumeOneInvitationOnce() throws Exception {
        var executor=java.util.concurrent.Executors.newFixedThreadPool(2);
        try(var invite=invitation();var admin=admin(invite);var one=joiner(invite);
            var two=new JoinHandshake.Joiner(invite,key(71),key(72),f.clock);var material=material()) {
            var start=new java.util.concurrent.CountDownLatch(1);List<java.util.concurrent.Future<Boolean>> results=new ArrayList<>();
            for(byte[] request:List.of(one.request(),two.request())) results.add(executor.submit(()->{
                start.await();try { admin.respond(request,adminX,f.a,material);return true; } catch(SecurityException rejected) { return false; }
            }));
            start.countDown();int accepted=0;
            for(var result:results) if(result.get(5,java.util.concurrent.TimeUnit.SECONDS)) accepted++;
            assertEquals(1,accepted);assertTrue(admin.isConsumed());
        } finally { executor.shutdownNow(); }
    }
}
