// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class JoinHandshakeFix1Test {
    final JoinHandshakeTest fixture=new JoinHandshakeTest();

    @Test void joinedReportsVerifiedGroupKeyVersionIndependentOfAdministratorVersion() throws Exception {
        var f=fixture.f;
        try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite);
            var material=new JoinHandshake.Materials(fixture.chain(),f.revocations(0,f.now,List.of(),f.a),7,fixture.groupKey);
            var joined=joiner.receive(admin.respond(joiner.request(),fixture.adminX,f.a,material))) {
            assertArrayEquals(fixture.groupKey,joined.groupKey());assertEquals(1,joined.state().administrators().version());
            assertEquals(7L,joined.groupKeyVersion());
        }
    }
    @Test void unauthenticatedPacketsDoNotChangeJoinerAndRealReplyStillWorks() throws Exception {
        for(String scenario:List.of("signature","broken","oversize","kind","invitation","manual-close")) {
            try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite);var material=fixture.material()) {
                byte[] request=joiner.request(), good=admin.respond(request,fixture.adminX,fixture.f.a,material), bad;
                var packet=JoinMessages.packet(good,true);
                switch(scenario) {
                    case "signature", "manual-close" -> { bad=good.clone();bad[bad.length-1]^=1; }
                    case "broken" -> bad=new byte[]{1};
                    case "oversize" -> bad=new byte[JoinHandshake.MAX_RESPONSE_BYTES+1];
                    case "kind" -> { bad=good.clone();bad[1]=3; }
                    case "invitation" -> bad=new JoinMessages.Packet(true,key(99),packet.enc,packet.ciphertext,packet.signature).encode();
                    default -> throw new AssertionError();
                }
                byte[] held=SecretAssertions.bytes(joiner,"handshakeSecret"), before=held.clone();
                Class<? extends RuntimeException> expected=scenario.equals("signature") || scenario.equals("invitation") || scenario.equals("manual-close") ? SecurityException.class : IllegalArgumentException.class;
                assertThrows(expected,()->joiner.receive(bad),scenario);
                assertArrayEquals(before,held,scenario);assertEquals(false,SecretAssertions.field(joiner,"closed"),scenario);
                if(scenario.equals("manual-close")) {
                    joiner.close();SecretAssertions.zero(held);assertThrows(IllegalStateException.class,joiner::retry);
                    assertThrows(IllegalStateException.class,()->joiner.receive(good));continue;
                }
                assertArrayEquals(request,joiner.retry(),scenario);
                try(var joined=joiner.receive(good)) { assertArrayEquals(fixture.groupKey,joined.groupKey()); }
                SecretAssertions.zero(held);
            }
        }
    }
    @Test void sameHandshakeAndCodeButDifferentIdentityCannotTakeOriginalReply() {
        try(var invite=fixture.invitation();var admin=fixture.admin(invite);var original=fixture.joiner(invite);
            var other=new JoinHandshake.Joiner(invite,key(71),fixture.f.handshake,fixture.f.clock);var material=fixture.material()) {
            byte[] first=admin.respond(original.request(),fixture.adminX,fixture.f.a,material);
            assertThrows(SecurityException.class,()->admin.respond(other.request(),fixture.adminX,fixture.f.a,material));
            byte[] retry=admin.respond(original.retry(),fixture.adminX,fixture.f.a,material);assertArrayEquals(first,retry);
            try(var joined=original.receive(retry)) { assertArrayEquals(fixture.groupKey,joined.groupKey()); }
        }
    }
    @Test void changedGroupAloneWithValidOuterSignatureClosesAndAdoptsNothing() throws Exception {
        try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite);var material=fixture.material()) {
            byte[] request=joiner.request(), good=admin.respond(request,fixture.adminX,fixture.f.a,material);
            var body=fixture.openResponse(good,request);var envelope=JoinMessages.packet(good,true);
            var changed=new JoinMessages.Response(key(99),body.chain,body.anchor,body.revocations,body.certificate,body.wrapped);
            byte[] signed=JoinHandshake.sealReply(changed,envelope.invitation,fixture.replyFingerprint(request),Crypto.x25519Public(fixture.f.handshake),fixture.f.a);
            byte[] held=SecretAssertions.bytes(joiner,"handshakeSecret");
            assertThrows(SecurityException.class,()->joiner.receive(signed));SecretAssertions.zero(held);
            assertThrows(IllegalStateException.class,joiner::retry);assertThrows(IllegalStateException.class,()->joiner.receive(good));
        }
    }
    byte[] signedRawReply(byte[] good,byte[] request,byte[] plaintext,boolean breakHpke) {
        var packet=JoinMessages.packet(good,true);
        byte[] info=Crypto.concat("DistribuTAK/join/response/v1".getBytes(StandardCharsets.US_ASCII),packet.invitation,fixture.replyFingerprint(request));
        try(var hpke=Hpke.sender(Crypto.x25519Public(fixture.f.handshake),info)) {
            byte[] ciphertext=hpke.seal(info,plaintext);if(breakHpke) ciphertext[0]^=1;
            var unsigned=new JoinMessages.Packet(true,packet.invitation,hpke.encapsulation(),ciphertext,new byte[64]);
            byte[] signature=Crypto.sign(fixture.f.a,Crypto.concat("DistribuTAK/join/response-signature/v1".getBytes(StandardCharsets.US_ASCII),info,unsigned.signedBytes()));
            return new JoinMessages.Packet(true,packet.invitation,hpke.encapsulation(),ciphertext,signature).encode();
        }
    }
    @Test void authenticatedMalformedInnerProtobufClosesAndClearsSecret() throws Exception {
        try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite);var material=fixture.material()) {
            byte[] request=joiner.request(),good=admin.respond(request,fixture.adminX,fixture.f.a,material);
            byte[] malformed=signedRawReply(good,request,new byte[]{0},false),held=SecretAssertions.bytes(joiner,"handshakeSecret");
            assertThrows(IllegalArgumentException.class,()->joiner.receive(malformed));SecretAssertions.zero(held);
            assertThrows(IllegalStateException.class,joiner::retry);assertThrows(IllegalStateException.class,()->joiner.receive(good));
        }
    }
    @Test void authenticatedHpkeFailureAlsoClosesAndClearsSecret() throws Exception {
        try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite);var material=fixture.material()) {
            byte[] request=joiner.request(),good=admin.respond(request,fixture.adminX,fixture.f.a,material);
            byte[] malformed=signedRawReply(good,request,new byte[]{0},true),held=SecretAssertions.bytes(joiner,"handshakeSecret");
            assertThrows(SecurityException.class,()->joiner.receive(malformed));SecretAssertions.zero(held);assertThrows(IllegalStateException.class,joiner::retry);
        }
    }
    @Test void joinedStateIsSharedAndCloseClearsHeldStateReference() {
        try(var invite=fixture.invitation();var admin=fixture.admin(invite);var joiner=fixture.joiner(invite);var material=fixture.material()) {
            var joined=joiner.receive(admin.respond(joiner.request(),fixture.adminX,fixture.f.a,material));
            var state=joined.state();assertSame(state,joined.state());assertEquals(1,state.administrators().version());
            joined.close();assertThrows(IllegalStateException.class,state::administrators);assertThrows(IllegalStateException.class,joined::state);
        }
    }
}
