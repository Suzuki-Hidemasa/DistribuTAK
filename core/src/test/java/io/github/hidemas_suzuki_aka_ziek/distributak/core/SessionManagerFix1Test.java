// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.Duration;
import java.time.Instant;
import java.time.Clock;
import java.time.ZoneOffset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionManagerTest.Node;

class SessionManagerFix1Test {
    final SessionManagerTest f=new SessionManagerTest();
    Node node(int n) { return f.new Node(n); }
    Node low(Node a,Node b) { return AdminRecords.compareBytes(Crypto.x25519Public(a.secret),Crypto.x25519Public(b.secret))<0 ? a : b; }
    void finish(Node initiator,Node responder,SessionManager.Outbound first) {
        var reply=responder.sessions.receive(first.packet()).outbound().get(0);
        var confirmation=initiator.sessions.receive(reply.packet()).outbound().get(0);
        responder.sessions.receive(confirmation.packet());
        assertTrue(initiator.sessions.isEstablished(responder.id));assertTrue(responder.sessions.isEstablished(initiator.id));
    }
    void setSent(Node a,Node b,long value) throws Exception {
        var sent=NoiseTransport.class.getDeclaredField("sent");sent.setAccessible(true);sent.setLong(f.active(a,b),value);
    }
    @Test void forgedSecondThenFreshFirstReplacesUnconfirmedCandidateAndRecovers() throws Exception {
        for(boolean forged:new boolean[]{false,true}) {
            try(var a=node(1);var b=node(2)) {
                f.connect(a,b);var oldA=f.secrets(a,b);var oldB=f.secrets(b,a);f.time.advance(120);
                var first=a.sessions.poll().get(0);var second=b.sessions.receive(first.packet()).outbound().get(0);
                if(forged) {
                    byte[] fake=second.packet();fake[fake.length-1]^=1; // 枠と暗号文だけで作れ、psk は不要。
                    assertThrows(SecurityException.class,()->a.sessions.receive(fake));
                    var candidate=f.secrets(b,a).subList(2,4);
                    assertTrue(a.sessions.isEstablished(b.id));assertTrue(b.sessions.isEstablished(a.id));
                    assertTrue(a.sessions.poll().isEmpty());f.time.advance(5);var fresh=a.sessions.poll().get(0);
                    assertFalse(Arrays.equals(first.packet(),fresh.packet()));
                    second=b.sessions.receive(fresh.packet()).outbound().get(0);f.wiped(candidate);
                }
                var confirm=a.sessions.receive(second.packet()).outbound().get(0);b.sessions.receive(confirm.packet());
                f.wiped(oldA);f.wiped(oldB);
                assertArrayEquals(new byte[]{1},b.sessions.receive(f.data(a,b,1)).plaintext());
                assertArrayEquals(new byte[]{2},a.sessions.receive(f.data(b,a,2)).plaintext());
            }
        }
    }
    @Test void earlyCounterRekeyWorksForBothPublicKeyOrders() throws Exception {
        for(boolean smallerInitiates:new boolean[]{false,true}) {
            try(var a=node(1);var b=node(2)) {
                Node small=low(a,b),large=small==a ? b : a;
                f.connect(small,large);Node sender=smallerInitiates ? small : large,receiver=sender==a ? b : a;
                setSent(sender,receiver,NoiseTransport.REKEY_MESSAGES-1);
                assertTrue(sender.sessions.poll().isEmpty());
                assertArrayEquals(new byte[]{3},receiver.sessions.receive(f.data(sender,receiver,3)).plaintext());
                finish(sender,receiver,sender.sessions.poll().get(0));
                assertArrayEquals(new byte[]{4},receiver.sessions.receive(f.data(sender,receiver,4)).plaintext());
            }
        }
    }
    @Test void reinstalledLargerPeerCanStartImmediately() {
        try(var a=node(1);var b=node(2)) {
            Node small=low(a,b),large=small==a ? b : a;f.connect(small,large);large.sessions.close();
            // 入れ直し後の時刻が、認証済み2通目の境と同じでも受ける。
            try(var replacement=node(large==a ? 1 : 2)) {
                replacement.remember(small);finish(replacement,small,replacement.sessions.start(small.id));
                assertArrayEquals(new byte[]{1},small.sessions.receive(f.data(replacement,small,1)).plaintext());
            }
        }
    }
    @Test void rotatingGroupKeySchedulesPendingCandidateAndExpiredPeerButNotRevoked() throws Exception {
        for(int stage=0;stage<3;stage++) for(boolean reverse:new boolean[]{false,true}) {
            try(var a=node(1);var b=node(2);var revoked=node(3)) {
                a.remember(b);b.remember(a);a.remember(revoked);
                Node sender=reverse ? b : a,receiver=reverse ? a : b;
                var first=(stage==1 ? receiver : sender).sessions.start((stage==1 ? sender : receiver).id);
                if(stage==1) sender.sessions.receive(first.packet());
                if(stage==2) { finish(sender,receiver,first);f.time.advance(181);a.sessions.refresh();b.sessions.refresh(); }
                a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis(),List.of(revoked.id),f.admin));
                List<byte[]> oldA=stage<2 ? f.secrets(sender,receiver) : List.of(),oldB=stage==1 ? f.secrets(receiver,sender) : List.of();
                a.sessions.rotateGroupKey(key(50),1);b.sessions.rotateGroupKey(key(50),1);f.wiped(oldA);f.wiped(oldB);
                List<SessionManager.Outbound> next;
                if(stage==2) {
                    assertTrue(a.sessions.poll().isEmpty());assertTrue(b.sessions.poll().isEmpty());
                    next=sender.sessions.sendWithStatus(receiver.id,new byte[]{99}).outbound();
                } else {
                    if(stage==0) { assertTrue(sender.sessions.poll().isEmpty());f.time.advance(5); }
                    next=sender.sessions.poll();
                }
                assertEquals(1,next.size());assertArrayEquals(receiver.id,next.get(0).peerId());
                assertEquals(1,SessionPacket.decode(next.get(0).packet()).version());finish(sender,receiver,next.get(0));
                assertArrayEquals(new byte[]{5},b.sessions.receive(f.data(a,b,5)).plaintext());
            }
        }
    }
    @Test void sendAfterTimeoutStartsNewHandshakeWithoutQueuingPlaintextAndIdlePollDoesNotStart() {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);b.remember(a);var old=a.sessions.start(b.id).packet();f.time.advance(90);
            assertTrue(a.sessions.poll().isEmpty());assertFalse(a.sessions.isHandshaking(b.id));
            f.time.advance(5);assertTrue(a.sessions.poll().isEmpty());
            var status=a.sessions.sendWithStatus(b.id,new byte[]{99});assertFalse(status.plaintextSent());
            var restarted=status.outbound();assertEquals(1,restarted.size());
            assertEquals(SessionPacket.FIRST,SessionPacket.decode(restarted.get(0).packet()).kind());
            assertFalse(Arrays.equals(old,restarted.get(0).packet()));
            var same=a.sessions.send(b.id,new byte[]{98});
            assertTrue(same.isEmpty() || Arrays.equals(restarted.get(0).packet(),same.get(0).packet()));
            finish(a,b,restarted.get(0));assertTrue(a.sessions.poll().isEmpty());
            var sent=a.sessions.sendWithStatus(b.id,new byte[]{7});assertTrue(sent.plaintextSent());
            assertArrayEquals(new byte[]{7},b.sessions.receive(sent.outbound().get(0).packet()).plaintext());
        }
    }
    @Test void revokedUnknownSelfInvalidAndClosedManagersCannotRestartFromSend() {
        try(var a=node(1);var b=node(2);var c=node(3)) {
            a.remember(b);a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis(),List.of(b.id),f.admin));
            assertThrows(SecurityException.class,()->a.sessions.send(b.id,new byte[]{1}));
            assertThrows(SecurityException.class,()->a.sessions.send(c.id,new byte[]{1}));
            assertTrue(a.sessions.poll().isEmpty());assertFalse(a.sessions.isHandshaking(b.id));
            c.remember(b);c.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis(),List.of(c.id),f.admin));
            assertThrows(IllegalStateException.class,()->c.sessions.send(b.id,new byte[]{1}));assertTrue(c.sessions.poll().isEmpty());
            b.sessions.close();assertThrows(IllegalStateException.class,()->b.sessions.send(a.id,new byte[]{1}));
        }
    }
    @Test void lateOldDataIsRejectedImmediatelyAfterRekeyWhileNewDataWorks() throws Exception {
        try(var a=node(1);var b=node(2)) {
            f.connect(a,b);var oldA=f.secrets(a,b);var oldB=f.secrets(b,a);
            byte[] delayedToB=f.data(a,b,1),delayedToA=f.data(b,a,2);
            f.time.advance(120);finish(a,b,a.sessions.poll().get(0));f.wiped(oldA);f.wiped(oldB);
            assertThrows(SecurityException.class,()->a.sessions.receive(delayedToA));
            assertThrows(SecurityException.class,()->b.sessions.receive(delayedToB));
            assertArrayEquals(new byte[]{3},b.sessions.receive(f.data(a,b,3)).plaintext());
            assertArrayEquals(new byte[]{4},a.sessions.receive(f.data(b,a,4)).plaintext());
        }
    }
    @Test void rollingBothWallClocksBackKeepsIncreasingFirstTimestampAndOffsetIsAnEstimate() {
        try(var a=node(1);var b=node(2)) {
            f.connect(a,b);assertEquals(Duration.ZERO,b.sessions.peerClockOffset(a.id));
            f.time.millis-=60_000;finish(a,b,a.sessions.start(b.id));
            Duration offset=b.sessions.peerClockOffset(a.id);
            assertTrue(offset.compareTo(Duration.ofSeconds(60))>=0);assertTrue(offset.compareTo(Duration.ofSeconds(61))<0);
            f.time.millis+=60_001;finish(a,b,a.sessions.start(b.id));assertEquals(Duration.ZERO,b.sessions.peerClockOffset(a.id));
        }
    }
    @Test void rememberPeerRejectsOlderAndSameTimeConflictingCertificateWithoutDestroyingLiveKeys() throws Exception {
        try(var a=node(1);var b=node(2)) {
            f.connect(a,b);var live=f.active(a,b);long issued=b.cert.issuedAt();
            var older=b.certificate(key(55),issued-1);
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(older));
            assertFalse(live.isClosed());assertArrayEquals(new byte[]{1},b.sessions.receive(f.data(a,b,1)).plaintext());
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(b.certificate(key(55),issued)));
            assertFalse(live.isClosed());a.sessions.rememberPeer(b.cert);
            f.time.advance(1);a.sessions.rememberPeer(b.certificate(key(55),f.time.millis()));assertTrue(live.isClosed());
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(b.cert));
        }
    }
    @Test void oldCertificateCannotClearInvalidFlagForANewerCertificate() throws Exception {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);f.time.advance(1);var latest=b.certificate(b.secret,f.time.millis());a.sessions.rememberPeer(latest);
            // 現在の証明書が先すぎる状態を作る。古い証明書だけは5分の範囲に残す。
            f.time.millis=latest.issuedAt()-300_001;a.sessions.refresh();assertEquals(true,SessionManagerTest.field(f.peerState(a,b),"invalid"));
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(b.cert));
            assertEquals(true,SessionManagerTest.field(f.peerState(a,b),"invalid"));
            b.remember(a);byte[] oldFirst=b.sessions.start(a.id).packet();var before=timestamps(a);
            assertThrows(SecurityException.class,()->a.sessions.receive(oldFirst));
            assertEquals(before,timestamps(a));assertEquals(true,SessionManagerTest.field(f.peerState(a,b),"invalid"));
            f.time.millis=latest.issuedAt();a.sessions.rememberPeer(latest);assertEquals(false,SessionManagerTest.field(f.peerState(a,b),"invalid"));
        }
    }
    Map<String,String> timestamps(Node n) throws Exception {
        Object guard=SessionManagerTest.field(n.sessions,"replay");
        var result=new HashMap<String,String>();
        for(var e:((Map<?,?>)SessionManagerTest.field(guard,"newest")).entrySet())
            result.put((String)e.getKey(),org.bouncycastle.util.encoders.Hex.toHexString((byte[])e.getValue()));
        return result;
    }
    byte[] firstAt(Node sender,Node receiver,Instant when,int seed) {
        byte[] id=new byte[16];id[0]=(byte)seed;
        byte[] prologue=Crypto.concat("DistribuTAK/member-session/v1".getBytes(StandardCharsets.US_ASCII),f.group,
            SessionPacket.header(SessionPacket.FIRST,id,0,0));
        try(var noise=new NoiseHandshake(true,sender.secret,Crypto.x25519Public(receiver.secret),f.psk,prologue);
            var handshake=new TimedHandshake(noise,true,Clock.fixed(when,ZoneOffset.UTC),new TimestampReplayGuard(),(cert,pub)->{})) {
            return new SessionPacket(SessionPacket.FIRST,id,0,0,handshake.writeMessage(sender.cert.encode())).encode();
        }
    }
    @Test void ignoredConcurrentFirstAndSecondDoNotCommitButAcceptedFirstRejectsEqualAndOlder() throws Exception {
        try(var a=node(1);var b=node(2)) {
            Node small=low(a,b),large=small==a ? b : a;
            f.connect(large,small); // small に受け入れた1通目の記録を残す。
            var before=timestamps(small);assertFalse(before.isEmpty());
            byte[] sf=small.sessions.start(large.id).packet(),lf=large.sessions.start(small.id).packet();
            assertTrue(small.sessions.receive(lf).outbound().isEmpty());assertEquals(before,timestamps(small));
            byte[] second=large.sessions.receive(sf).outbound().get(0).packet();
            large.sessions.receive(small.sessions.receive(second).outbound().get(0).packet());
            assertEquals(before,timestamps(small)); // 2通目の値も commit しない。
            var late=small.sessions.receive(lf).outbound();assertEquals(1,late.size());
            assertThrows(SecurityException.class,()->large.sessions.receive(late.get(0).packet()));
            assertNotEquals(before,timestamps(small)); // 成立後の1通目は、候補として受けたので確定する。
            finish(large,small,large.sessions.start(small.id));
            Instant accepted=(Instant)SessionManagerTest.field(large.sessions,"lastTimestamp");
            var after=timestamps(small);assertNotEquals(before,after);
            assertThrows(SecurityException.class,()->small.sessions.receive(firstAt(large,small,accepted,101)));
            assertThrows(SecurityException.class,()->small.sessions.receive(firstAt(large,small,accepted.minusNanos(1),102)));
            assertEquals(after,timestamps(small));
            assertEquals(1,small.sessions.receive(firstAt(large,small,accepted.plusNanos(1),103)).outbound().size());
        }
    }
    @Test void secondTimestampDoesNotRejectNewFirstButAcceptedEqualTimestampStillCannotBeReplayed() throws Exception {
        try(var a=node(1);var b=node(2)) {
            Node small=low(a,b),large=small==a ? b : a;f.connect(small,large);
            Instant boundary=(Instant)SessionManagerTest.field(large.sessions,"lastTimestamp");
            assertNotNull(boundary);
            assertEquals(1,small.sessions.receive(firstAt(large,small,boundary,110)).outbound().size());
            var candidate=f.secrets(small,large).subList(2,4);
            assertThrows(SecurityException.class,()->small.sessions.receive(firstAt(large,small,boundary,111)));
            assertFalse(Arrays.equals(candidate.get(0),new byte[32]));
            assertEquals(1,small.sessions.receive(firstAt(large,small,boundary.plusNanos(1),112)).outbound().size());
            f.wiped(candidate);
        }
    }
    @Test void forgedSecondDoesNotCommitReplayAndScheduledRecoveryWorksAfterOldKeyExpires() throws Exception {
        try(var a=node(1);var b=node(2)) {
            f.connect(a,b);var old=f.active(a,b);var recorded=timestamps(a);
            f.time.advance(120);byte[] first=a.sessions.poll().get(0).packet();byte[] reply=b.sessions.receive(first).outbound().get(0).packet();
            reply[reply.length-1]^=1;assertThrows(SecurityException.class,()->a.sessions.receive(reply));
            assertSame(old,f.active(a,b));assertEquals(recorded,timestamps(a));
            f.time.advance(61);assertFalse(a.sessions.isEstablished(b.id));assertFalse(b.sessions.isEstablished(a.id));
            var scheduled=a.sessions.poll();assertEquals(1,scheduled.size());finish(a,b,scheduled.get(0));
            assertArrayEquals(new byte[]{3},b.sessions.receive(f.data(a,b,3)).plaintext());
        }
    }
    @Test void firstReplayStateIsScopedToHandshakeKeyAndClearedOnForgetAndClose() throws Exception {
        try(var a=node(1);var b=node(2)) {
            f.connect(b,a);assertFalse(timestamps(a).isEmpty());
            f.time.advance(1);a.sessions.rememberPeer(b.certificate(key(60),f.time.millis()));
            assertTrue(timestamps(a).isEmpty());
        }
        try(var a=node(1);var b=node(2)) {
            f.connect(b,a);assertFalse(timestamps(a).isEmpty());
            a.state.acceptRevocations(AdminRecords.list(REVOCATIONS,f.group,1,f.time.millis(),List.of(b.id),f.admin));
            a.sessions.forgetRevokedPeer(b.id);assertTrue(timestamps(a).isEmpty());
        }
        try(var a=node(1);var b=node(2)) {
            f.connect(b,a);assertFalse(timestamps(a).isEmpty());a.sessions.close();assertTrue(timestamps(a).isEmpty());
        }
    }
    @Test void oversizePlaintextDoesNotStartHandshakeAndExactMaximumIsDelivered() {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);b.remember(a);
            assertThrows(IllegalArgumentException.class,()->a.sessions.sendWithStatus(b.id,new byte[1177]));
            assertFalse(a.sessions.isHandshaking(b.id));assertTrue(a.sessions.poll().isEmpty());
            finish(a,b,a.sessions.start(b.id));var result=a.sessions.sendWithStatus(b.id,new byte[1176]);
            assertTrue(result.plaintextSent());assertEquals(1232,result.outbound().get(0).packet().length);
            assertArrayEquals(new byte[1176],b.sessions.receive(result.outbound().get(0).packet()).plaintext());
        }
    }
    @Test void candidateSendDoesNotStartAnotherHandshakeOrRetainPlaintext() {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);b.remember(a);var reply=b.sessions.receive(a.sessions.start(b.id).packet()).outbound().get(0);
            var waiting=b.sessions.sendWithStatus(a.id,new byte[]{99});assertFalse(waiting.plaintextSent());assertTrue(waiting.outbound().isEmpty());
            var confirm=a.sessions.receive(reply.packet()).outbound().get(0);b.sessions.receive(confirm.packet());
            assertTrue(b.sessions.poll().isEmpty());assertArrayEquals(new byte[]{1},a.sessions.receive(f.data(b,a,1)).plaintext());
        }
    }
    @Test void discardedAuthenticatedFirstClosesTimedHandshakeWithoutCommittingReplayState() throws Exception {
        try(var a=node(1);var b=node(2)) {
            byte[] prologue={1};var guard=new TimestampReplayGuard();boolean[] verified={false};
            try(var ni=new NoiseHandshake(true,a.secret,Crypto.x25519Public(b.secret),f.psk,prologue);
                var nr=new NoiseHandshake(false,b.secret,null,f.psk,prologue);
                var initiator=new TimedHandshake(ni,true,f.time,new TimestampReplayGuard(),(cert,pub)->{});
                var responder=new TimedHandshake(nr,false,f.time,guard,(cert,pub)->{ b.state.verifyCertificate(AdminRecords.decode(cert),pub);verified[0]=true; })) {
                byte[] first=initiator.writeMessage(a.cert.encode());
                var result=responder.readMessage(first,r->{ assertTrue(verified[0]);return false; });
                assertArrayEquals(a.cert.encode(),result.certificate());
                assertTrue(((Map<?,?>)SessionManagerTest.field(guard,"newest")).isEmpty());
                assertThrows(IllegalStateException.class,()->responder.writeMessage(b.cert.encode()));
                assertThrows(IllegalStateException.class,()->responder.transport(()->0L));
                for(String name:List.of("s","e","psk","ck","k")) {
                    byte[] value=(byte[])SessionManagerTest.field(nr,name);if(value!=null) assertArrayEquals(new byte[value.length],value);
                }
                try(var validNoise=new NoiseHandshake(false,b.secret,null,f.psk,prologue);
                    var valid=new TimedHandshake(validNoise,false,f.time,guard,(cert,pub)->b.state.verifyCertificate(AdminRecords.decode(cert),pub))) {
                    valid.readMessage(first);assertFalse(((Map<?,?>)SessionManagerTest.field(guard,"newest")).isEmpty());
                    assertTrue(valid.writeMessage(b.cert.encode()).length>0);
                }
            }
        }
    }
    @Test void sameTimestampDifferentSignedPayloadIsRejectedEvenWhenBothAdministratorsAreTrusted() {
        try(var a=node(1);var b=node(2)) {
            a.remember(b);byte[] otherAdmin=key(70);
            a.state.acceptAdministrators(AdminProofFixtures.list(f.group,1,f.time.millis(),
                List.of(Crypto.ed25519Public(f.admin),Crypto.ed25519Public(otherAdmin)),f.admin,f.admin,otherAdmin),v->fail());
            byte[] hp=Crypto.x25519Public(b.secret);
            var different=AdminRecords.certificate(f.group,Crypto.ed25519Public(b.identity),hp,SignaturePurpose.identityProof(b.identity,f.group,hp),b.cert.issuedAt(),otherAdmin);
            a.state.verifyCertificate(different,hp); // 新旧の比較以外は通る対照。
            assertThrows(SecurityException.class,()->a.sessions.rememberPeer(different));
            a.sessions.rememberPeer(AdminRecords.decode(b.cert.encode())); // 同じpayloadは受ける。
            f.time.advance(1);
            var newer=AdminRecords.certificate(f.group,Crypto.ed25519Public(b.identity),hp,SignaturePurpose.identityProof(b.identity,f.group,hp),f.time.millis(),otherAdmin);
            a.sessions.rememberPeer(newer);
        }
    }
}
