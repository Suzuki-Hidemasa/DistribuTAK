// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class AdministratorFirstValidationTest {
    static final class Rig implements AutoCloseable {
        final UdpEndpointTest f=new UdpEndpointTest();
        final UdpEndpointTest.Node administrator,member;
        final boolean retained;
        final AdminRecords.Record expired;
        Rig(boolean retained)throws Exception {
            this.retained=retained;
            administrator=f.new Node(1,"127.0.0.1");member=f.new Node(2,"127.0.0.1");
            expired=certificate(administrator.secret,f.clock.millis()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS+1,f.admin);
            expect(expired);f.wallMillis.incrementAndGet();member.sessions.refresh();
            assertEquals(f.clock.millis(),expired.expiresAt());
            assertEquals(retained,member.sessions.hasPeer(administrator.id));
            assertEquals(UdpEndpoint.CloseReason.RUNNING,member.state.localCertificateReason(member.cert,member.cert.field(1)));
            member.endpoint.allowDiscoveredReplies(source->false);
        }
        AdminRecords.Record certificate(byte[] handshake,long issued,byte[] signer){
            byte[] pub=Crypto.x25519Public(handshake);
            return AdminRecords.certificate(f.group,administrator.cert.field(0),pub,
                    SignaturePurpose.identityProof(key(1),f.group,pub),issued,signer);
        }
        AdminRecords.Record fresh(){return certificate(administrator.secret,f.clock.millis(),f.admin);}
        void expect(AdminRecords.Record certificate){
            member.endpoint.expectPeerCertificate(certificate);
            if(retained)member.sessions.rememberPeer(certificate);
        }
        byte[] first(byte[] certificate,byte[] secret)throws Exception {
            byte[] id=new byte[16];new java.security.SecureRandom().nextBytes(id);
            byte[] prologue=Crypto.concat("DistribuTAK/member-session/v1".getBytes(StandardCharsets.US_ASCII),f.group,
                    SessionPacket.header(SessionPacket.FIRST,id,0,0));
            try(var noise=new NoiseHandshake(true,secret,member.cert.field(1),f.psk,prologue);
                var handshake=new TimedHandshake(noise,true,f.clock,new TimestampReplayGuard(),(cert,pub)->{})){
                return new SessionPacket(SessionPacket.FIRST,id,0,0,handshake.writeMessage(certificate)).encode();
            }
        }
        SessionManager.Received receive(byte[] certificate,byte[] secret)throws Exception {
            var check=UdpEndpoint.class.getDeclaredMethod("checkFirstPeer",AdminRecords.Record.class,java.net.InetSocketAddress.class);
            check.setAccessible(true);
            // ソケットの待ちを挟まず、製品の証明書検査と FIRST の受入判定をそのまま通す。
            // Run production certificate validation and FIRST admission without waiting on a socket.
            return member.sessions.receive(first(certificate,secret),cert->{
                try{check.invoke(member.endpoint,cert,administrator.address());}
                catch(InvocationTargetException e){throw (RuntimeException)e.getCause();}
                catch(ReflectiveOperationException e){throw new AssertionError(e);}
            });
        }
        void rejected(byte[] certificate,byte[] secret,String reason)throws Exception {
            var peers=(Map<?,?>)SessionManagerTest.field(member.sessions,"peers");
            var previous=Map.copyOf(peers);
            Object slot=previous.isEmpty()?null:previous.values().iterator().next();
            Object previousCertificate=slot==null?null:SessionManagerTest.field(slot,"certificate");
            var replay=SessionManagerTest.field(member.sessions,"replay");
            var timestamps=Map.copyOf((Map<?,?>)SessionManagerTest.field(replay,"newest"));
            var failure=assertThrows(RuntimeException.class,()->receive(certificate,secret));
            assertTrue(causes(failure).contains(reason),()->"Unexpected rejection category: "+failure.getClass().getSimpleName());
            assertEquals(previous,peers);
            if(slot!=null)assertSame(previousCertificate,SessionManagerTest.field(slot,"certificate"));
            assertFalse(member.sessions.isEstablished(administrator.id));
            assertEquals(timestamps,SessionManagerTest.field(replay,"newest"));
            assertTrue(((Map<?,?>)SessionManagerTest.field(member.sessions,"routes")).isEmpty());
        }
        public void close(){member.close();administrator.close();}
    }
    static String causes(Throwable error){
        var text=new StringBuilder();for(Throwable e=error;e!=null;e=e.getCause())text.append(e.getMessage()).append('\n');return text.toString();
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void validNewFirstReplacesOnlyExpiredAdministrator(boolean retained)throws Exception {
        try(var r=new Rig(retained);var received=r.receive(r.fresh().encode(),r.administrator.secret)){
            assertEquals(1,received.outbound().size());
            assertArrayEquals(r.fresh().encode(),r.member.sessions.peerCertificate(r.administrator.id).encode());
            assertFalse(r.member.sessions.isUnregistered(r.administrator.id));
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void olderIssueIsRejectedBeforeAdoption(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            r.expect(r.certificate(r.administrator.secret,r.f.clock.millis()+2,r.f.admin));
            var older=r.certificate(r.administrator.secret,r.f.clock.millis()+1,r.f.admin);
            assertEquals(UdpEndpoint.CloseReason.RUNNING,r.member.state.localCertificateReason(older,older.field(1)));
            r.rejected(older.encode(),r.administrator.secret,retained?"証明書が古い":"保存した相手の身元か発行順");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void differentContentAtSameIssueIsRejectedBeforeAdoption(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            r.expect(r.fresh());var different=r.certificate(key(77),r.f.clock.millis(),r.f.admin);
            assertEquals(UdpEndpoint.CloseReason.RUNNING,r.member.state.localCertificateReason(different,different.field(1)));
            r.rejected(different.encode(),key(77),retained?"同じ発行時刻の内容":"保存した相手の身元か発行順");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void differentIdentityCannotReplaceTheAdministratorSlot(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            byte[] pub=r.administrator.cert.field(1);
            var foreign=AdminRecords.certificate(r.f.group,Crypto.ed25519Public(key(78)),pub,
                    SignaturePurpose.identityProof(key(78),r.f.group,pub),r.f.clock.millis(),r.f.admin);
            assertEquals(UdpEndpoint.CloseReason.RUNNING,r.member.state.localCertificateReason(foreign,pub));
            r.rejected(foreign.encode(),r.administrator.secret,"登録のない相手の送り元");
            assertFalse(r.member.sessions.hasPeer(Crypto.blake2s(foreign.field(0))));
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void invalidCertificateSignatureIsRejected(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            byte[] wire=r.fresh().encode();wire[wire.length-1]^=1;var bad=AdminRecords.decode(wire);
            assertTrue(bad.verifyIdentityBinding());assertTrue(r.member.state.administrators().hasEntry(bad.signer()));
            assertFalse(bad.hasValidSignature());
            var reason=assertThrows(SecurityException.class,()->r.member.state.storedCertificateStatus(bad,bad.field(1)));
            assertTrue(reason.getMessage().contains("管理記録の署名"));
            r.rejected(wire,r.administrator.secret,"証明書を受け入れられません");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void invalidIdentityBindingSignatureIsRejected(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            byte[] proof=r.fresh().field(2);proof[0]^=1;
            var bad=AdminRecords.certificate(r.f.group,r.administrator.cert.field(0),r.administrator.cert.field(1),proof,r.f.clock.millis(),r.f.admin);
            assertTrue(bad.hasValidSignature());assertTrue(r.member.state.administrators().hasEntry(bad.signer()));assertFalse(bad.verifyIdentityBinding());
            var reason=assertThrows(SecurityException.class,()->r.member.state.storedCertificateStatus(bad,bad.field(1)));
            assertTrue(reason.getMessage().contains("身元の鍵の署名"));
            r.rejected(bad.encode(),r.administrator.secret,"証明書を受け入れられません");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void signerOutsideAdministratorListIsRejected(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            var bad=r.certificate(r.administrator.secret,r.f.clock.millis(),key(79));
            assertTrue(bad.hasValidSignature());assertTrue(bad.verifyIdentityBinding());assertFalse(r.member.state.administrators().hasEntry(bad.signer()));
            var reason=assertThrows(SecurityException.class,()->r.member.state.storedCertificateStatus(bad,bad.field(1)));
            assertTrue(reason.getMessage().contains("署名者が今の管理者"));
            r.rejected(bad.encode(),r.administrator.secret,"証明書を受け入れられません");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void revokedIdentityIsRejectedEvenWithAuthorizedSigner(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            var fresh=r.fresh();assertTrue(r.member.state.administrators().hasEntry(fresh.signer()));
            r.member.state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,r.f.group,1,r.f.clock.millis(),List.of(r.administrator.id),r.f.admin));
            assertEquals(AdminState.StoredCertificateStatus.REVOKED,r.member.state.storedCertificateStatus(fresh,fresh.field(1)));
            r.rejected(fresh.encode(),r.administrator.secret,"証明書を受け入れられません");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void certificateAtExpiryIsRejected(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            assertEquals(AdminState.StoredCertificateStatus.EXPIRED,r.member.state.storedCertificateStatus(r.expired,r.expired.field(1)));
            r.rejected(r.expired.encode(),r.administrator.secret,"証明書を受け入れられません");
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void certificateOneMillisecondBeforeExpiryIsAccepted(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            var last=r.certificate(r.administrator.secret,r.expired.issuedAt()+1,r.f.admin);
            assertEquals(r.f.clock.millis()+1,last.expiresAt());
            assertEquals(AdminState.StoredCertificateStatus.VALID,r.member.state.storedCertificateStatus(last,last.field(1)));
            try(var received=r.receive(last.encode(),r.administrator.secret)){assertEquals(1,received.outbound().size());}
            assertArrayEquals(last.encode(),r.member.sessions.peerCertificate(r.administrator.id).encode());
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void issueBeyondFiveMinutesIsRejectedAsClockFailure(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            var future=r.certificate(r.administrator.secret,r.f.clock.millis()+300_001,r.f.admin);
            assertEquals(AdminState.StoredCertificateStatus.CLOCK_FAILURE,r.member.state.storedCertificateStatus(future,future.field(1)));
            r.rejected(future.encode(),r.administrator.secret,"証明書を受け入れられません");
        }
    }
    @Test void negativeReceiverClockStopsBeforeAcceptingFirst()throws Exception {
        var f=new SessionManagerTest();
        try(var a=f.new Node(1);var b=f.new Node(2)){
            a.remember(b);b.remember(a);byte[] first=a.sessions.start(b.id).packet();f.time.millis=-1;
            assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,b.state.localCertificateReason(a.cert,a.cert.field(1)));
            assertThrows(IllegalStateException.class,()->b.sessions.receive(first));
            assertEquals(UdpEndpoint.CloseReason.CLOCK_FAILURE,b.sessions.closeReason());
            assertTrue(((Map<?,?>)SessionManagerTest.field(b.sessions,"peers")).isEmpty());
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void signedNegativeIssueTimeIsRejectedAsMalformed(boolean retained)throws Exception {
        try(var r=new Rig(retained)){
            var cert=r.fresh();var payloadBytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(payloadBytes);
            out.writeUInt64(1,1);out.writeByteArray(2,r.f.group);out.writeByteArray(3,cert.signer());out.writeUInt64(4,0);out.writeUInt64(5,-1);
            for(int i=0;i<3;i++)out.writeByteArray(6+i,cert.field(i));
            out.writeUInt64(9,-1);out.writeUInt64(10,AdminRecords.CERTIFICATE_LIFETIME_MILLIS-1);
            out.writeUInt64(15,2);out.writeByteArray(16,SignaturePurpose.CERTIFICATE.purpose());out.writeUInt64(17,2);out.flush();
            byte[] payload=payloadBytes.toByteArray(),signature=SignaturePurpose.CERTIFICATE.sign(r.f.admin,payload);
            assertTrue(SignaturePurpose.CERTIFICATE.verify(cert.signer(),payload,signature));
            var envelope=new ByteArrayOutputStream();var encoded=CodedOutputStream.newInstance(envelope);
            encoded.writeByteArray(1,payload);encoded.writeByteArray(2,signature);encoded.flush();byte[] wire=envelope.toByteArray();
            var malformed=assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(wire));
            r.rejected(wire,r.administrator.secret,malformed.getMessage());
        }
    }
}
