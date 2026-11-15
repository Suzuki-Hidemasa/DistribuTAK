// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AdminFormatTest {
    final byte[] group=new byte[32],secret=new byte[32],identity=new byte[32],handshake=Crypto.x25519Public(new byte[32]);
    @Test void certificateUsesStrictV2AndBothDomains() {
        byte[] proof=SignaturePurpose.identityProof(identity,group,handshake);
        var record=AdminRecords.certificate(group,Crypto.ed25519Public(identity),handshake,proof,100,secret);
        assertEquals(2,record.format());assertEquals(2,record.identityProofFormat());
        assertTrue(record.verifyIdentityBinding());assertTrue(record.hasValidSignature());
        assertTrue(SignaturePurpose.CERTIFICATE.verify(record.signer(),record.signedBytes(),record.signature()));
        assertFalse(Crypto.verify(record.signer(),record.signedBytes(),record.signature()));
        assertEquals(2,AdminRecords.decode(record.encode()).format());
    }
    @Test void bothListsUseTheirExpectedDomain() {
        for(var kind:List.of(AdminRecords.Kind.ADMINS,AdminRecords.Kind.REVOCATIONS)) {
            var record=AdminRecords.list(kind,group,0,100,List.of(Crypto.ed25519Public(secret)),secret);
            assertEquals(2,record.format());assertTrue(record.hasValidSignature());
            assertFalse(Crypto.verify(record.signer(),record.signedBytes(),record.signature()));
            AdminRecords.decode(record.encode()).verify(kind,group,List.of(record.signer()));
        }
    }
    static AdminRecords.Record legacy(AdminRecords.Record original,byte[] identity,byte[] signer)throws Exception {
        var bytes=new java.io.ByteArrayOutputStream();var out=com.google.protobuf.CodedOutputStream.newInstance(bytes);
        out.writeUInt32(1,original.kind().ordinal()+1);out.writeByteArray(2,original.group());out.writeByteArray(3,original.signer());
        out.writeUInt64(4,original.version());out.writeUInt64(5,original.signedAt());
        if(original.kind()==AdminRecords.Kind.CERTIFICATE){
            out.writeByteArray(6,original.field(0));out.writeByteArray(7,original.field(1));out.writeByteArray(8,Crypto.sign(identity,original.field(1)));
            out.writeUInt64(9,original.issuedAt());out.writeUInt64(10,original.expiresAt());
        }else for(byte[] entry:original.entries())out.writeByteArray(6,entry);
        out.flush();return signed(bytes.toByteArray(),signer,false);
    }
    static AdminRecords.Record signed(byte[] payload,byte[] signer,boolean domain)throws Exception {
        var bytes=new java.io.ByteArrayOutputStream();var out=com.google.protobuf.CodedOutputStream.newInstance(bytes);
        out.writeByteArray(1,payload);out.writeByteArray(2,domain?SignaturePurpose.CERTIFICATE.sign(signer,payload):Crypto.sign(signer,payload));
        out.flush();return AdminRecords.decode(bytes.toByteArray());
    }
    AdminRecords.Record certificate(long issued){return AdminRecords.certificate(group,Crypto.ed25519Public(identity),handshake,
            SignaturePurpose.identityProof(identity,group,handshake),issued,secret);}
    AdminState state(long now){
        var state=new AdminState(group,Crypto.ed25519Public(secret),java.time.Clock.fixed(java.time.Instant.ofEpochMilli(now),java.time.ZoneOffset.UTC),new InMemoryAdminRecordStore());
        var first=AdminRecords.list(AdminRecords.Kind.ADMINS,group,0,100,List.of(Crypto.ed25519Public(secret)),secret);
        state.bootstrap(first,AdminRecords.signAnchor(first,secret));
        state.acceptRevocations(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,0,100,List.of(),secret));return state;
    }
    @Test void legacyCertificateRequiresExactStoredBytesAndCanBeUnpinned()throws Exception {
        var state=state(1000);var old=legacy(certificate(100),identity,secret);var other=legacy(certificate(101),identity,secret);
        assertThrows(SecurityException.class,()->state.verifyCertificate(old,handshake));
        state.trustStoredLegacyCertificate(old);state.verifyCertificate(old,handshake);
        assertThrows(SecurityException.class,()->state.verifyCertificate(other,handshake));
        state.forgetLegacyCertificate(old.field(0));assertThrows(SecurityException.class,()->state.verifyCertificate(old,handshake));
    }
    @Test void v2NeverFallsBackToRawSignature()throws Exception {
        var malformed=signed(certificate(100).signedBytes(),secret,false);assertEquals(2,malformed.format());
        assertFalse(malformed.hasValidSignature());assertThrows(SecurityException.class,()->state(1000).verifyCertificate(malformed,handshake));
    }
    @Test void unknownFormatAndWrongPurposeAreRejectedBeforeVerification()throws Exception {
        byte[] payload=certificate(100).signedBytes();
        // builderの既定値省略より前に、明示項目の形式番号だけを書き換える。
        int marker=-1;for(int i=0;i<payload.length-1;i++)if(payload[i]==120&&payload[i+1]==2)marker=i;
        assertTrue(marker>=0);payload[marker+1]=3;byte[] unknown=payload;
        assertThrows(IllegalArgumentException.class,()->signed(unknown,secret,true));
        payload=certificate(100).signedBytes();payload[marker+4]^=1;byte[] purpose=payload;
        assertThrows(IllegalArgumentException.class,()->signed(purpose,secret,true));
    }
    @Test void newLegacyListsAreRefusedButExactTrustedListsAreNoChange()throws Exception {
        var state=state(1000);var fresh=AdminRecords.list(AdminRecords.Kind.ADMINS,group,1,101,List.of(Crypto.ed25519Public(secret)),secret);
        assertThrows(SecurityException.class,()->state.acceptAdministrators(legacy(fresh,null,secret),v->{}));
        var revoked=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,1,101,List.of(),secret);
        assertThrows(SecurityException.class,()->state.acceptRevocations(legacy(revoked,null,secret)));
        var first=legacy(AdminRecords.list(AdminRecords.Kind.ADMINS,group,0,100,List.of(Crypto.ed25519Public(secret)),secret),null,secret);
        var oldRevoked=legacy(AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,0,100,List.of(),secret),null,secret);
        var joined=new AdminState(group,Crypto.ed25519Public(secret),java.time.Clock.systemUTC(),new InMemoryAdminRecordStore());
        joined.join(List.of(first),AdminRecords.signAnchor(first,secret),oldRevoked);
        assertFalse(joined.acceptAdministrators(first,v->{}));assertFalse(joined.acceptRevocations(oldRevoked));
        var snapshot=joined.snapshot();var store=new InMemoryAdminRecordStore();store.save(snapshot);
        var restored=new AdminState(group,Crypto.ed25519Public(secret),java.time.Clock.systemUTC(),store);restored.restore();
        assertEquals(1,restored.administrators().format());assertEquals(1,restored.revocations().format());
    }
    @Test void invitationHistoryCannotReturnToLegacyAfterV2()throws Exception {
        var first=AdminRecords.list(AdminRecords.Kind.ADMINS,group,0,100,List.of(Crypto.ed25519Public(secret)),secret);
        var next=legacy(AdminRecords.list(AdminRecords.Kind.ADMINS,group,1,101,List.of(Crypto.ed25519Public(secret)),secret),null,secret);
        var revoked=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,0,100,List.of(),secret);
        var joined=new AdminState(group,Crypto.ed25519Public(secret),java.time.Clock.systemUTC(),new InMemoryAdminRecordStore());
        assertThrows(SecurityException.class,()->joined.join(List.of(first,next),AdminRecords.signAnchor(first,secret),revoked));
    }
    @Test void renewalCannotCopyRawProofAndChecksReasonAndOperation()throws Exception {
        var base=certificate(100);var state=state(100+20L*86_400_000);
        assertThrows(SecurityException.class,()->state.issueCertificateRenewal(base,Crypto.sign(identity,handshake),secret,RenewalMessage.Reason.AUTO_RENEWAL,null));
        assertThrows(SecurityException.class,()->state.issueCertificateRenewal(base,base.field(2),secret,RenewalMessage.Reason.AUTO_RENEWAL,new byte[16]));
        assertThrows(IllegalArgumentException.class,()->state.issueCertificateRenewal(base,base.field(2),secret,RenewalMessage.Reason.ADMIN_REMOVAL_PREPARE,null));
        assertEquals(2,state.issueCertificateRenewal(base,base.field(2),secret,RenewalMessage.Reason.AUTO_RENEWAL,null).format());
    }
}
