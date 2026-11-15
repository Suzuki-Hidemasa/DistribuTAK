// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
import java.io.*;
import com.google.protobuf.CodedOutputStream;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AdminBindingBoundaryTest {
    static final byte[] group=AdminRecordsTest.key(33),signer=AdminRecordsTest.key(1),identity=AdminRecordsTest.key(2);
    static AdminBinding own() {
        var proof=AdminControl.keyProof(group,new byte[16],0,identity,signer);
        return AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode());
    }
    static byte[] signed(List<AdminBinding> bindings,boolean corruptSignature)throws IOException {
        bindings=new ArrayList<>(bindings);bindings.sort((a,b)->AdminRecords.compareBytes(a.administratorKey(),b.administratorKey()));
        var buffer=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(buffer);
        out.writeUInt32(1,2);out.writeByteArray(2,group);out.writeByteArray(3,Crypto.ed25519Public(signer));out.writeUInt64(4,0);out.writeUInt64(5,1000);
        for(var binding:bindings)out.writeByteArray(6,binding.administratorKey());for(var binding:bindings)out.writeByteArray(7,binding.encode());
        out.writeUInt32(15,2);out.writeByteArray(16,SignaturePurpose.ADMINISTRATORS.purpose());out.flush();byte[] payload=buffer.toByteArray();
        byte[] signature=SignaturePurpose.ADMINISTRATORS.sign(signer,payload);if(corruptSignature)signature[0]^=1;
        buffer.reset();out=CodedOutputStream.newInstance(buffer);out.writeByteArray(1,payload);out.writeByteArray(2,signature);out.flush();return buffer.toByteArray();
    }
    static byte[] large(int unknown)throws IOException {
        var bindings=new ArrayList<AdminBinding>();bindings.add(own());
        for(int n=0;n<unknown;n++){byte[] key=new byte[32];for(int b=0;b<4;b++)key[31-b]=(byte)(n>>>(8*b));bindings.add(AdminBinding.unknown(key));}
        return signed(bindings,false);
    }
    static final class Boundary {
        final byte[] lower,upper;final int count;
        Boundary()throws IOException {
            int n=(AdminRecords.MAX_RECORD_BYTES-1024)/72;byte[] previous=large(n),next=large(n+1);
            while(next.length<=AdminRecords.MAX_RECORD_BYTES){previous=next;n++;next=large(n+1);}
            lower=previous;upper=next;count=n+1;
        }
    }
    static final class Fixture {static final Boundary boundary=make();static Boundary make(){try{return new Boundary();}catch(IOException e){throw new ExceptionInInitializerError(e);}}}
    JoinMessages.Response response(byte[] record) {
        byte[] handshake=Crypto.x25519Public(AdminRecordsTest.key(3));
        var certificate=AdminRecords.certificate(group,Crypto.ed25519Public(identity),handshake,SignaturePurpose.identityProof(identity,group,handshake),1000,signer);
        byte[] wrapped=GroupKeyEnvelope.wrap(group,Crypto.blake2s(certificate.field(0)),handshake,0,1000,new byte[32],signer).encode();
        return new JoinMessages.Response(group,List.of(record),new byte[64],AdminRecords.initialRevocations(group,1000,signer).encode(),certificate.encode(),wrapped);
    }
    @Test void fieldSevenListImmediatelyBelowThreeMiBIsDecodedAndAcceptedInJoinResponse() {
        var boundary=Fixture.boundary;assertTrue(boundary.count<AdminRecords.MAX_ENTRIES);
        assertTrue(boundary.lower.length<=AdminRecords.MAX_RECORD_BYTES);assertTrue(AdminRecords.MAX_RECORD_BYTES-boundary.lower.length<72);
        var record=AdminRecords.decode(boundary.lower);assertTrue(record.hasAdminBindings());assertTrue(record.hasValidSignature());assertEquals(boundary.count,record.bindings().size());
        var state=new AdminState(group,Crypto.ed25519Public(signer),java.time.Clock.fixed(java.time.Instant.ofEpochMilli(1000),java.time.ZoneOffset.UTC),new InMemoryAdminRecordStore());
        state.bootstrap(record,AdminRecords.signAnchor(record,signer));assertEquals(boundary.count,state.administrators().bindings().size());
        var decoded=JoinMessages.response(response(boundary.lower).encode());assertTrue(Arrays.equals(boundary.lower,decoded.chain.get(0)));
    }
    @Test void fieldSevenListImmediatelyAboveThreeMiBIsRejectedByRecordAndJoinResponse() {
        var boundary=Fixture.boundary;assertTrue(boundary.upper.length>AdminRecords.MAX_RECORD_BYTES);assertTrue(boundary.upper.length-AdminRecords.MAX_RECORD_BYTES<=72);
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(boundary.upper));assertThrows(IllegalArgumentException.class,()->response(boundary.upper));
    }
    @Test void listSignatureIsCheckedBeforePossessionProof()throws Exception {
        var binding=own();byte[] invalid=binding.possessionProof();invalid[invalid.length-1]^=1;
        var bad=AdminBinding.bound(binding.administratorKey(),binding.memberId(),invalid);
        byte[] both=signed(List.of(bad),true),proofOnly=signed(List.of(bad),false);
        assertThrows(SecurityException.class,()->AdminRecords.decode(both));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(proofOnly));
    }
}
