// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.List;
import java.io.ByteArrayOutputStream;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.AdminRecordSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AdminRecordsTest {
    static byte[] key(int value) { byte[] b=new byte[32];b[0]=(byte)value;b[1]=(byte)value;return b; }
    final byte[] group=key(1), admin=key(2), other=key(3);
    @Test void signsExactBytesAndSeparatesGroupAndKind() {
        var record=AdminRecords.list(AdminRecords.Kind.ADMINS,group,0,100,List.of(Crypto.ed25519Public(admin)),admin);
        var copy=AdminRecords.decode(record.encode());
        assertArrayEquals(record.signedBytes(),copy.signedBytes());
        copy.verify(AdminRecords.Kind.ADMINS,group,List.of(Crypto.ed25519Public(admin)));
        assertThrows(SecurityException.class,()->copy.verify(AdminRecords.Kind.REVOCATIONS,group,List.of(Crypto.ed25519Public(admin))));
        assertThrows(SecurityException.class,()->copy.verify(AdminRecords.Kind.ADMINS,other,List.of(Crypto.ed25519Public(admin))));
        assertThrows(SecurityException.class,()->copy.verify(AdminRecords.Kind.ADMINS,group,List.of(Crypto.ed25519Public(other))));
    }
    @Test void rejectsUnknownDuplicateAndNoncanonicalFields() {
        var r=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,1,100,List.of(key(7)),admin);
        byte[] raw=r.encode();
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(Crypto.concat(raw,new byte[]{24,1})));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(Crypto.concat(raw,new byte[]{18,0})));
        // 正しい外側のタグ0x0aだけを、長い表現0x8a 0x00に替える。
        byte[] overlong=Crypto.concat(new byte[]{(byte)0x8a,0},java.util.Arrays.copyOfRange(raw,1,raw.length));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(overlong));
    }
    @Test void listOrderIsCanonicalAndDoesNotAliasCaller() {
        var r=AdminRecords.list(AdminRecords.Kind.ADMINS,group,0,100,List.of(key(255),key(128)),admin);
        assertArrayEquals(key(128),r.entries().get(0));
        r.entries().get(0)[0]=0;
        assertArrayEquals(key(128),r.entries().get(0));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.list(AdminRecords.Kind.ADMINS,group,0,100,List.of(key(7),key(7)),admin));
    }
    @Test void unsignedLexicographicOrderIncludesPrefixLength() {
        assertTrue(AdminRecords.compareBytes(new byte[]{(byte)128},new byte[]{127})>0);
        assertTrue(AdminRecords.compareBytes(new byte[]{1,0},new byte[]{1})>0);
        assertEquals(0,AdminRecords.compareBytes(new byte[]{1},new byte[]{1}));
    }
    static byte[] envelope(byte[] payload, byte[] signature) throws Exception {
        var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);
        out.writeByteArray(1,payload);out.writeByteArray(2,signature);out.flush();return bytes.toByteArray();
    }
    @Test void rejectsUnknownDuplicateUnsortedAndOverlongPayloadFieldsEvenWithValidSignature() throws Exception {
        var r=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,0,100,List.of(),admin);
        byte[] original=r.signedBytes();
        for(byte[] payload:new byte[][]{
            Crypto.concat(original,new byte[]{56,1}), // 知らない項目7。
            Crypto.concat(original,new byte[]{40,100}), // 時刻の重複。
            Crypto.concat(new byte[]{8,(byte)0x83,0},java.util.Arrays.copyOfRange(original,2,original.length)), // 種類の非最短整数。
            Crypto.concat(java.util.Arrays.copyOfRange(original,2,original.length),new byte[]{8,3}) // 番号の順が逆。
        }) {
            byte[] wire=envelope(payload,Crypto.sign(admin,payload));
            assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(wire));
        }
        var message=AdminRecordSchema.RevocationList.newBuilder().setKind(3).setGroupId(ByteString.copyFrom(group))
            .setSigner(ByteString.copyFrom(Crypto.ed25519Public(admin))).setVersion(1).setSignedAt(100)
            .addMemberIds(ByteString.copyFrom(key(128))).addMemberIds(ByteString.copyFrom(key(127))).build();
        byte[] payload=message.toByteArray();
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(envelope(payload,Crypto.sign(admin,payload))));
    }
    @Test void replacingSignedGroupKindRecipientOrVersionCannotReuseSignature() throws Exception {
        var r=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group,1,100,List.of(),admin);
        var parsed=AdminRecordSchema.RevocationList.parseFrom(r.signedBytes());
        for(var altered:List.of(parsed.toBuilder().setGroupId(ByteString.copyFrom(other)).build(),
                                parsed.toBuilder().setKind(2).addMemberIds(ByteString.copyFrom(other)).build())) {
            if(altered.getKind()!=3)assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(envelope(altered.toByteArray(),r.signature())));
            else {
                var received=AdminRecords.decode(envelope(altered.toByteArray(),r.signature()));
                assertThrows(SecurityException.class,()->received.verify(received.kind(),received.group(),List.of(Crypto.ed25519Public(admin))));
            }
        }
        var wrapped=GroupKeyEnvelope.wrap(group,key(4),Crypto.x25519Public(key(5)),1,100,key(6),admin);
        var body=AdminRecordSchema.WrappedGroupKey.parseFrom(wrapped.signedBytes());
        for(var altered:List.of(body.toBuilder().setRecipientId(ByteString.copyFrom(other)).build(),body.toBuilder().setVersion(2).build())) {
            var received=AdminRecords.decode(envelope(altered.toByteArray(),wrapped.signature()));
            assertThrows(SecurityException.class,()->received.verify(AdminRecords.Kind.WRAPPED_KEY,group,List.of(Crypto.ed25519Public(admin))));
        }
    }
    @Test void protoSchemaMatchesManualWriterForAllPublicFields() throws Exception {
        var r=AdminRecords.list(AdminRecords.Kind.ADMINS,group,1,100,List.of(Crypto.ed25519Public(admin)),admin);
        var e=AdminRecordSchema.SignedRecord.parseFrom(r.encode());var p=AdminRecordSchema.AdministratorList.parseFrom(e.getPayload());
        assertEquals(2,p.getKind());assertEquals(1,p.getVersion());assertEquals(100,p.getSignedAt());
        assertArrayEquals(group,p.getGroupId().toByteArray());assertArrayEquals(r.signature(),e.getSignature().toByteArray());
    }
}
