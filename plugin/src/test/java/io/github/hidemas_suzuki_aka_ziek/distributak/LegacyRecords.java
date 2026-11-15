// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.io.ByteArrayOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
/** 版5の試料専用。製品には形式1の生成口を残さない。 */
final class LegacyRecords {
    private static final class Writer {
        final ByteArrayOutputStream out;
        Writer(ByteArrayOutputStream out){this.out=out;}
        void number(long value){while((value&~127L)!=0){out.write(((int)value&127)|128);value>>>=7;}out.write((int)value);}
        void writeUInt64(int field,long value){number(field<<3);number(value);}
        void writeUInt32(int field,int value){writeUInt64(field,value);}
        void writeByteArray(int field,byte[] value){number(field<<3|2);number(value.length);out.writeBytes(value);}
        void flush(){}
    }
    static AdminRecords.Record record(AdminRecords.Record original,byte[] identitySecret,byte[] administratorSecret)throws Exception {
        var bytes=new ByteArrayOutputStream();var out=new Writer(bytes);
        out.writeUInt32(1,original.kind().ordinal()+1);out.writeByteArray(2,original.group());out.writeByteArray(3,original.signer());
        out.writeUInt64(4,original.version());out.writeUInt64(5,original.signedAt());
        if(original.kind()==AdminRecords.Kind.CERTIFICATE) {
            out.writeByteArray(6,original.field(0));out.writeByteArray(7,original.field(1));out.writeByteArray(8,Crypto.sign(identitySecret,original.field(1)));
            out.writeUInt64(9,original.issuedAt());out.writeUInt64(10,original.expiresAt());
        }else for(byte[] entry:original.entries())out.writeByteArray(6,entry);
        out.flush();byte[] payload=bytes.toByteArray();bytes.reset();out=new Writer(bytes);
        out.writeByteArray(1,payload);out.writeByteArray(2,Crypto.sign(administratorSecret,payload));out.flush();return AdminRecords.decode(bytes.toByteArray());
    }
    static void install(LanGroup group,AdminRecords.Record certificate,AdminRecords.Record peer,byte[] admin,java.time.Clock clock)throws Exception {
        var first=record(group.state.administrators(),null,admin);var revoked=record(group.state.revocations(),null,admin);
        group.state=new AdminState(group.groupId,group.urlAdmin,clock,new InMemoryAdminRecordStore());
        group.state.join(java.util.List.of(first),AdminRecords.signAnchor(first,admin),revoked);
        group.certificate=certificate;group.peerCertificate=peer;
        group.state.trustStoredLegacyCertificate(certificate);group.state.trustStoredLegacyCertificate(peer);
    }
}
