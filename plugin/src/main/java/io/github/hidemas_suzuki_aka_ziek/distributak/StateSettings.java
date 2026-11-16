// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.io.IOException;
import java.nio.ByteBuffer;
/** 最後に確定したstateの値。stateが先に進んだときは、その値で直す。 */
final class StateSettings {
    static final class Rollback extends SecurityException {Rollback(){super("保存が古い状態に戻っています");}}
    static final int MAX_BYTES=157;
    private long keyVersion,generation;
    private byte[] announcement,commitment,managementDigest;
    final int port;
    final long saveSeq,administratorVersion,revocationVersion,issuedAt;
    StateSettings(int port,long seq,long admins,long revoked,long issued) {
        LanSupport.port(port,new java.security.SecureRandom());
        if(seq<0||admins<0||revoked<0||issued<0)throw new SecurityException("設定の値が違います");
        this.port=port;saveSeq=seq;administratorVersion=admins;revocationVersion=revoked;issuedAt=issued;
    }
    static StateSettings of(LanGroup group){
        var snapshot=group.management==null?group.state.snapshot():group.management.snapshot;
        var result=new StateSettings(group.port,group.saveSeq,snapshot.administratorVersion(),snapshot.revocationVersion(),group.certificate.issuedAt());
        if(group.management!=null){
            result.keyVersion=group.keyVersion;result.generation=group.managementGeneration;result.managementDigest=group.managementDigest.clone();
            byte[] value=snapshot.announcement();result.announcement=value==null?new byte[32]:io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto.blake2s(value);
            result.commitment=value==null?new byte[32]:io.github.hidemas_suzuki_aka_ziek.distributak.core.KeyAnnouncement.decode(value).keyCommitment();
        }return result;
    }
    byte[] encode(){
        var out=ByteBuffer.allocate(generation==0?45:MAX_BYTES).putInt(0x44544346).putInt(generation==0?2:3).putInt(port).put((byte)0)
                .putLong(saveSeq).putLong(administratorVersion).putLong(revocationVersion).putLong(issuedAt);
        if(generation!=0)out.putLong(keyVersion).put(announcement).put(commitment).putLong(generation).put(managementDigest);
        return out.array();
    }
    static StateSettings decode(byte[] bytes)throws IOException {
        if(bytes.length!=13&&bytes.length!=45&&bytes.length!=MAX_BYTES)throw new IOException("設定の長さが違います");
        var in=ByteBuffer.wrap(bytes);if(in.getInt()!=0x44544346)throw new IOException("設定の版が違います");
        int version=in.getInt(),port=in.getInt();
        if(in.get()!=0||version<1||version>3||bytes.length!=(version==1?13:version==2?45:MAX_BYTES))throw new IOException("設定の版か値が違います");
        var value=version==1?new StateSettings(port,0,0,0,0):new StateSettings(port,in.getLong(),in.getLong(),in.getLong(),in.getLong());
        if(version==3){value.keyVersion=in.getLong();value.announcement=new byte[32];in.get(value.announcement);value.commitment=new byte[32];in.get(value.commitment);
            value.generation=in.getLong();value.managementDigest=new byte[32];in.get(value.managementDigest);
            if(value.keyVersion<0||value.generation<=0)throw new IOException("設定の番号が違います");}
        return value;
    }
    void check(LanGroup group) {
        if(generation!=0&&group.saveSeq==saveSeq&&!java.util.Arrays.equals(encode(),of(group).encode()))throw new Rollback();
        if(group.saveSeq<saveSeq || group.saveSeq==saveSeq && (group.state.administrators().version()<administratorVersion
                ||group.state.revocations().version()<revocationVersion||group.certificate.issuedAt()<issuedAt))
            throw new Rollback();
    }
}
