// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.io.IOException;
import java.nio.ByteBuffer;
/** 最後に確定したstateの値。stateが先に進んだときは、その値で直す。 */
final class StateSettings {
    static final class Rollback extends SecurityException {Rollback(){super("保存が古い状態に戻っています");}}
    static final int MAX_BYTES=45;
    final int port;
    final long saveSeq,administratorVersion,revocationVersion,issuedAt;
    StateSettings(int port,long seq,long admins,long revoked,long issued) {
        LanSupport.port(port,new java.security.SecureRandom());
        if(seq<0||admins<0||revoked<0||issued<0)throw new SecurityException("設定の値が違います");
        this.port=port;saveSeq=seq;administratorVersion=admins;revocationVersion=revoked;issuedAt=issued;
    }
    static StateSettings of(LanGroup group){return new StateSettings(group.port,group.saveSeq,group.state.administrators().version(),group.state.revocations().version(),group.certificate.issuedAt());}
    byte[] encode(){return ByteBuffer.allocate(MAX_BYTES).putInt(0x44544346).putInt(2).putInt(port).put((byte)0)
            .putLong(saveSeq).putLong(administratorVersion).putLong(revocationVersion).putLong(issuedAt).array();}
    static StateSettings decode(byte[] bytes)throws IOException {
        if(bytes.length!=13&&bytes.length!=MAX_BYTES)throw new IOException("設定の長さが違います");
        var in=ByteBuffer.wrap(bytes);if(in.getInt()!=0x44544346)throw new IOException("設定の版が違います");
        int version=in.getInt(),port=in.getInt();
        if(in.get()!=0||version!=1&&version!=2||version==1&&bytes.length!=13||version==2&&bytes.length!=MAX_BYTES)throw new IOException("設定の版か値が違います");
        return version==1?new StateSettings(port,0,0,0,0):new StateSettings(port,in.getLong(),in.getLong(),in.getLong(),in.getLong());
    }
    void check(LanGroup group) {
        if(group.saveSeq<saveSeq || group.saveSeq==saveSeq && (group.state.administrators().version()<administratorVersion
                ||group.state.revocations().version()<revocationVersion||group.certificate.issuedAt()<issuedAt))
            throw new Rollback();
    }
}
