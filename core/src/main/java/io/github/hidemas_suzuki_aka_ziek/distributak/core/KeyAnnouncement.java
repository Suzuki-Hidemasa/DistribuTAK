// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * 鍵の入れ替えの告知（04 §4.5）。鍵そのものは保持しない。
 * <p>
 * Key rotation announcement (04 §4.5). Does not retain the key itself.
 */
public final class KeyAnnouncement {
    private static final byte[] COMMITMENT_DOMAIN="DistribuTAK/key-commitment/v1\0".getBytes(StandardCharsets.US_ASCII);
    private final byte[] group,signer,revocationDigest,keyCommitment,adminDigest,payload,signature;
    private final long keyVersion,signedAt,revocationVersion,adminVersion;
    private KeyAnnouncement(byte[] group,byte[] signer,long keyVersion,long signedAt,long revocationVersion,
                            byte[] revocationDigest,byte[] keyCommitment,long adminVersion,byte[] adminDigest,byte[] signature) {
        for(byte[] b:new byte[][]{group,signer,revocationDigest,keyCommitment,adminDigest})Crypto.length(b,32);
        if(keyVersion<0||signedAt<0||revocationVersion<0||adminVersion<0)throw invalid();
        this.group=group.clone();this.signer=signer.clone();this.keyVersion=keyVersion;this.signedAt=signedAt;
        this.revocationVersion=revocationVersion;this.revocationDigest=revocationDigest.clone();this.keyCommitment=keyCommitment.clone();
        this.adminVersion=adminVersion;this.adminDigest=adminDigest.clone();this.signature=signature==null?null:signature.clone();
        payload=encode(out->{out.writeUInt32(1,1);out.writeByteArray(2,this.group);out.writeByteArray(3,this.signer);
            out.writeUInt64(4,keyVersion);out.writeUInt64(5,signedAt);out.writeUInt64(6,revocationVersion);
            out.writeByteArray(7,this.revocationDigest);out.writeByteArray(8,this.keyCommitment);
            out.writeUInt64(9,adminVersion);out.writeByteArray(10,this.adminDigest);});
    }
    @FunctionalInterface private interface Writer {void write(CodedOutputStream out)throws IOException;}
    private static byte[] encode(Writer writer) {
        try{var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);writer.write(out);out.flush();return bytes.toByteArray();}
        catch(IOException impossible){throw invalid();}
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("告知の形式が違います");}
    /** 告知を既存の用途で署名する。 / Signs an announcement with the existing purpose. */
    public static KeyAnnouncement issue(byte[] group,byte[] secret,long keyVersion,long signedAt,long revocationVersion,
                                         byte[] revocationDigest,byte[] keyCommitment,long adminVersion,byte[] adminDigest) {
        var unsigned=new KeyAnnouncement(group,Crypto.ed25519Public(secret),keyVersion,signedAt,revocationVersion,
                revocationDigest,keyCommitment,adminVersion,adminDigest,null);
        return new KeyAnnouncement(group,unsigned.signer,keyVersion,signedAt,revocationVersion,revocationDigest,keyCommitment,
                adminVersion,adminDigest,SignaturePurpose.KEY_ROTATION.sign(secret,unsigned.payload));
    }
    private static void tag(CodedInputStream in,int field,int wire)throws IOException{if(in.readTag()!=(field<<3|wire))throw invalid();}
    private static byte[] bytes(CodedInputStream in,int field)throws IOException{tag(in,field,2);return in.readByteArray();}
    private static long number(CodedInputStream in,int field)throws IOException{tag(in,field,0);return in.readUInt64();}
    /** 正規形だけを読み、署名は verify で調べる。 / Reads canonical syntax; verify checks the signature. */
    public static KeyAnnouncement decode(byte[] wire) {
        if(wire==null||wire.length>1024)throw invalid();
        try{
            var outer=CodedInputStream.newInstance(wire);byte[] payload=bytes(outer,1),signature=bytes(outer,2);Crypto.length(signature,64);
            if(!outer.isAtEnd())throw invalid();
            var in=CodedInputStream.newInstance(payload);if(number(in,1)!=1)throw invalid();
            var record=new KeyAnnouncement(bytes(in,2),bytes(in,3),number(in,4),number(in,5),number(in,6),
                    bytes(in,7),bytes(in,8),number(in,9),bytes(in,10),signature);
            if(!in.isAtEnd()||!Arrays.equals(payload,record.payload)||!Arrays.equals(wire,record.encode()))throw invalid();
            return record;
        }catch(IOException malformed){throw invalid();}
    }
    /** グループ・今の管理者・署名を検査する。 / Checks group, current administrator and signature. */
    public void verify(byte[] expectedGroup,List<byte[]> administrators) {
        if(!Crypto.equal(group,expectedGroup)||!AdminRecords.contains(administrators,signer)||!hasValidSignature())
            throw new SecurityException("告知の署名か宛先が違います");
    }
    public boolean hasValidSignature(){return SignaturePurpose.KEY_ROTATION.verify(signer,payload,signature);}
    /** 用途・グループ・版を結んだ既存の BLAKE2s の入力。 / Existing BLAKE2s input binding purpose, group and version. */
    public static byte[] commitment(byte[] group,long version,byte[] key) {
        Crypto.length(group,32);Crypto.length(key,32);if(version<0)throw invalid();
        byte[] input=Crypto.concat(COMMITMENT_DOMAIN,group,ByteBuffer.allocate(8).putLong(version).array(),key);
        try{return Crypto.blake2s(input);}finally{Crypto.wipe(input);}
    }
    public static int compare(KeyAnnouncement a,KeyAnnouncement b) {
        int c=Long.compare(a.keyVersion,b.keyVersion);if(c!=0)return c;
        c=Long.compare(a.signedAt,b.signedAt);return c!=0?c:AdminRecords.compareBytes(a.payload,b.payload);
    }
    public byte[] encode(){return encode(out->{out.writeByteArray(1,payload);out.writeByteArray(2,signature);});}
    public byte[] group(){return group.clone();}
    public byte[] signer(){return signer.clone();}
    public long keyVersion(){return keyVersion;}
    public long signedAt(){return signedAt;}
    public long revocationVersion(){return revocationVersion;}
    public byte[] revocationDigest(){return revocationDigest.clone();}
    public byte[] keyCommitment(){return keyCommitment.clone();}
    public long adminVersion(){return adminVersion;}
    public byte[] adminDigest(){return adminDigest.clone();}
    public byte[] signedBytes(){return payload.clone();}
    public byte[] signature(){return signature.clone();}
}
