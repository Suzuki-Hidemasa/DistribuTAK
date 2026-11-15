// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.*;
/** 従来の一覧の試験を、対応する秘密鍵で所持証明した一覧へ移すための試料。 */
final class AdminProofFixtures {
    static AdminRecords.Record list(byte[] group,long version,long time,List<byte[]> keys,byte[] signer,byte[]... available) {
        var bindings=new ArrayList<AdminBinding>();
        for(byte[] key:keys) {
            byte[] secret=null;for(byte[] candidate:available)if(Crypto.equal(key,Crypto.ed25519Public(candidate))){secret=candidate;break;}
            if(secret==null)throw new IllegalArgumentException("試料の管理者秘密鍵がありません");
            byte[] identity=Crypto.blake2s(Crypto.concat(new byte[]{73,68},secret));
            var proof=AdminControl.keyProof(group,new byte[16],version==0?0:version-1,identity,secret);
            bindings.add(AdminBinding.bound(key,proof.memberId(),proof.encode()));
        }
        return AdminRecords.administrators(group,version,time,bindings,signer);
    }
    /** 第2回までに保存した形式2の正確な一覧（項目7なし）を作る試料。 */
    static AdminRecords.Record unboundHistory(AdminRecords.Record record,byte[] signer) throws java.io.IOException {
        var input=com.google.protobuf.CodedInputStream.newInstance(record.signedBytes());var payload=new java.io.ByteArrayOutputStream();byte[] original=record.signedBytes();
        while(!input.isAtEnd()) {int start=input.getTotalBytesRead();int tag=input.readTag();input.skipField(tag);int end=input.getTotalBytesRead();if((tag>>>3)!=7)payload.write(original,start,end-start);}
        byte[] raw=payload.toByteArray();var wire=new java.io.ByteArrayOutputStream();var out=com.google.protobuf.CodedOutputStream.newInstance(wire);
        out.writeByteArray(1,raw);out.writeByteArray(2,SignaturePurpose.ADMINISTRATORS.sign(signer,raw));out.flush();return AdminRecords.decode(wire.toByteArray());
    }
}
