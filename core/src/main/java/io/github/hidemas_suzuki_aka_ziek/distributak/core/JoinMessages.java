// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** 入るためだけの握手の正規形。大きさを検査してからprotobufを読む。 */
final class JoinMessages {
    static final int MAX_REQUEST=4096, MAX_RESPONSE=16*1024*1024, MAX_CHAIN=64;
    static final int MAX_REPLY_PACKET=MAX_RESPONSE+1024;
    private JoinMessages() {}
    @FunctionalInterface private interface Writer { void write(CodedOutputStream out) throws IOException; }
    private static byte[] encode(int size, Writer writer) {
        byte[] bytes=new byte[size];
        try { var out=CodedOutputStream.newInstance(bytes);writer.write(out);out.checkNoSpaceLeft();return bytes; }
        catch(IOException | RuntimeException e) { Crypto.wipe(bytes);throw new IllegalArgumentException("入るための記録を書けません",e); }
    }
    private static int size(int field, byte[] value) { return CodedOutputStream.computeByteArraySize(field,value); }
    private static void limit(byte[] raw, int max) {
        if(raw==null || raw.length>max) throw new IllegalArgumentException("入るための記録が上限を超えています");
    }
    private static void tag(CodedInputStream in,int field,int wire) throws IOException {
        if(in.readTag()!=(field<<3|wire)) throw new IllegalArgumentException("入るための記録の項目が違います");
    }
    private static byte[] bytes(CodedInputStream in,int field) throws IOException { tag(in,field,2);return in.readByteArray(); }
    private static void kind(CodedInputStream in,int value) throws IOException {
        tag(in,1,0);if(in.readUInt32()!=value) throw new IllegalArgumentException("入るための記録の種類が違います");
    }
    private static void canonical(CodedInputStream in,byte[] raw,byte[] encoded) throws IOException {
        try { if(!in.isAtEnd() || !Arrays.equals(raw,encoded)) throw new IllegalArgumentException("入るための記録が正規形ではありません"); }
        finally { Crypto.wipe(encoded); }
    }
    static final class Request implements AutoCloseable {
        final byte[] invitation,identity,handshake,binding,code,proof,signature;
        private byte[] receivedPrefix,receivedProofPrefix;
        Request(byte[] invitation,byte[] identity,byte[] handshake,byte[] binding,byte[] code,byte[] proof) {
            this(invitation,identity,handshake,binding,code,proof,new byte[64]);
        }
        Request(byte[] invitation,byte[] identity,byte[] handshake,byte[] binding,byte[] code,byte[] proof,byte[] signature) {
            Crypto.length(invitation,32);Crypto.length(identity,32);Crypto.length(handshake,32);Crypto.length(binding,64);Crypto.length(code,8);Crypto.length(proof,32);
            Crypto.length(signature,64);
            for(byte c:code) if(c<48 || c>57) throw new IllegalArgumentException("TOTPは8桁の数字だけです");
            this.invitation=invitation.clone();this.identity=identity.clone();this.handshake=handshake.clone();this.binding=binding.clone();this.code=code.clone();this.proof=proof.clone();this.signature=signature.clone();
        }
        byte[] unsigned() { return receivedProofPrefix==null ? write(6) : receivedProofPrefix.clone(); }
        byte[] signedBytes() { return receivedPrefix==null ? write(7) : receivedPrefix.clone(); }
        byte[] encode() { return write(8); }
        private byte[] write(int through) {
            int size=2+size(2,invitation)+size(3,identity)+size(4,handshake)+size(5,binding)+size(6,code)+(through>=7 ? size(7,proof) : 0)+(through>=8 ? size(8,signature) : 0);
            return JoinMessages.encode(size,out->{ out.writeUInt32(1,1);out.writeByteArray(2,invitation);out.writeByteArray(3,identity);out.writeByteArray(4,handshake);
                out.writeByteArray(5,binding);out.writeByteArray(6,code);if(through>=7) out.writeByteArray(7,proof);if(through>=8) out.writeByteArray(8,signature); });
        }
        @Override public void close() { Crypto.wipe(invitation);Crypto.wipe(identity);Crypto.wipe(handshake);Crypto.wipe(binding);Crypto.wipe(code);Crypto.wipe(proof);Crypto.wipe(signature);Crypto.wipe(receivedPrefix);Crypto.wipe(receivedProofPrefix); }
    }
    static Request request(byte[] raw) {
        limit(raw,MAX_REQUEST);List<byte[]> values=new ArrayList<>();Request result=null;
        try {
            var in=CodedInputStream.newInstance(raw);kind(in,1);
            for(int field=2;field<=6;field++) values.add(bytes(in,field));
            int proofPrefixEnd=in.getTotalBytesRead();values.add(bytes(in,7));
            int prefixEnd=in.getTotalBytesRead();values.add(bytes(in,8));
            result=new Request(values.get(0),values.get(1),values.get(2),values.get(3),values.get(4),values.get(5),values.get(6));
            result.receivedPrefix=Arrays.copyOf(raw,prefixEnd);
            result.receivedProofPrefix=Arrays.copyOf(raw,proofPrefixEnd);
            canonical(in,raw,result.encode());return result;
        } catch(IOException | RuntimeException e) {
            if(result!=null) result.close();throw new IllegalArgumentException("入るための求めが壊れています",e);
        } finally { for(byte[] value:values) Crypto.wipe(value); }
    }
    static final class Response {
        final byte[] group,anchor,revocations,certificate,wrapped;
        final List<byte[]> chain;
        Response(byte[] group,List<byte[]> chain,byte[] anchor,byte[] revocations,byte[] certificate,byte[] wrapped) {
            Crypto.length(group,32);Crypto.length(anchor,64);
            if(chain.isEmpty() || chain.size()>MAX_CHAIN) throw new IllegalArgumentException("管理者の鎖の長さが範囲外です");
            int total=2+size(2,group)+size(4,anchor);
            for(byte[] record:chain) { limit(record,AdminRecords.MAX_RECORD_BYTES);total=Math.addExact(total,size(3,record)); }
            for(byte[] record:List.of(revocations,certificate,wrapped)) limit(record,AdminRecords.MAX_RECORD_BYTES);
            total=Math.addExact(total,size(5,revocations)+size(6,certificate)+size(7,wrapped));
            if(total>MAX_RESPONSE) throw new IllegalArgumentException("入るための返事が上限を超えています");
            this.group=group.clone();this.anchor=anchor.clone();this.revocations=revocations.clone();this.certificate=certificate.clone();this.wrapped=wrapped.clone();
            List<byte[]> copy=new ArrayList<>();for(byte[] entry:chain) copy.add(entry.clone());this.chain=List.copyOf(copy);
        }
        byte[] encode() {
            int size=2+size(2,group)+size(4,anchor)+size(5,revocations)+size(6,certificate)+size(7,wrapped);
            for(byte[] entry:chain) size+=size(3,entry);
            return JoinMessages.encode(size,out->{out.writeUInt32(1,2);out.writeByteArray(2,group);for(byte[] entry:chain) out.writeByteArray(3,entry);
                out.writeByteArray(4,anchor);out.writeByteArray(5,revocations);out.writeByteArray(6,certificate);out.writeByteArray(7,wrapped);});
        }
    }
    static Response response(byte[] raw) {
        limit(raw,MAX_RESPONSE);
        try {
            var in=CodedInputStream.newInstance(raw);kind(in,2);byte[] group=bytes(in,2);List<byte[]> chain=new ArrayList<>();
            int next=in.readTag();
            while(next==26) {
                if(chain.size()==MAX_CHAIN) throw new IllegalArgumentException("管理者の鎖が長すぎます");
                byte[] entry=in.readByteArray();limit(entry,AdminRecords.MAX_RECORD_BYTES);chain.add(entry);next=in.readTag();
            }
            if(next!=34) throw new IllegalArgumentException("起点の署名がありません");
            byte[] anchor=in.readByteArray();var result=new Response(group,chain,anchor,bytes(in,5),bytes(in,6),bytes(in,7));
            canonical(in,raw,result.encode());return result;
        } catch(IOException e) { throw new IllegalArgumentException("入るための返事が壊れています",e); }
    }
    static final class Packet implements AutoCloseable {
        final boolean reply;
        final byte[] invitation,enc,ciphertext,signature;
        private byte[] receivedPrefix;
        Packet(boolean reply,byte[] invitation,byte[] enc,byte[] ciphertext,byte[] signature) {
            Crypto.length(invitation,32);Crypto.length(enc,32);Crypto.length(signature,reply ? 64 : 0);
            if(ciphertext==null || ciphertext.length<16 || ciphertext.length>(reply ? MAX_RESPONSE+16 : MAX_REQUEST)) throw new IllegalArgumentException("HPKEの包みの長さが違います");
            this.reply=reply;this.invitation=invitation.clone();this.enc=enc.clone();this.ciphertext=ciphertext.clone();this.signature=signature.clone();
        }
        byte[] signedBytes() { return receivedPrefix==null ? write(false) : receivedPrefix.clone(); }
        byte[] encode() { return write(true); }
        private byte[] write(boolean includeSignature) {
            int size=2+size(2,invitation)+size(3,enc)+size(4,ciphertext)+(reply && includeSignature ? size(5,signature) : 0);
            if(size>(reply ? MAX_REPLY_PACKET : MAX_REQUEST)) throw new IllegalArgumentException("HPKEの包みが大きすぎます");
            return JoinMessages.encode(size,out->{out.writeUInt32(1,reply ? 4 : 3);out.writeByteArray(2,invitation);out.writeByteArray(3,enc);
                out.writeByteArray(4,ciphertext);if(reply && includeSignature) out.writeByteArray(5,signature);});
        }
        /** 入力の呼び出し元の配列は触らず、この包みが所有する写しを消す。 */
        @Override public void close() {
            Crypto.wipe(invitation);Crypto.wipe(enc);Crypto.wipe(ciphertext);Crypto.wipe(signature);Crypto.wipe(receivedPrefix);
        }
    }
    static Packet packet(byte[] raw,boolean reply) {
        limit(raw,reply ? MAX_REPLY_PACKET : MAX_REQUEST);List<byte[]> values=new ArrayList<>();Packet result=null;
        try {
            var in=CodedInputStream.newInstance(raw);kind(in,reply ? 4 : 3);
            for(int field=2;field<=4;field++) values.add(bytes(in,field));int prefixEnd=in.getTotalBytesRead();
            values.add(reply ? bytes(in,5) : new byte[0]);
            result=new Packet(reply,values.get(0),values.get(1),values.get(2),values.get(3));result.receivedPrefix=Arrays.copyOf(raw,prefixEnd);
            canonical(in,raw,result.encode());return result;
        } catch(IOException e) {
            if(result!=null) result.close();throw new IllegalArgumentException("HPKEの包みが壊れています",e);
        } catch(RuntimeException e) {
            if(result!=null) result.close();throw e;
        } finally { for(byte[] value:values) Crypto.wipe(value); }
    }
}
