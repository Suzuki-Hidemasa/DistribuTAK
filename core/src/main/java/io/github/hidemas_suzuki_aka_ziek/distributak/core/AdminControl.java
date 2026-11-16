// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
/** 依頼と知らせだけを表す。権限は検証・保存した一覧からだけ得る（答え214）。 */
public final class AdminControl {
    public enum Operation { REQUEST, OFFER, KEY_PROOF, APPROVED, REJECTED }
    private final Operation operation;
    private final byte[] group,request,member,key,identitySignature,possessionSignature,identity;
    private final long version;
    private AdminControl(Operation op,byte[] group,byte[] request,byte[] member,byte[] key,long version,byte[] identitySignature,byte[] possessionSignature,byte[] identity) {
        this.operation=java.util.Objects.requireNonNull(op);Crypto.length(group,32);Crypto.length(request,16);Crypto.length(member,32);Crypto.length(key,32);
        if(version<0)throw invalid();
        if(op==Operation.REQUEST||op==Operation.KEY_PROOF){Crypto.length(identitySignature,64);Crypto.length(possessionSignature,64);Crypto.length(identity,32);}
        else if(op==Operation.OFFER){if(identitySignature!=null||identity!=null)throw invalid();Crypto.length(possessionSignature,64);}
        else if(identitySignature!=null||possessionSignature!=null||identity!=null)throw invalid();
        this.group=group.clone();this.request=request.clone();this.member=member.clone();this.key=key.clone();this.version=version;
        this.identitySignature=copy(identitySignature);this.possessionSignature=copy(possessionSignature);this.identity=copy(identity);
    }
    private static byte[] copy(byte[] value){return value==null?null:value.clone();}
    public Operation operation(){return operation;}
    public byte[] group(){return group.clone();}
    public byte[] requestId(){return request.clone();}
    public byte[] memberId(){return member.clone();}
    public byte[] administratorKey(){return key.clone();}
    public long baseVersion(){return version;}
    public byte[] identityKey(){return copy(identity);}
    public byte[] identitySignature(){return copy(identitySignature);}
    public byte[] possessionSignature(){return copy(possessionSignature);}
    private static AdminControl proof(Operation op,byte[] group,byte[] request,long version,byte[] identitySecret,byte[] administratorSecret) {
        byte[] identity=Crypto.ed25519Public(identitySecret),key=Crypto.ed25519Public(administratorSecret),member=Crypto.blake2s(identity);
        var unsigned=new AdminControl(op,group,request,member,key,version,new byte[64],new byte[64],identity);
        byte[] payload=unsigned.unsignedBytes();return new AdminControl(op,group,request,member,key,version,
                SignaturePurpose.ADMIN_REQUEST.sign(identitySecret,payload),SignaturePurpose.ADMIN_KEY_PROOF.sign(administratorSecret,payload),identity);
    }
    public static AdminControl request(byte[] group,byte[] request,long version,byte[] identitySecret,byte[] administratorSecret){return proof(Operation.REQUEST,group,request,version,identitySecret,administratorSecret);}
    public static AdminControl keyProof(byte[] group,byte[] request,long version,byte[] identitySecret,byte[] administratorSecret){return proof(Operation.KEY_PROOF,group,request,version,identitySecret,administratorSecret);}
    public static AdminControl offer(byte[] group,byte[] request,byte[] member,long version,byte[] administratorSecret) {
        byte[] key=Crypto.ed25519Public(administratorSecret);var unsigned=new AdminControl(Operation.OFFER,group,request,member,key,version,null,new byte[64],null);
        return new AdminControl(Operation.OFFER,group,request,member,key,version,null,SignaturePurpose.ADMIN_KEY_PROOF.sign(administratorSecret,unsigned.unsignedBytes()),null);
    }
    public static AdminControl approved(AdminControl request,long newVersion) {
        if(newVersion<=request.version)throw invalid();return notice(Operation.APPROVED,request,newVersion);
    }
    public static AdminControl rejected(AdminControl request){return notice(Operation.REJECTED,request,request.version);}
    private static AdminControl notice(Operation op,AdminControl request,long version) {
        if(request.operation!=Operation.REQUEST&&request.operation!=Operation.KEY_PROOF)throw invalid();
        return new AdminControl(op,request.group,request.request,request.member,request.key,version,null,null,null);
    }
    public boolean verifyPossessionProof() {
        return (operation==Operation.REQUEST||operation==Operation.KEY_PROOF)&&Crypto.equal(member,Crypto.blake2s(identity))
                &&SignaturePurpose.ADMIN_REQUEST.verify(identity,unsignedBytes(),identitySignature)
                &&SignaturePurpose.ADMIN_KEY_PROOF.verify(key,unsignedBytes(),possessionSignature);
    }
    public boolean verifyOffer(){return operation==Operation.OFFER&&SignaturePurpose.ADMIN_KEY_PROOF.verify(key,unsignedBytes(),possessionSignature);}
    @FunctionalInterface private interface Writer {void write(CodedOutputStream out)throws IOException;}
    private static byte[] write(Writer writer) {
        try{var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);writer.write(out);out.flush();return bytes.toByteArray();}
        catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
    private void common(CodedOutputStream out)throws IOException {
        out.writeUInt32(1,1);out.writeByteArray(2,group);out.writeByteArray(3,request);out.writeUInt32(4,operation.ordinal()+1);
        out.writeByteArray(5,member);out.writeByteArray(6,key);out.writeUInt64(7,version);
    }
    public byte[] unsignedBytes(){return write(out->{common(out);if(identity!=null)out.writeByteArray(10,identity);});}
    public byte[] encode() {
        return write(out->{common(out);if(identitySignature!=null)out.writeByteArray(8,identitySignature);
            if(possessionSignature!=null)out.writeByteArray(9,possessionSignature);if(identity!=null)out.writeByteArray(10,identity);});
    }
    public byte[] envelope(){return wrap(encode());}
    private static byte[] wrap(byte[] control) {
        byte[] management=write(out->{out.writeUInt32(1,1);out.writeByteArray(ManagementEnvelopeFields.ADMIN_CONTROL,control);});
        byte[] envelope=write(out->{out.writeUInt32(1,3);out.writeByteArray(10,management);});if(envelope.length>1176)throw invalid();return envelope;
    }
    private static void tag(CodedInputStream in,int field,int type)throws IOException{if(in.readTag()!=(field<<3|type))throw invalid();}
    private static byte[] bytes(CodedInputStream in,int field)throws IOException{tag(in,field,2);return in.readByteArray();}
    private static long number(CodedInputStream in,int field)throws IOException{tag(in,field,0);return in.readUInt64();}
    public static AdminControl decode(byte[] wire) {
        if(wire==null||wire.length>1176)throw invalid();
        try{var in=CodedInputStream.newInstance(wire);if(number(in,1)!=1)throw invalid();
            byte[] group=bytes(in,2),request=bytes(in,3);long kind=number(in,4);if(kind<1||kind>5)throw invalid();
            Operation op=Operation.values()[(int)kind-1];byte[] member=bytes(in,5),key=bytes(in,6);long version=number(in,7);
            byte[] identitySignature=null,possessionSignature=null,identity=null;
            if(op==Operation.REQUEST||op==Operation.KEY_PROOF){identitySignature=bytes(in,8);possessionSignature=bytes(in,9);identity=bytes(in,10);}
            else if(op==Operation.OFFER)possessionSignature=bytes(in,9);
            var message=new AdminControl(op,group,request,member,key,version,identitySignature,possessionSignature,identity);
            if(!in.isAtEnd()||!Arrays.equals(wire,message.encode()))throw invalid();return message;
        }catch(IOException malformed){throw invalid();}
    }
    public static AdminControl fromEnvelope(byte[] wire) {
        if(wire==null||wire.length>1176)throw invalid();
        try{var outer=CodedInputStream.newInstance(wire);if(number(outer,1)!=3)throw invalid();
            var management=CodedInputStream.newInstance(bytes(outer,10));if(!outer.isAtEnd()||number(management,1)!=1)throw invalid();
            var message=decode(bytes(management,ManagementEnvelopeFields.ADMIN_CONTROL));if(!management.isAtEnd()||!Arrays.equals(wire,message.envelope()))throw invalid();return message;
        }catch(IOException malformed){throw invalid();}
    }
    public static boolean isEnvelope(byte[] wire){try{fromEnvelope(wire);return true;}catch(RuntimeException malformed){return false;}}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("管理権限の操作の形が違います");}
    @Override public String toString(){return "Administrator control";}
}
