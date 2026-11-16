// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/** schema3/management9 専用。存在しないべき項目も、正規形との照合で断る。 */
public final class RenewalMessage {
    public static final int MAX_BYTES=1176,MAX_CERTIFICATE_BYTES=1024;
    public enum Operation { PROOF_REQUEST,PROOF_REPLY,CERTIFICATE_DELIVERY }
    public enum Reason { AUTO_RENEWAL,ADMIN_REMOVAL_PREPARE,INVITATION_PREPARE }
    private final Operation operation;
    private final Reason reason;
    private final byte[] group,request,member,administrator,base,handshake,managementOperation,identity,proof,certificate;
    private RenewalMessage(Operation operation,Reason reason,byte[] group,byte[] request,byte[] member,byte[] administrator,
            byte[] base,byte[] handshake,byte[] managementOperation,byte[] identity,byte[] proof,byte[] certificate) {
        this.operation=java.util.Objects.requireNonNull(operation);this.reason=java.util.Objects.requireNonNull(reason);
        for(byte[] value:new byte[][]{group,member,administrator,base,handshake})Crypto.length(value,32);Crypto.length(request,16);
        if(reason==Reason.AUTO_RENEWAL&&managementOperation!=null)throw invalid();
        if(reason!=Reason.AUTO_RENEWAL)Crypto.length(managementOperation,16);
        if(operation==Operation.PROOF_REPLY){Crypto.length(identity,32);Crypto.length(proof,64);}
        else if(identity!=null||proof!=null)throw invalid();
        if(operation==Operation.CERTIFICATE_DELIVERY){
            if(certificate==null||certificate.length>MAX_CERTIFICATE_BYTES||AdminRecords.decode(certificate).format()!=2)throw invalid();
        }else if(certificate!=null)throw invalid();
        this.group=group.clone();this.request=request.clone();this.member=member.clone();this.administrator=administrator.clone();
        this.base=base.clone();this.handshake=handshake.clone();this.managementOperation=copy(managementOperation);
        this.identity=copy(identity);this.proof=copy(proof);this.certificate=copy(certificate);
    }
    private static byte[] copy(byte[] value){return value==null?null:value.clone();}
    public Operation operation(){return operation;}
    public Reason reason(){return reason;}
    public byte[] group(){return group.clone();}
    public byte[] requestId(){return request.clone();}
    public byte[] memberId(){return member.clone();}
    public byte[] administrator(){return administrator.clone();}
    public byte[] baseDigest(){return base.clone();}
    public byte[] handshake(){return handshake.clone();}
    public byte[] managementOperation(){return copy(managementOperation);}
    public byte[] identity(){return copy(identity);}
    public byte[] proof(){return copy(proof);}
    public byte[] certificate(){return copy(certificate);}
    public static RenewalMessage request(AdminRecords.Record base,byte[] requestId,byte[] administrator,Reason reason,byte[] operationId) {
        if(base.kind()!=AdminRecords.Kind.CERTIFICATE)throw invalid();
        return new RenewalMessage(Operation.PROOF_REQUEST,reason,base.group(),requestId,Crypto.blake2s(base.field(0)),administrator,
            Crypto.blake2s(base.signedBytes()),base.field(1),operationId,null,null,null);
    }
    private RenewalMessage with(Operation operation,byte[] identity,byte[] proof,byte[] certificate) {
        return new RenewalMessage(operation,reason,group,request,member,administrator,base,handshake,managementOperation,identity,proof,certificate);
    }
    public static RenewalMessage reply(RenewalMessage request,byte[] identitySecret) {
        if(request.operation!=Operation.PROOF_REQUEST||!Crypto.equal(request.member,Crypto.blake2s(Crypto.ed25519Public(identitySecret))))throw invalid();
        return request.with(Operation.PROOF_REPLY,Crypto.ed25519Public(identitySecret),SignaturePurpose.identityProof(identitySecret,request.group,request.handshake),null);
    }
    public static RenewalMessage delivery(RenewalMessage request,byte[] certificate) {
        return request.with(Operation.CERTIFICATE_DELIVERY,null,null,certificate);
    }
    public boolean sameRequest(RenewalMessage other) {
        return other!=null&&reason==other.reason&&Arrays.equals(group,other.group)&&Arrays.equals(request,other.request)
            &&Arrays.equals(member,other.member)&&Arrays.equals(administrator,other.administrator)&&Arrays.equals(base,other.base)
            &&Arrays.equals(handshake,other.handshake)&&Arrays.equals(managementOperation,other.managementOperation);
    }
    /**
     * 要求番号以外が同じか。再鍵のあとに同じ操作が新しい要求番号で届いた配送を、受領済みの配送と照合するために使う（DTAK-7）。
     * <p>
     * Whether everything except the request id is the same. Used to match a delivery that arrives for the same operation with a new request id after a re-key against the accepted delivery (DTAK-7).
     *
     * @param other 比べる相手。The message to compare with.
     * @return 要求番号以外が同じなら true。True if all fields other than the request id are equal.
     */
    public boolean sameOperation(RenewalMessage other) {
        return other!=null&&reason==other.reason&&Arrays.equals(group,other.group)
            &&Arrays.equals(member,other.member)&&Arrays.equals(administrator,other.administrator)&&Arrays.equals(base,other.base)
            &&Arrays.equals(handshake,other.handshake)&&Arrays.equals(managementOperation,other.managementOperation);
    }
    public boolean matchesBase(AdminRecords.Record certificate) {
        return Crypto.equal(group,certificate.group())&&Crypto.equal(member,Crypto.blake2s(certificate.field(0)))
            &&Crypto.equal(handshake,certificate.field(1))&&Crypto.equal(base,Crypto.blake2s(certificate.signedBytes()));
    }
    @FunctionalInterface private interface Writer{void write(CodedOutputStream out)throws IOException;}
    private static byte[] write(Writer writer) {
        try{var buffer=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(buffer);writer.write(out);out.flush();return buffer.toByteArray();}
        catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
    private byte[] body() {
        return write(out->{
            out.writeUInt32(1,1);out.writeUInt32(2,operation.ordinal()+1);out.writeByteArray(3,group);out.writeByteArray(4,request);
            out.writeByteArray(5,member);out.writeByteArray(6,administrator);out.writeByteArray(7,base);out.writeByteArray(8,handshake);
            out.writeUInt32(9,reason.ordinal()+1);if(managementOperation!=null)out.writeByteArray(10,managementOperation);
            if(operation!=Operation.CERTIFICATE_DELIVERY)out.writeUInt32(11,2);
            if(operation==Operation.PROOF_REPLY){out.writeByteArray(12,identity);out.writeByteArray(13,proof);}
            if(operation==Operation.CERTIFICATE_DELIVERY)out.writeByteArray(14,certificate);
        });
    }
    private static byte[] wrap(byte[] body) {
        byte[] management=write(out->{out.writeUInt32(1,1);out.writeByteArray(9,body);});
        byte[] wire=write(out->{out.writeUInt32(1,3);out.writeByteArray(10,management);});
        if(wire.length>MAX_BYTES)throw invalid();return wire;
    }
    public byte[] encode(){return wrap(body());}
    /** セッションの外側は保存しない。先頭0/形式2で旧SignedRecordと分ける。 */
    public byte[] pendingValue(){
        if(operation!=Operation.CERTIFICATE_DELIVERY)throw invalid();
        encode();return Crypto.concat(new byte[]{0,2},body());
    }
    public static RenewalMessage pendingValue(byte[] encoded) {
        if(encoded==null||encoded.length<3||encoded[0]!=0||encoded[1]!=2||encoded.length>MAX_BYTES)throw invalid();
        var message=decode(wrap(Arrays.copyOfRange(encoded,2,encoded.length)));
        if(message.operation!=Operation.CERTIFICATE_DELIVERY||!Arrays.equals(encoded,message.pendingValue()))throw invalid();return message;
    }
    private static void tag(CodedInputStream in,int field,int wire)throws IOException{if(in.readTag()!=(field<<3|wire))throw invalid();}
    private static long number(CodedInputStream in,int field)throws IOException{tag(in,field,0);return in.readUInt64();}
    private static byte[] bytes(CodedInputStream in,int field)throws IOException{tag(in,field,2);return in.readByteArray();}
    public static boolean isManagement(byte[] wire) {
        if(wire==null)return false;
        try{var in=CodedInputStream.newInstance(wire);return number(in,1)==3;}
        catch(IOException|RuntimeException malformed){return false;}
    }
    public static RenewalMessage decode(byte[] wire) {
        if(wire==null||wire.length==0||wire.length>MAX_BYTES)throw invalid();
        try {
            var outer=CodedInputStream.newInstance(wire);if(number(outer,1)!=3)throw invalid();
            var management=CodedInputStream.newInstance(bytes(outer,10));if(!outer.isAtEnd()||number(management,1)!=1)throw invalid();
            var in=CodedInputStream.newInstance(bytes(management,9));if(!management.isAtEnd()||number(in,1)!=1)throw invalid();
            long operation=number(in,2);if(operation<1||operation>3)throw invalid();var op=Operation.values()[(int)operation-1];
            byte[] group=bytes(in,3),request=bytes(in,4),member=bytes(in,5),admin=bytes(in,6),base=bytes(in,7),handshake=bytes(in,8);
            long reason=number(in,9);if(reason<1||reason>3)throw invalid();var why=Reason.values()[(int)reason-1];
            byte[] managementOperation=why!=Reason.AUTO_RENEWAL?bytes(in,10):null,identity=null,proof=null,certificate=null;
            if(op!=Operation.CERTIFICATE_DELIVERY&&number(in,11)!=2)throw invalid();
            if(op==Operation.PROOF_REPLY){identity=bytes(in,12);proof=bytes(in,13);}
            if(op==Operation.CERTIFICATE_DELIVERY)certificate=bytes(in,14);
            if(!in.isAtEnd())throw invalid();
            var result=new RenewalMessage(op,why,group,request,member,admin,base,handshake,managementOperation,identity,proof,certificate);
            if(!Arrays.equals(wire,result.encode()))throw invalid();return result;
        }catch(IOException malformed){throw invalid();}
    }
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("証明の更新メッセージの形式が違います");}
    @Override public String toString(){return "Certificate renewal message";}
}
