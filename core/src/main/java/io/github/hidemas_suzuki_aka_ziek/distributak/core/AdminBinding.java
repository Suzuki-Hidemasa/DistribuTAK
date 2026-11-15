// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
/** 管理者鍵とメンバーの対応の正規形。所持証明の署名は一覧の検証でも確かめる。 */
public final class AdminBinding {
    public enum State { UNKNOWN, BOUND }
    private final byte[] key,member,proof;
    private final State state;
    private AdminBinding(byte[] key,State state,byte[] member,byte[] proof) {
        Crypto.length(key,32);this.state=java.util.Objects.requireNonNull(state);
        if(state==State.UNKNOWN){if(member!=null||proof!=null)throw invalid();}
        else {Crypto.length(member,32);if(proof==null||proof.length==0)throw invalid();}
        this.key=key.clone();this.member=copy(member);this.proof=copy(proof);
    }
    private static byte[] copy(byte[] value){return value==null?null:value.clone();}
    public static AdminBinding unknown(byte[] key){return new AdminBinding(key,State.UNKNOWN,null,null);}
    public static AdminBinding bound(byte[] key,byte[] member,byte[] proof){return new AdminBinding(key,State.BOUND,member,proof);}
    public State state(){return state;}
    public byte[] administratorKey(){return key.clone();}
    public byte[] memberId(){return copy(member);}
    public byte[] possessionProof(){return copy(proof);}
    public boolean verifies(byte[] group,long listVersion) {
        if(state==State.UNKNOWN)return true;
        try{var control=AdminControl.decode(proof);return control.verifyPossessionProof()&&Crypto.equal(group,control.group())
                &&Crypto.equal(key,control.administratorKey())&&Crypto.equal(member,control.memberId())&&control.baseVersion()<=listVersion;}
        catch(RuntimeException invalid){return false;}
    }
    public byte[] identityKey(){return state==State.UNKNOWN?null:AdminControl.decode(proof).identityKey();}
    public byte[] encode() {
        try{var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);
            out.writeByteArray(1,key);out.writeUInt32(2,state.ordinal());
            if(state==State.BOUND){out.writeByteArray(3,member);out.writeByteArray(4,proof);}
            out.flush();return bytes.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
    public static AdminBinding decode(byte[] wire) {
        if(wire==null)throw invalid();
        try{var in=CodedInputStream.newInstance(wire);tag(in,1,2);byte[] key=in.readByteArray();tag(in,2,0);long state=in.readUInt64();
            AdminBinding binding;
            if(state==0)binding=unknown(key);
            else if(state==1){tag(in,3,2);byte[] member=in.readByteArray();tag(in,4,2);binding=bound(key,member,in.readByteArray());}
            else throw invalid();
            if(!in.isAtEnd()||!Arrays.equals(wire,binding.encode()))throw invalid();return binding;
        }catch(IOException malformed){throw invalid();}
    }
    private static void tag(CodedInputStream in,int field,int type)throws IOException{if(in.readTag()!=(field<<3|type))throw invalid();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("管理者の対応の形が違います");}
    @Override public String toString(){return "Administrator binding";}
}
