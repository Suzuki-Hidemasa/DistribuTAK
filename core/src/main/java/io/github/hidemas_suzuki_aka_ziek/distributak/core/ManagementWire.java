// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * 管理ページ専用の、項目の順と線の型を固定した読み書き。
 * <p>
 * Encoding and decoding with fixed field order and wire types for management pages only.
 */
final class ManagementWire {
    static final int MAX_ENVELOPE_BYTES=1176;
    @FunctionalInterface interface Writer {void write(CodedOutputStream out)throws IOException;}
    record Body(int field,byte[] data){}
    private ManagementWire(){}
    static byte[] write(Writer writer){
        try{
            var buffer=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(buffer);
            writer.write(out);out.flush();return buffer.toByteArray();
        }catch(IOException impossible){throw new IllegalStateException(impossible);}
    }
    static void tag(CodedInputStream in,int field,int type)throws IOException{
        if(in.readTag()!=(field<<3|type))throw invalid();
    }
    static int number(CodedInputStream in,int field,int maximum)throws IOException{
        tag(in,field,0);long value=in.readUInt64();
        if(value<0||value>maximum)throw invalid();return (int)value;
    }
    static byte[] bytes(CodedInputStream in,int field)throws IOException{
        tag(in,field,2);return in.readByteArray();
    }
    static byte[] wrap(int field,byte[] body){
        byte[] management=write(out->{out.writeUInt32(1,1);out.writeByteArray(field,body);});
        byte[] result=write(out->{out.writeUInt32(1,3);out.writeByteArray(10,management);});
        if(result.length>MAX_ENVELOPE_BYTES)throw invalid();return result;
    }
    static Body unwrap(byte[] wire)throws IOException{
        if(wire==null||wire.length==0||wire.length>MAX_ENVELOPE_BYTES)throw invalid();
        var outer=CodedInputStream.newInstance(wire);if(number(outer,1,3)!=3)throw invalid();
        var management=CodedInputStream.newInstance(bytes(outer,10));
        if(!outer.isAtEnd()||number(management,1,1)!=1)throw invalid();
        int bodyTag=management.readTag();if((bodyTag&7)!=2)throw invalid();
        var result=new Body(bodyTag>>>3,management.readByteArray());
        if(!management.isAtEnd())throw invalid();return result;
    }
    static IllegalArgumentException invalid(){return new IllegalArgumentException("Invalid management page message");}
}
