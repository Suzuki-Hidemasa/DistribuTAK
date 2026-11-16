// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import java.io.IOException;
import java.util.Arrays;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementWire.*;

/**
 * 最大 4 ページの配送確認。これだけで署名済み記録を受理したとは扱わない。項目 11 は利用者が決めた確定の番号。
 * complete=1 は、受け手が対象の全体を完成した（または完了の記録に一致する）ことだけを示し、署名・権限・適用の成功は保証しない。
 * <p>
 * Confirms delivery of up to four pages, never acceptance of a signed record. Field 11 is the number fixed by the user's decision.
 * complete=1 only indicates that the receiver completed the whole object (or matched a remembered completion), and does not guarantee signature validity, authorization, or successful application.
 */
public final class ManagementPageAck {
    public static final int ENVELOPE_FIELD=ManagementEnvelopeFields.PAGE_ACK,MAX_INDICES=4;
    private final byte[] group,operation,digest;
    private final int[] indices;
    private final boolean complete;
    public ManagementPageAck(byte[] group,byte[] operation,byte[] digest,int[] indices,boolean complete){
        Crypto.length(group,32);Crypto.length(operation,16);Crypto.length(digest,32);
        if(indices==null||indices.length<1||indices.length>MAX_INDICES)throw invalid();
        int previous=-1;
        for(int index:indices){if(index<=previous||index>=ManagementPage.MAX_PAGES)throw invalid();previous=index;}
        this.group=group.clone();this.operation=operation.clone();this.digest=digest.clone();this.indices=indices.clone();this.complete=complete;
    }
    public byte[] group(){return group.clone();}
    public byte[] operationId(){return operation.clone();}
    public byte[] objectDigest(){return digest.clone();}
    public int[] pageIndices(){return indices.clone();}
    public boolean complete(){return complete;}
    public byte[] encode(){
        return write(out->{
            out.writeUInt32(1,1);out.writeByteArray(2,group);out.writeByteArray(3,operation);out.writeByteArray(4,digest);
            byte[] packed=write(values->{for(int index:indices)values.writeUInt32NoTag(index);});
            out.writeByteArray(5,packed);out.writeUInt32(6,complete?1:0);
        });
    }
    public byte[] envelope(){return wrap(ENVELOPE_FIELD,encode());}
    public static ManagementPageAck decode(byte[] wire){
        if(wire==null||wire.length<1||wire.length>128)throw invalid();
        try{
            var in=CodedInputStream.newInstance(wire);if(number(in,1,1)!=1)throw invalid();
            byte[] group=bytes(in,2),operation=bytes(in,3),digest=bytes(in,4);
            var packed=CodedInputStream.newInstance(bytes(in,5));int[] indices=new int[MAX_INDICES];int size=0;
            while(!packed.isAtEnd()){
                if(size==MAX_INDICES)throw invalid();long index=packed.readUInt64();
                if(index<0||index>=ManagementPage.MAX_PAGES)throw invalid();indices[size++]=(int)index;
            }
            boolean complete=number(in,6,1)==1;
            if(!in.isAtEnd())throw invalid();
            var result=new ManagementPageAck(group,operation,digest,Arrays.copyOf(indices,size),complete);
            if(!Arrays.equals(wire,result.encode()))throw invalid();return result;
        }catch(IOException malformed){throw invalid();}
    }
    public static ManagementPageAck decodeEnvelope(byte[] wire){
        try{
            var body=unwrap(wire);if(body.field()!=ENVELOPE_FIELD)throw invalid();var ack=decode(body.data());
            if(!Arrays.equals(wire,ack.envelope()))throw invalid();return ack;
        }catch(IOException malformed){throw invalid();}
    }
    @Override public String toString(){return "Management page acknowledgement";}
}
