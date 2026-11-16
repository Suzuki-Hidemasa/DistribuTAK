// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementWire.*;

/**
 * 管理記録の正確なバイト列を運ぶページ。署名・権限の検証や記録の適用は行わない（04 §4.5）。
 * <p>
 * A page carrying exact managed-record bytes, without signature or authority verification or record application (04 §4.5).
 */
public final class ManagementPage {
    public static final int PAGE_BYTES=1024,MAX_PAGES=3072,MAX_TOTAL_BYTES=3*1024*1024,MAX_ENTRIES=65536,MAX_BYTES=1132;
    // 既存 BLAKE2s に付ける壊れ検出用の前置き。末尾 NUL はなく、認証や署名の用途には使わない。
    // Prefix for corruption detection with existing BLAKE2s, without a trailing NUL; never used for authentication or signatures.
    private static final byte[] LABEL="DistribuTAK/management-page/v1".getBytes(StandardCharsets.UTF_8);
    public enum Kind {
        REVOCATION(1,3),ANNOUNCEMENT(2,5),ROSTER(3,4),ROSTER_SUMMARY(4,7);
        private final int number,field;
        Kind(int number,int field){this.number=number;this.field=field;}
        public int number(){return number;}
        public int envelopeField(){return field;}
        private static Kind from(int number){
            for(var kind:values())if(kind.number==number)return kind;throw invalid();
        }
    }
    private final Kind kind;
    private final byte[] operation,group,digest,data;
    private final int total,index,count,entries;
    public ManagementPage(Kind kind,byte[] operation,byte[] group,byte[] digest,int total,int index,int count,byte[] data,int entries){
        this.kind=Objects.requireNonNull(kind);Crypto.length(operation,16);Crypto.length(group,32);Crypto.length(digest,32);
        if(total<1||total>MAX_TOTAL_BYTES||count!=(total+PAGE_BYTES-1)/PAGE_BYTES||index<0||index>=count
                ||entries<0||entries>MAX_ENTRIES||data==null||data.length!=Math.min(PAGE_BYTES,total-index*PAGE_BYTES))throw invalid();
        this.operation=operation.clone();this.group=group.clone();this.digest=digest.clone();this.data=data.clone();
        this.total=total;this.index=index;this.count=count;this.entries=entries;
        if(!withinKindLimits())throw invalid();
    }
    boolean withinKindLimits(){return (kind!=Kind.ROSTER&&kind!=Kind.ROSTER_SUMMARY)||(entries<=32&&total<=65536);}
    public Kind kind(){return kind;}
    public byte[] operationId(){return operation.clone();}
    public byte[] group(){return group.clone();}
    public byte[] objectDigest(){return digest.clone();}
    public byte[] data(){return data.clone();}
    public int totalBytes(){return total;}
    public int pageIndex(){return index;}
    public int pageCount(){return count;}
    public int totalEntries(){return entries;}
    /**
     * 連結した全体の壊れと転送の同一性だけを調べる値。署名の代わりにはしない。
     * <p>
     * A check for corruption and transfer identity of the complete concatenated object, never a substitute for signatures.
     */
    public static byte[] digestOf(byte[] data){return Crypto.blake2s(Crypto.concat(LABEL,Objects.requireNonNull(data)));}
    public static List<ManagementPage> split(Kind kind,byte[] operation,byte[] group,byte[] data,int entries){
        if(data==null||data.length<1||data.length>MAX_TOTAL_BYTES)throw invalid();
        int count=(data.length+PAGE_BYTES-1)/PAGE_BYTES;byte[] digest=digestOf(data);
        var pages=new ArrayList<ManagementPage>(count);
        for(int index=0;index<count;index++){
            int from=index*PAGE_BYTES;
            pages.add(new ManagementPage(kind,operation,group,digest,data.length,index,count,
                    Arrays.copyOfRange(data,from,Math.min(data.length,from+PAGE_BYTES)),entries));
        }
        return List.copyOf(pages);
    }
    public byte[] encode(){
        return write(out->{
            out.writeUInt32(1,1);out.writeUInt32(2,kind.number);out.writeByteArray(3,operation);out.writeByteArray(4,group);
            out.writeByteArray(5,digest);out.writeUInt32(6,total);out.writeUInt32(7,index);out.writeUInt32(8,count);
            out.writeByteArray(9,data);out.writeUInt32(10,entries);
        });
    }
    public byte[] envelope(){return wrap(kind.field,encode());}
    public static ManagementPage decode(byte[] wire){
        if(wire==null||wire.length<1||wire.length>MAX_BYTES)throw invalid();
        try{
            var in=CodedInputStream.newInstance(wire);if(number(in,1,1)!=1)throw invalid();
            var kind=Kind.from(number(in,2,4));byte[] operation=bytes(in,3),group=bytes(in,4),digest=bytes(in,5);
            int total=number(in,6,MAX_TOTAL_BYTES),index=number(in,7,MAX_PAGES-1),count=number(in,8,MAX_PAGES);
            byte[] data=bytes(in,9);int entries=number(in,10,MAX_ENTRIES);
            if(!in.isAtEnd())throw invalid();
            var result=new ManagementPage(kind,operation,group,digest,total,index,count,data,entries);
            if(!Arrays.equals(wire,result.encode()))throw invalid();return result;
        }catch(IOException malformed){throw invalid();}
    }
    public static ManagementPage decodeEnvelope(byte[] wire){
        try{
            var body=unwrap(wire);var page=decode(body.data());
            if(body.field()!=page.kind.field||!Arrays.equals(wire,page.envelope()))throw invalid();return page;
        }catch(IOException malformed){throw invalid();}
    }
    @Override public String toString(){return "Management page";}
}
