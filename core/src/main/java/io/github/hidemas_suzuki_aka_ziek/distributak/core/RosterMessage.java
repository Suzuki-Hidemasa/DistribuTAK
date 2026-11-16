// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import java.io.IOException;
import java.util.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementWire.*;

/**
 * 名簿と要約の厳密な本体形式。権限と証明書の検証は受信側が行う。
 * <p>
 * Strict roster and summary body encoding. The receiver verifies authority and certificates.
 */
public final class RosterMessage {
    public static final int MAX_COUNT=32,MAX_BYTES=65536,MAX_CERTIFICATE_BYTES=1024;
    private RosterMessage(){}
    private static void ordered(byte[] previous,byte[] current){
        Crypto.length(current,32);
        if(previous!=null&&AdminRecords.compareBytes(previous,current)>=0)throw invalid();
    }
    private static byte[] summaryEntry(MemberDirectory.Summary value){
        return write(out->{out.writeByteArray(1,value.memberId());out.writeUInt64(2,value.issuedAt());out.writeByteArray(3,value.digest());});
    }
    private static MemberDirectory.Summary summaryEntry(byte[] bytes)throws IOException{
        var in=CodedInputStream.newInstance(bytes);byte[] member=bytes(in,1);tag(in,2,0);long issued=in.readUInt64();
        var value=new MemberDirectory.Summary(member,issued,bytes(in,3));
        if(!in.isAtEnd()||!Arrays.equals(bytes,summaryEntry(value)))throw invalid();return value;
    }
    public record Summary(int total,byte[] digest,byte[] after,List<MemberDirectory.Summary> entries,boolean more){
        public Summary(int total,byte[] digest,byte[] after,List<MemberDirectory.Summary> entries){this(total,digest,after,entries,false);}
        public Summary(int total,byte[] digest,byte[] after,List<MemberDirectory.Summary> entries,boolean more){
            if(total<0||total>MemberDirectory.MAX_MEMBERS||entries==null||entries.size()>MAX_COUNT||entries.size()>total)throw invalid();
            if(more&&(entries.size()!=MAX_COUNT||total<=MAX_COUNT))throw invalid();
            Crypto.length(digest,32);if(after==null||after.length!=0&&after.length!=32)throw invalid();
            byte[] previous=after.length==0?null:after;
            for(var entry:entries){ordered(previous,entry.memberId());previous=entry.memberId();}
            this.total=total;this.digest=digest.clone();this.after=after.clone();this.entries=List.copyOf(entries);this.more=more;
        }
        @Override public byte[] digest(){return digest.clone();}
        @Override public byte[] after(){return after.clone();}
        public byte[] encode(){
            return write(out->{out.writeUInt32(1,1);out.writeUInt32(2,total);out.writeByteArray(3,digest);
                out.writeByteArray(4,after);out.writeUInt32(5,entries.size());
                for(var entry:entries)out.writeByteArray(6,summaryEntry(entry));out.writeUInt32(7,more?1:0);});
        }
        @Override public String toString(){return "Roster summary";}
    }
    public static Summary decodeSummary(byte[] wire){
        if(wire==null||wire.length>MAX_BYTES)throw invalid();
        try{
            var in=CodedInputStream.newInstance(wire);if(number(in,1,1)!=1)throw invalid();
            int total=number(in,2,MemberDirectory.MAX_MEMBERS);byte[] digest=bytes(in,3),after=bytes(in,4);
            int count=number(in,5,MAX_COUNT);var entries=new ArrayList<MemberDirectory.Summary>();
            for(int i=0;i<count;i++)entries.add(summaryEntry(bytes(in,6)));
            var result=new Summary(total,digest,after,entries,number(in,7,1)==1);
            if(!in.isAtEnd()||!Arrays.equals(wire,result.encode()))throw invalid();return result;
        }catch(IOException malformed){throw invalid();}
    }
    public record Batch(List<AdminRecords.Record> certificates,boolean intervalDone){
        public Batch(List<AdminRecords.Record> certificates,boolean intervalDone){
            this.certificates=List.copyOf(certificates);if(certificates.isEmpty()&&!intervalDone)throw invalid();this.intervalDone=intervalDone;
        }
        public byte[] encode(){return encodeBatch(certificates,intervalDone);}
        @Override public String toString(){return "Roster batch";}
    }
    public static byte[] encodeCertificates(List<AdminRecords.Record> certificates){return encodeBatch(certificates,true);}
    private static byte[] encodeBatch(List<AdminRecords.Record> certificates,boolean intervalDone){
        if(certificates==null||certificates.size()>MAX_COUNT)throw invalid();byte[] previous=null;
        for(var certificate:certificates){
            if(certificate.kind()!=AdminRecords.Kind.CERTIFICATE||certificate.encode().length>MAX_CERTIFICATE_BYTES)throw invalid();
            byte[] member=Crypto.blake2s(certificate.field(0));ordered(previous,member);previous=member;
        }
        byte[] result=write(out->{out.writeUInt32(1,1);out.writeUInt32(2,certificates.size());
            for(var certificate:certificates)out.writeByteArray(3,certificate.encode());out.writeUInt32(4,intervalDone?1:0);});
        if(result.length>MAX_BYTES)throw invalid();return result;
    }
    public static List<AdminRecords.Record> decodeCertificates(byte[] wire){return decodeBatch(wire).certificates();}
    public static Batch decodeBatch(byte[] wire){
        if(wire==null||wire.length>MAX_BYTES)throw invalid();
        try{
            var in=CodedInputStream.newInstance(wire);if(number(in,1,1)!=1)throw invalid();
            int count=number(in,2,MAX_COUNT);var result=new ArrayList<AdminRecords.Record>();
            for(int i=0;i<count;i++){
                byte[] certificate=bytes(in,3);if(certificate.length>MAX_CERTIFICATE_BYTES)throw invalid();
                result.add(AdminRecords.decode(certificate));
            }
            var batch=new Batch(result,number(in,4,1)==1);
            if(!in.isAtEnd()||!Arrays.equals(wire,batch.encode()))throw invalid();return batch;
        }catch(IOException malformed){throw invalid();}
    }
    /**
     * 現在有効な全件の要約を既存の全体照合関数でまとめ、最大32件ずつ送る。
     * <p>
     * Summarizes all currently valid entries with the existing whole-object digest and sends at most thirty-two at a time.
     */
    public static Summary summarize(MemberDirectory directory,byte[] after){
        return summarize(directory.validRecipients(),after);
    }
    private static Summary summarize(List<MemberDirectory.Entry> eligible,byte[] after){
        var all=new ArrayList<MemberDirectory.Summary>();
        for(var entry:eligible)all.add(new MemberDirectory.Summary(entry.memberId(),entry.issuedAt(),entry.digest()));
        byte[] encoded=write(out->{for(var entry:all)out.writeByteArray(1,summaryEntry(entry));});
        var selected=new ArrayList<MemberDirectory.Summary>();
        int remaining=0;
        for(var entry:all)if(after.length==0||AdminRecords.compareBytes(entry.memberId(),after)>0){
            remaining++;if(selected.size()<MAX_COUNT)selected.add(entry);
        }
        return new Summary(all.size(),ManagementPage.digestOf(encoded),after,selected,remaining>MAX_COUNT);
    }
    /**
     * 相手の比較区間にある不足分だけを返す。同時刻の不一致は候補にしない。
     * <p>
     * Returns only missing entries in the peer's comparison interval, excluding equal-time conflicts.
     */
    public static Batch respond(MemberDirectory directory,Summary remote){
        var eligible=directory.validRecipients();var local=summarize(eligible,new byte[0]);
        if(local.total()==remote.total()&&Crypto.equal(local.digest(),remote.digest()))return new Batch(List.of(),true);
        byte[] high=remote.more()?remote.entries().get(remote.entries().size()-1).memberId():null;
        var result=new ArrayList<AdminRecords.Record>();
        for(var entry:eligible){
            if(remote.after().length!=0&&AdminRecords.compareBytes(entry.memberId(),remote.after())<=0)continue;
            if(high!=null&&AdminRecords.compareBytes(entry.memberId(),high)>0)break;
            MemberDirectory.Summary held=null;
            for(var known:remote.entries())if(Crypto.equal(entry.memberId(),known.memberId())){held=known;break;}
            if(held!=null&&held.issuedAt()>=entry.issuedAt())continue;
            if(result.size()==MAX_COUNT)return new Batch(result,false);
            result.add(entry.certificate());
        }
        return new Batch(result,true);
    }

}
