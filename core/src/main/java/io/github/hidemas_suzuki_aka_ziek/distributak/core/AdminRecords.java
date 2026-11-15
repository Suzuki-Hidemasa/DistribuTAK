// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.nio.charset.StandardCharsets;

/** 管理記録の案。署名は受信した payload そのものに対して検査する。秘密の鍵は保持しない。 */
public final class AdminRecords {
    public static final long CERTIFICATE_LIFETIME_MILLIS=30L*24*60*60*1000;
    public static final int MAX_RECORD_BYTES=3*1024*1024, MAX_ENTRIES=65536;
    public enum Kind { CERTIFICATE, ADMINS, REVOCATIONS, WRAPPED_KEY }
    private static final byte[] ANCHOR_DOMAIN="DistribuTAK/anchor/v1".getBytes(StandardCharsets.US_ASCII);
    /** 古い失効を捨てず、上位にグループの作り直しを求めるための結果。 */
    public static final class RevocationLimitException extends IllegalArgumentException {
        public RevocationLimitException() { super("失効の一覧が上限に達しました。グループを作り直してください"); }
    }
    private AdminRecords() {}

    public static int compareBytes(byte[] a, byte[] b) {
        for(int i=0;i<Math.min(a.length,b.length);i++) {
            int c=(a[i]&255)-(b[i]&255);if(c!=0) return c;
        }
        return Integer.compare(a.length,b.length);
    }
    static boolean contains(List<byte[]> values, byte[] value) {
        for(byte[] candidate:values) if(Crypto.equal(candidate,value)) return true;
        return false;
    }
    private static boolean containsSorted(List<byte[]> values, byte[] value) {
        int low=0, high=values.size()-1;
        while(low<=high) {
            int middle=(low+high)>>>1, comparison=compareBytes(values.get(middle),value);
            if(comparison==0) return true;
            if(comparison<0) low=middle+1;else high=middle-1;
        }
        return false;
    }
    static List<byte[]> sorted(List<byte[]> entries) {
        if(entries.size()>MAX_ENTRIES) throw new IllegalArgumentException("一覧が上限を超えています");
        List<byte[]> out=new ArrayList<>();
        for(byte[] e:entries) { Crypto.length(e,32);out.add(e.clone()); }
        out.sort(AdminRecords::compareBytes);
        for(int i=1;i<out.size();i++) if(Crypto.equal(out.get(i-1),out.get(i))) throw new IllegalArgumentException("一覧の値が重複しています");
        return List.copyOf(out);
    }
    @FunctionalInterface private interface Writer { void write(CodedOutputStream out) throws IOException; }
    private static byte[] encode(Writer writer) {
        try {
            var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);
            writer.write(out);out.flush();return bytes.toByteArray();
        } catch(IOException impossible) { throw new IllegalStateException(impossible); }
    }
    /** 返す配列と一覧は写し。秘密を含まない記録だけを扱う。 */
    public static final class Record {
        private final Kind kind;
        private final int format,identityProofFormat;
        private final List<AdminBinding> bindings;
        private final boolean hasAdminBindings;
        private final byte[] group,signer,payload,signature;
        private final long version,signedAt,issuedAt,expiresAt;
        private final List<byte[]> entries;
        private final byte[][] fields;
        private Record(Kind kind, byte[] group, byte[] signer, long version, long signedAt,
                       List<byte[]> entries, byte[][] fields, long issuedAt, long expiresAt,
                       byte[] payload, byte[] signature, int format, int identityProofFormat) {
            this(kind,group,signer,version,signedAt,entries,fields,issuedAt,expiresAt,payload,signature,format,identityProofFormat,null,false);
        }
        private Record(Kind kind, byte[] group, byte[] signer, long version, long signedAt,
                       List<byte[]> entries, byte[][] fields, long issuedAt, long expiresAt,
                       byte[] payload, byte[] signature, int format, int identityProofFormat,List<AdminBinding> suppliedBindings,boolean hasAdminBindings) {
            Crypto.length(group,32);Crypto.length(signer,32);
            if(version<0 || signedAt<0) throw new IllegalArgumentException("版か時刻が負です");
            this.format=format;this.identityProofFormat=identityProofFormat;
            this.kind=kind;this.group=group.clone();this.signer=signer.clone();this.version=version;this.signedAt=signedAt;
            this.entries=sorted(entries);this.fields=new byte[fields.length][];
            this.hasAdminBindings=hasAdminBindings;
            if(hasAdminBindings&&(kind!=Kind.ADMINS||format!=2))throw new IllegalArgumentException("管理者の対応の形式が違います");
            // 受信した一覧は、所持証明の検査より先に一覧そのものの署名を確かめる。
            if(hasAdminBindings&&payload!=null&&signature!=null&&!SignaturePurpose.ADMINISTRATORS.verify(signer,payload,signature))
                throw new SecurityException("管理者の一覧の署名が違います");
            var ordered=new ArrayList<AdminBinding>();
            if(kind==Kind.ADMINS) {
                if(suppliedBindings==null)for(byte[] key:this.entries)ordered.add(AdminBinding.unknown(key));
                else ordered.addAll(suppliedBindings);
                ordered.sort((a,b)->compareBytes(a.administratorKey(),b.administratorKey()));
                if(ordered.size()!=this.entries.size())throw new IllegalArgumentException("管理者と対応の数が違います");
                var members=new java.util.HashSet<String>();
                for(int i=0;i<ordered.size();i++) {
                    var binding=ordered.get(i);
                    if(!Crypto.equal(binding.administratorKey(),this.entries.get(i))||!binding.verifies(group,version))
                        throw new IllegalArgumentException("管理者の対応か所持証明が違います");
                    if(binding.state()==AdminBinding.State.BOUND&&!members.add(java.util.Base64.getEncoder().encodeToString(binding.memberId())))
                        throw new IllegalArgumentException("管理者と身元の対応が重複しています");
                }
            }
            this.bindings=List.copyOf(ordered);
            for(int i=0;i<fields.length;i++) this.fields[i]=fields[i].clone();
            this.issuedAt=issuedAt;this.expiresAt=expiresAt;
            if(kind==Kind.ADMINS && entries.isEmpty()) throw new IllegalArgumentException("管理者がいません");
            if(kind==Kind.CERTIFICATE) {
                Crypto.length(fields[0],32);Crypto.length(fields[1],32);Crypto.length(fields[2],64);
                if(issuedAt<0 || expiresAt<issuedAt || expiresAt-issuedAt!=CERTIFICATE_LIFETIME_MILLIS || signedAt!=issuedAt || version!=0)
                    throw new IllegalArgumentException("証明書の期間か版が違います");
            } else if(kind==Kind.WRAPPED_KEY) {
                for(int i=0;i<3;i++) Crypto.length(fields[i],32);
                Crypto.length(fields[3],48); // Noise の psk 32 バイト + GCM tag 16 バイト。
            }
            this.payload=payload==null ? canonical() : payload.clone();
            this.signature=signature==null ? null : signature.clone();
        }
        private byte[] canonical() {
            return AdminRecords.encode(out->{
                out.writeUInt32(1,kind.ordinal()+1);out.writeByteArray(2,group);out.writeByteArray(3,signer);
                out.writeUInt64(4,version);out.writeUInt64(5,signedAt);
                if(kind==Kind.ADMINS || kind==Kind.REVOCATIONS) {
                    for(byte[] entry:entries) out.writeByteArray(6,entry);
                    if(hasAdminBindings)for(var binding:bindings)out.writeByteArray(7,binding.encode());
                } else {
                    for(int i=0;i<fields.length;i++) out.writeByteArray(6+i,fields[i]);
                    if(kind==Kind.CERTIFICATE) { out.writeUInt64(9,issuedAt);out.writeUInt64(10,expiresAt); }
                }
                if(format==2) {
                    out.writeUInt32(15,2);out.writeByteArray(16,purpose(kind).purpose());
                    if(kind==Kind.CERTIFICATE)out.writeUInt32(17,identityProofFormat);
                }
            });
        }
        public boolean hasAdminBindings(){return hasAdminBindings;}
        public List<AdminBinding> bindings(){return bindings;}
        public AdminBinding binding(byte[] key) {
            int low=0,high=bindings.size()-1;
            while(low<=high){int mid=(low+high)>>>1;int comparison=compareBytes(bindings.get(mid).administratorKey(),key);
                if(comparison==0)return bindings.get(mid);if(comparison<0)low=mid+1;else high=mid-1;}
            return null;
        }
        public int format(){return format;}
        public int identityProofFormat(){return identityProofFormat;}
        public boolean hasValidSignature(){return format==1?Crypto.verify(signer,payload,signature):purpose(kind).verify(signer,payload,signature);}
        public boolean verifyIdentityBinding(){
            if(kind!=Kind.CERTIFICATE)throw new IllegalArgumentException("証明書ではありません");
            return identityProofFormat==1?Crypto.verify(fields[0],fields[1],fields[2]):SignaturePurpose.verifyIdentity(group,fields[0],fields[1],fields[2]);
        }
        public Kind kind() { return kind; }
        public long version() { return version; }
        public long signedAt() { return signedAt; }
        public long issuedAt() { return issuedAt; }
        public long expiresAt() { return expiresAt; }
        public byte[] group() { return group.clone(); }
        public byte[] signer() { return signer.clone(); }
        public byte[] signedBytes() { return payload.clone(); }
        public byte[] signature() { return signature.clone(); }
        public List<byte[]> entries() {
            List<byte[]> copy=new ArrayList<>(entries.size());for(byte[] entry:entries) copy.add(entry.clone());
            return List.copyOf(copy);
        }
        /** 内部の並びを二分探索する。配列は外へ渡さない。 */
        public boolean hasEntry(byte[] entry) { return containsSorted(entries,entry); }
        public byte[] field(int index) { return fields[index].clone(); }
        public byte[] encode() { return AdminRecords.encode(out->{out.writeByteArray(1,payload);out.writeByteArray(2,signature);}); }
        public void verify(Kind expectedKind, byte[] expectedGroup, List<byte[]> administrators) {
            if(kind!=expectedKind || !Crypto.equal(group,expectedGroup) || !contains(administrators,signer)
                    || !hasValidSignature()) throw new SecurityException("管理記録の署名か宛先が違います");
        }
        void verifySignature(Kind expectedKind, byte[] expectedGroup) {
            if(kind!=expectedKind || !Crypto.equal(group,expectedGroup) || !hasValidSignature())
                throw new SecurityException("管理記録の署名か宛先が違います");
        }
        void verify(Kind expectedKind, byte[] expectedGroup, Record administrators) {
            verifySignature(expectedKind,expectedGroup);
            if(!administrators.hasEntry(signer)) throw new SecurityException("署名者が今の管理者に含まれていません");
        }
    }
    private static SignaturePurpose purpose(Kind kind) {
        return switch(kind){case CERTIFICATE->SignaturePurpose.CERTIFICATE;case ADMINS->SignaturePurpose.ADMINISTRATORS;
            case REVOCATIONS->SignaturePurpose.REVOCATIONS;case WRAPPED_KEY->SignaturePurpose.WRAPPED_KEY;};
    }
    static byte[] anchorMessage(Record first) { return Crypto.concat(ANCHOR_DOMAIN,first.payload); }
    /** 招待で渡す起点に、一覧そのものの署名とは用途を分けた署名を添える。 */
    public static byte[] signAnchor(Record first, byte[] administratorSecret) {
        if(first.kind!=Kind.ADMINS) throw new IllegalArgumentException("起点は管理者の一覧だけです");
        return Crypto.sign(administratorSecret,anchorMessage(first));
    }
    // 並んだ2つの一覧を同時にたどり、差分や和集合を作る。内部の配列は読み取りだけに使う。
    private static List<byte[]> difference(List<byte[]> left, List<byte[]> right) {
        List<byte[]> result=new ArrayList<>();int j=0;
        for(byte[] entry:left) {
            while(j<right.size() && compareBytes(right.get(j),entry)<0) j++;
            if(j==right.size() || compareBytes(entry,right.get(j))!=0) result.add(entry);
        }
        return result;
    }
    private static List<byte[]> union(List<byte[]> left, List<byte[]> right) {
        List<byte[]> result=new ArrayList<>(left.size()+right.size());int i=0,j=0;
        while(i<left.size() || j<right.size()) {
            if(j==right.size() || i<left.size() && compareBytes(left.get(i),right.get(j))<0) result.add(left.get(i++));
            else if(i==left.size() || compareBytes(left.get(i),right.get(j))>0) result.add(right.get(j++));
            else { result.add(left.get(i++));j++; }
        }
        return result;
    }
    static Record reissueList(Record base, Record previous, Record own, long signedAt, byte[] secret) {
        List<byte[]> removed=difference(previous.entries,own.entries), added=difference(own.entries,previous.entries);
        List<byte[]> merged=union(difference(base.entries,removed),added);
        if(own.kind==Kind.REVOCATIONS && merged.size()>MAX_ENTRIES) throw new RevocationLimitException();
        if(own.kind==Kind.ADMINS) {
            var bindings=new ArrayList<AdminBinding>();
            for(byte[] key:merged) {
                var current=base.binding(key);var mine=own.binding(key);
                bindings.add(current==null?mine:current.state()==AdminBinding.State.UNKNOWN&&mine!=null?mine:current);
            }
            return administrators(own.group,Math.addExact(base.version,1),signedAt,bindings,secret);
        }
        return list(own.kind,own.group,Math.addExact(base.version,1),signedAt,merged,secret);
    }
    private static Record sign(Kind kind, byte[] group, long version, long signedAt, List<byte[]> entries,
                               byte[][] fields, long issued, long expires, byte[] secret) {
        int format=kind==Kind.WRAPPED_KEY?1:2;
        var unsigned=new Record(kind,group,Crypto.ed25519Public(secret),version,signedAt,entries,fields,issued,expires,null,null,format,2);
        byte[] signature=format==1?Crypto.sign(secret,unsigned.payload):purpose(kind).sign(secret,unsigned.payload);
        return new Record(kind,group,unsigned.signer,version,signedAt,entries,fields,issued,expires,unsigned.payload,signature,format,2);
    }
    public static Record list(Kind kind, byte[] group, long version, long signedAt, List<byte[]> entries, byte[] administratorSecret) {
        if(kind!=Kind.ADMINS && kind!=Kind.REVOCATIONS) throw new IllegalArgumentException("一覧ではありません");
        if(kind==Kind.ADMINS){var bindings=new ArrayList<AdminBinding>();for(byte[] key:entries)bindings.add(AdminBinding.unknown(key));return administrators(group,version,signedAt,bindings,administratorSecret);}
        return sign(kind,group,version,signedAt,entries,new byte[0][],0,0,administratorSecret);
    }
    public static Record administrators(byte[] group,long version,long signedAt,List<AdminBinding> bindings,byte[] administratorSecret) {
        var entries=new ArrayList<byte[]>();for(var binding:bindings)entries.add(binding.administratorKey());
        var unsigned=new Record(Kind.ADMINS,group,Crypto.ed25519Public(administratorSecret),version,signedAt,entries,new byte[0][],0,0,null,null,2,2,bindings,true);
        return new Record(Kind.ADMINS,group,unsigned.signer,version,signedAt,entries,new byte[0][],0,0,unsigned.payload,
                SignaturePurpose.ADMINISTRATORS.sign(administratorSecret,unsigned.payload),2,2,bindings,true);
    }
    public static Record initialRevocations(byte[] group, long signedAt, byte[] administratorSecret) {
        return list(Kind.REVOCATIONS,group,0,signedAt,List.of(),administratorSecret);
    }
    public static Record certificate(byte[] group, byte[] identity, byte[] handshake, byte[] identitySignature, long issuedAt, byte[] adminSecret) {
        return sign(Kind.CERTIFICATE,group,0,issuedAt,List.of(),new byte[][]{identity,handshake,identitySignature},issuedAt,
                Math.addExact(issuedAt,CERTIFICATE_LIFETIME_MILLIS),adminSecret);
    }
    static Record wrapped(byte[] group, long version, long signedAt, byte[] recipient, byte[] handshake, byte[] enc, byte[] ciphertext, byte[] adminSecret) {
        return sign(Kind.WRAPPED_KEY,group,version,signedAt,List.of(),new byte[][]{recipient,handshake,enc,ciphertext},0,0,adminSecret);
    }
    private static void tag(CodedInputStream in, int field, int wire) throws IOException {
        if(in.readTag()!=(field<<3|wire)) throw new IllegalArgumentException("管理記録の項目が不足、重複、または未対応です");
    }
    private static byte[] bytes(CodedInputStream in, int field) throws IOException { tag(in,field,2);return in.readByteArray(); }
    private static long number(CodedInputStream in, int field) throws IOException { tag(in,field,0);return in.readUInt64(); }
    public static Record decode(byte[] wire) {
        if(wire==null || wire.length>MAX_RECORD_BYTES) throw new IllegalArgumentException("管理記録の長さが範囲外です");
        try {
            var envelope=CodedInputStream.newInstance(wire);
            byte[] payload=bytes(envelope,1), signature=bytes(envelope,2);Crypto.length(signature,64);
            if(!envelope.isAtEnd()) throw new IllegalArgumentException("署名つき記録に余分な項目があります");
            var in=CodedInputStream.newInstance(payload);long type=number(in,1);
            if(type<1 || type>4) throw new IllegalArgumentException("記録の種類が違います");
            Kind kind=Kind.values()[(int)type-1];byte[] group=bytes(in,2), signer=bytes(in,3);
            long version=number(in,4), signedAt=number(in,5), issued=0, expires=0;
            List<byte[]> entries=new ArrayList<>();byte[][] fields=new byte[0][];
            int format=1,identityProofFormat=1;var bindings=new ArrayList<AdminBinding>();boolean hasBindings=false;
            if(kind==Kind.ADMINS || kind==Kind.REVOCATIONS) {
                while(!in.isAtEnd()) {
                    int next=in.readTag();
                    if(next==(15<<3)){format=(int)in.readUInt64();break;}
                    if(next==(7<<3|2)&&kind==Kind.ADMINS) {
                        if(bindings.size()==MAX_ENTRIES)throw new IllegalArgumentException("対応の一覧が上限を超えています");
                        hasBindings=true;bindings.add(AdminBinding.decode(in.readByteArray()));
                    }else {
                        if(next!=(6<<3|2))throw new IllegalArgumentException("一覧に未対応の項目があります");
                        if(entries.size()==MAX_ENTRIES) throw new IllegalArgumentException("一覧が上限を超えています");
                        entries.add(in.readByteArray());
                    }
                }
            } else {
                fields=new byte[kind==Kind.CERTIFICATE ? 3 : 4][];
                for(int i=0;i<fields.length;i++) fields[i]=bytes(in,6+i);
                if(kind==Kind.CERTIFICATE) { issued=number(in,9);expires=number(in,10); }
                if(!in.isAtEnd()){long value=number(in,15);if(value!=2)throw new IllegalArgumentException("未対応の形式です");format=2;}
            }
            if(format!=1) {
                if(format!=2||kind==Kind.WRAPPED_KEY||!Arrays.equals(bytes(in,16),purpose(kind).purpose()))
                    throw new IllegalArgumentException("管理記録の形式か用途が違います");
                if(kind==Kind.CERTIFICATE){if(number(in,17)!=2)throw new IllegalArgumentException("未対応の本人証明です");identityProofFormat=2;}
            }
            if(!in.isAtEnd()) throw new IllegalArgumentException("管理記録に余分な項目があります");
            var record=new Record(kind,group,signer,version,signedAt,entries,fields,issued,expires,payload,signature,format,identityProofFormat,hasBindings?bindings:null,hasBindings);
            // 正規形を検査する。項目7のある一覧は、上の作成時に一覧の署名→所持証明も確かめる。
            if(!Arrays.equals(payload,record.canonical()) || !Arrays.equals(wire,record.encode()))
                throw new IllegalArgumentException("管理記録が正規形ではありません");
            return record;
        } catch(IOException e) { throw new IllegalArgumentException("管理記録が壊れています",e); }
    }
    public static int compare(Record a, Record b) {
        int c=Long.compare(a.version,b.version);if(c!=0) return c;
        c=Long.compare(a.signedAt,b.signedAt);return c!=0 ? c : compareBytes(a.payload,b.payload);
    }
}
