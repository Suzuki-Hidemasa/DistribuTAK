// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SignaturePurpose;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * 管理者が署名する管理用 DHT 記録（種類 2〜6）の外側（04 §4.5）。外側は payload(1)、signature(2)。
 * payload は schema(1)、purpose(2)、group_id(3)、kind(4)、record_key(5)、signer(6)、version(7)、signed_at(8)、
 * expires_at(9)、subject(10)、record(11)、publication_seq(12)、admin_version(13)、admin_digest(14)、
 * recipient_certificate(15、種類 4 だけ)。0 も明示し、受信した payload そのものを検査する。
 * <p>
 * The outer layer of an administrator-signed managed DHT record (kinds 2-6; 04 §4.5). The envelope is payload(1) and
 * signature(2). The payload carries schema(1), purpose(2), group_id(3), kind(4), record_key(5), signer(6), version(7),
 * signed_at(8), expires_at(9), subject(10), record(11), publication_seq(12), admin_version(13), admin_digest(14) and
 * recipient_certificate(15, kind 4 only). Zeros are written explicitly and the received payload itself is checked.
 */
public final class ManagedDhtRecord {
    /** 通常の STORE に載せられる最大の大きさ。 / Largest size that fits an ordinary STORE. */
    public static final int MAX_STORE_BYTES=768;
    /** 種類 4 に付ける受け手の証明書の最大の大きさ。 / Largest recipient certificate attached to a kind-4 record. */
    public static final int MAX_RECIPIENT_CERTIFICATE_BYTES=1024;
    private static final byte[] PURPOSE=SignaturePurpose.DHT_MANAGEMENT.purpose();
    private record Body(byte[] group,int kind,byte[] key,byte[] signer,long version,long signedAt,long expiresAt,byte[] subject,
                        byte[] inner,long publicationSeq,long adminVersion,byte[] adminDigest,byte[] certificate){}
    private final Body body;
    private final byte[] payload,signature,encoded;
    private AdminRecords.Record decodedInner;
    private ManagedDhtRecord(Body body,byte[] payload,byte[] signature) {
        this.body=body;this.payload=payload.clone();this.signature=signature.clone();
        encoded=encode(out->{out.writeByteArray(1,payload);out.writeByteArray(2,signature);});
    }
    @FunctionalInterface private interface Writer {void write(CodedOutputStream out)throws IOException;}
    private static byte[] encode(Writer writer) {
        try{var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);writer.write(out);out.flush();return bytes.toByteArray();}
        catch(IOException impossible){throw rejected();}
    }
    private static ManagedRejected rejected(){return new ManagedRejected(ManagedStatus.INVALID);}
    private static byte[] canonical(Body b) {
        return encode(out->{
            out.writeUInt32(1,1);out.writeByteArray(2,PURPOSE);out.writeByteArray(3,b.group);out.writeUInt32(4,b.kind);
            out.writeByteArray(5,b.key);out.writeByteArray(6,b.signer);out.writeUInt64(7,b.version);out.writeUInt64(8,b.signedAt);
            out.writeUInt64(9,b.expiresAt);out.writeByteArray(10,b.subject);out.writeByteArray(11,b.inner);
            out.writeUInt64(12,b.publicationSeq);out.writeUInt64(13,b.adminVersion);out.writeByteArray(14,b.adminDigest);
            if(b.certificate!=null)out.writeByteArray(15,b.certificate);
        });
    }
    private static void length(byte[] value,int expected){if(value==null||value.length!=expected)throw rejected();}
    /** 長さ・範囲・期限・項目 15 の有無を調べる。署名や鍵の計算はしない。 / Checks lengths, ranges, expiry and item 15; no key or signature work. */
    private static void shape(Body b) {
        for(byte[] bytes:new byte[][]{b.group,b.key,b.signer,b.subject,b.adminDigest})length(bytes,32);
        if(b.kind<DhtKeys.LATEST_ADMINS||b.kind>DhtKeys.KEY_ANNOUNCEMENT)throw rejected();
        if(b.version<0||b.signedAt<0||b.expiresAt<0||b.publicationSeq<0||b.adminVersion<0)throw rejected();
        if(b.inner==null||b.inner.length==0||b.inner.length>AdminRecords.MAX_RECORD_BYTES)throw rejected();
        try{if(b.expiresAt!=Math.addExact(b.signedAt,DhtLimits.RECORD_LIFETIME_MILLIS))throw rejected();}
        catch(ArithmeticException overflow){throw rejected();}
        if(b.kind==DhtKeys.WRAPPED_KEY){
            if(b.certificate==null||b.certificate.length==0||b.certificate.length>MAX_RECIPIENT_CERTIFICATE_BYTES)throw rejected();
        }else if(b.certificate!=null)throw rejected();
    }
    private static byte[] subjectOf(int kind,AdminRecords.Record inner) {
        return switch(kind){
            case DhtKeys.ADMIN_HISTORY->DhtKeys.adminHistorySubject(inner.version());
            case DhtKeys.WRAPPED_KEY->inner.field(0);
            default->new byte[32];
        };
    }
    private static AdminRecords.Kind innerKind(int kind) {
        return switch(kind){
            case DhtKeys.LATEST_ADMINS,DhtKeys.ADMIN_HISTORY->AdminRecords.Kind.ADMINS;
            case DhtKeys.LATEST_REVOCATIONS->AdminRecords.Kind.REVOCATIONS;
            case DhtKeys.WRAPPED_KEY->AdminRecords.Kind.WRAPPED_KEY;
            default->null;
        };
    }
    /**
     * 管理者の秘密の鍵で外側を作って署名する。種類 6 の内側はまだ扱わない。
     * <p>
     * Builds and signs the outer layer with the administrator's secret key. The inner record of kind 6 is not handled yet.
     */
    public static ManagedDhtRecord issue(int kind,byte[] group,byte[] adminSecret,AdminRecords.Record inner,long publicationSeq,
                                          long adminVersion,byte[] adminDigest,long signedAt,byte[] recipientCertificate) {
        length(group,32);length(adminSecret,32);length(adminDigest,32);
        AdminRecords.Kind expected=innerKind(kind);
        if(expected==null||inner==null||inner.kind()!=expected||!Crypto.equal(inner.group(),group))throw rejected();
        if(publicationSeq<0||adminVersion<0||signedAt<0)throw rejected();
        long expires;try{expires=Math.addExact(signedAt,DhtLimits.RECORD_LIFETIME_MILLIS);}catch(ArithmeticException overflow){throw rejected();}
        byte[] subject=subjectOf(kind,inner);
        var body=new Body(group.clone(),kind,DhtKeys.derive(group,kind,subject).bytes(),Crypto.ed25519Public(adminSecret),inner.version(),
                signedAt,expires,subject,inner.encode(),publicationSeq,adminVersion,adminDigest.clone(),
                recipientCertificate==null?null:recipientCertificate.clone());
        shape(body);
        byte[] payload=canonical(body);
        return new ManagedDhtRecord(body,payload,SignaturePurpose.DHT_MANAGEMENT.sign(adminSecret,payload));
    }
    private static void tag(CodedInputStream in,int field,int wire)throws IOException {
        if(in.readTag()!=(field<<3|wire))throw rejected();
    }
    private static byte[] bytes(CodedInputStream in,int field)throws IOException{tag(in,field,2);return in.readByteArray();}
    private static long number(CodedInputStream in,int field)throws IOException{tag(in,field,0);return in.readUInt64();}
    /**
     * 大きさと構文だけを検査する。鍵・署名・内側の検査はここでは行わない。
     * <p>
     * Checks only size and syntax. Key, signature and inner-record checks are not done here.
     */
    static ManagedDhtRecord parse(byte[] wire) {
        if(wire==null||wire.length>DhtWire.MAX_TRANSFER_BYTES)throw rejected();
        try {
            var outer=CodedInputStream.newInstance(wire);byte[] payload=bytes(outer,1),signature=bytes(outer,2);length(signature,64);
            if(!outer.isAtEnd())throw rejected();
            var in=CodedInputStream.newInstance(payload);
            if(number(in,1)!=1||!Arrays.equals(bytes(in,2),PURPOSE))throw rejected();
            byte[] group=bytes(in,3);long kind=number(in,4);
            if(kind<DhtKeys.LATEST_ADMINS||kind>DhtKeys.KEY_ANNOUNCEMENT)throw rejected();
            byte[] key=bytes(in,5),signer=bytes(in,6);
            long version=number(in,7),signedAt=number(in,8),expires=number(in,9);
            byte[] subject=bytes(in,10),inner=bytes(in,11);
            long seq=number(in,12),adminVersion=number(in,13);byte[] digest=bytes(in,14),certificate=null;
            if(!in.isAtEnd())certificate=bytes(in,15);
            if(!in.isAtEnd())throw rejected();
            var body=new Body(group,(int)kind,key,signer,version,signedAt,expires,subject,inner,seq,adminVersion,digest,certificate);
            shape(body);
            var record=new ManagedDhtRecord(body,payload,signature);
            if(!Arrays.equals(payload,canonical(body))||!Arrays.equals(wire,record.encoded))throw rejected();
            return record;
        }catch(IOException malformed){throw rejected();}
    }
    /**
     * 構文→鍵と宛先→外側の署名→内側の記録、の順に検査する。STORE と FIND VALUE で同じ検査を使う。
     * 権限・版・期限・失効はここでは見ない。
     * <p>
     * Checks syntax, then key and subject, then the outer signature, then the inner record, in that order. STORE and
     * FIND VALUE share this check. Authority, version, expiry and revocation are not looked at here.
     */
    public static ManagedDhtRecord verifyStructure(byte[] wire,byte[] expectedGroup) {
        try {
            ManagedDhtRecord record=parse(wire);Body b=record.body;length(expectedGroup,32);
            if(!Arrays.equals(expectedGroup,b.group))throw rejected();
            // 宛先と鍵を作り直して比べる。種類 2・3・6 の宛先は 32 バイトの 0、種類 5 は版から決まる。
            // Recompute subject and key. Kinds 2, 3 and 6 use 32 zero bytes; kind 5 derives it from the version.
            if(b.kind==DhtKeys.ADMIN_HISTORY&&!Arrays.equals(b.subject,DhtKeys.adminHistorySubject(b.version)))throw rejected();
            if(!record.key().equals(DhtKeys.derive(b.group,b.kind,b.subject)))throw rejected();
            if(!record.hasValidSignature())throw rejected();
            record.checkInner();
            return record;
        }catch(ManagedRejected rejected){throw rejected;}
        catch(RuntimeException invalid){throw rejected();}
    }
    private void checkInner() {
        AdminRecords.Kind expected=innerKind(body.kind);
        if(expected==null)return;
        var inner=AdminRecords.decode(body.inner);
        if(inner.kind()!=expected||!Crypto.equal(inner.group(),body.group)||inner.version()!=body.version)throw rejected();
        if(body.kind==DhtKeys.WRAPPED_KEY&&!Crypto.equal(inner.field(0),body.subject))throw rejected();
        decodedInner=inner;
    }
    /** 外側の署名を管理用の用途で検査する。 / Verifies the outer signature with the management purpose. */
    public boolean hasValidSignature(){return SignaturePurpose.DHT_MANAGEMENT.verify(body.signer,payload,signature);}
    /** 通常の STORE に載る大きさか。 / Whether the record fits an ordinary STORE. */
    public boolean fitsStore(){return encoded.length<=MAX_STORE_BYTES;}
    /** 内側の記録。検査を通ったあとで使う。種類 6 は null。 / The inner record, for use after verification; null for kind 6. */
    public AdminRecords.Record inner() {
        if(decodedInner==null&&innerKind(body.kind)!=null)decodedInner=AdminRecords.decode(body.inner);
        return decodedInner;
    }
    public int kind(){return body.kind;}
    public DhtId key(){return new DhtId(body.key);}
    public byte[] group(){return body.group.clone();}
    public byte[] signer(){return body.signer.clone();}
    public long version(){return body.version;}
    public long signedAt(){return body.signedAt;}
    public long expiresAt(){return body.expiresAt;}
    public byte[] subject(){return body.subject.clone();}
    public byte[] innerRecord(){return body.inner.clone();}
    public long publicationSeq(){return body.publicationSeq;}
    public long adminVersion(){return body.adminVersion;}
    public byte[] adminDigest(){return body.adminDigest.clone();}
    /** 受け手の証明書。種類 4 だけにある。ないときは null。 / The recipient certificate, present only for kind 4; null otherwise. */
    public byte[] recipientCertificate(){return body.certificate==null?null:body.certificate.clone();}
    public byte[] payload(){return payload.clone();}
    public byte[] signature(){return signature.clone();}
    public byte[] encode(){return encoded.clone();}
    @Override public String toString(){return "DHT managed record";}
}
