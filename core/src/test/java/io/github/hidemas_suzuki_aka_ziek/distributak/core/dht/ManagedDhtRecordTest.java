// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminWrappedFixture;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SignaturePurpose;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * 管理用DHT記録の外側（04 §4.5）。形・鍵・署名・内側との一致を調べる。
 * <p>
 * The outer layer of a managed DHT record (04 §4.5): shape, key, signature and agreement with the inner record.
 */
class ManagedDhtRecordTest {
    static final long NOW=1_700_000_000_000L;
    static final byte[] GROUP=DhtIdTest.id(9).bytes(),ZERO=new byte[32];
    static byte[] secret(int n){byte[] b=new byte[32];for(int i=0;i<4;i++)b[28+i]=(byte)(n>>>(24-i*8));return b;}
    static byte[] pub(int n){return Crypto.ed25519Public(secret(n));}
    static byte[] digest(int n){byte[] b=new byte[32];b[0]=(byte)n;return b;}
    static List<byte[]> members(int count) {
        var list=new ArrayList<byte[]>();for(int i=0;i<count;i++)list.add(DhtIdTest.id(100+i).bytes());return list;
    }
    static AdminRecords.Record revocations(long version,long signedAt,int count) {
        return AdminRecords.list(AdminRecords.Kind.REVOCATIONS,GROUP,version,signedAt,members(count),secret(1));
    }
    static AdminRecords.Record admins(long version,long signedAt,int... who) {
        var keys=new ArrayList<byte[]>();for(int n:who)keys.add(pub(n));
        return AdminRecords.list(AdminRecords.Kind.ADMINS,GROUP,version,signedAt,keys,secret(1));
    }
    static AdminRecords.Record wrapped(long version,long signedAt,byte[] recipient) {
        return AdminRecords.wrapped(GROUP,version,signedAt,recipient,digest(1),digest(2),new byte[48],secret(1),digest(7));
    }
    static byte[] certificate() {
        return AdminRecords.certificate(GROUP,pub(7),digest(3),new byte[64],NOW,secret(1)).encode();
    }
    static ManagedDhtRecord revocationRecord(long version,long seq,long adminVersion,long signedAt,int count) {
        return ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),revocations(version,signedAt,count),
                seq,adminVersion,digest(5),signedAt,null);
    }
    @FunctionalInterface interface Output {void write(CodedOutputStream out)throws Exception;}
    static byte[] wire(Output writer) {
        try{var b=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(b);writer.write(out);out.flush();return b.toByteArray();}
        catch(Exception e){throw new AssertionError(e);}
    }
    static boolean numeric(int field){return field==1||field==4||field==7||field==8||field==9||field==12||field==13;}
    /** 外側の payload を項目番号→値（Long か byte[]）に分ける。順は番号の昇順で、項目 15 は無いことがある。 */
    static Object[] fields(ManagedDhtRecord record) {
        try {
            var outer=CodedInputStream.newInstance(record.encode());outer.readTag();byte[] payload=outer.readByteArray();
            var in=CodedInputStream.newInstance(payload);Object[] result=new Object[16];
            while(!in.isAtEnd()){int field=in.readTag()>>>3;result[field]=numeric(field)?(Object)in.readUInt64():in.readByteArray();}
            return result;
        }catch(Exception e){throw new AssertionError(e);}
    }
    static byte[] payload(Object[] fields,int... order) {
        return wire(out->{for(int n:order)if(fields[n]==null)continue;else if(numeric(n))out.writeUInt64(n,(Long)fields[n]);else out.writeByteArray(n,(byte[])fields[n]);});
    }
    static int[] order(int last){int[] order=new int[last];for(int i=0;i<last;i++)order[i]=i+1;return order;}
    static byte[] envelope(byte[] payload,byte[] signature){return wire(out->{out.writeByteArray(1,payload);out.writeByteArray(2,signature);});}
    static byte[] resign(byte[] payload){return envelope(payload,SignaturePurpose.DHT_MANAGEMENT.sign(secret(1),payload));}
    static byte[] change(ManagedDhtRecord record,int field,Object value) {
        var f=fields(record);f[field]=value;return resign(payload(f,order(15)));
    }
    static void reject(Runnable action) {
        var e=assertThrows(ManagedRejected.class,action::run);
        assertEquals(ManagedStatus.INVALID,e.status());assertEquals("管理記録を受け付けられません",e.getMessage());
    }
    static ManagedDhtRecord verify(byte[] wire){return ManagedDhtRecord.verifyStructure(wire,GROUP);}

    @Test void legacyWrappedKeysAreRefusedInNewManagedRecords() {
        byte[] member=DhtIdTest.id(55).bytes();
        var legacy=AdminWrappedFixture.wrapped(GROUP,6,NOW,member,digest(1),digest(2),new byte[48],secret(1));
        var record=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),legacy,1,3,digest(5),NOW,certificate());
        reject(()->verify(record.encode()));
    }
    @Test void announcementsRoundTripAndMatchTheOuterGroupAndVersion() {
        var inner=io.github.hidemas_suzuki_aka_ziek.distributak.core.KeyAnnouncement.issue(GROUP,secret(1),8,NOW,3,digest(4),digest(6),2,digest(5));
        var record=ManagedDhtRecord.issue(GROUP,secret(1),inner,1,2,digest(5),NOW);
        assertArrayEquals(inner.encode(),verify(record.encode()).announcement().encode());
        reject(()->verify(change(record,7,9L)));
        reject(()->verify(change(record,11,new byte[]{1})));
        reject(()->verify(change(record,15,certificate())));
        assertEquals(ManagedDhtRecord.Transport.STORE,record.transport());
    }
    @Test void transportUsesTheEntireOuterRecordAtTheExactBoundary() {
        assertEquals(ManagedDhtRecord.Transport.STORE,widest(7).transport());
        assertEquals(ManagedDhtRecord.Transport.TRANSFER,widest(8).transport());
    }

    // ---- 鍵・宛先・番号 / key, subject, numbers ----
    @Test void everyKindDerivesItsKeyAndSubjectAndRoundTrips() {
        var latest=ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),admins(3,NOW,1,2),4,3,digest(5),NOW,null);
        var back=verify(latest.encode());
        assertArrayEquals(latest.encode(),back.encode());assertEquals(DhtKeys.LATEST_ADMINS,back.kind());
        assertEquals(DhtKeys.derive(GROUP,2,ZERO),back.key());assertArrayEquals(ZERO,back.subject());
        assertEquals(3,back.version());assertEquals(4,back.publicationSeq());assertEquals(3,back.adminVersion());
        assertArrayEquals(digest(5),back.adminDigest());assertArrayEquals(pub(1),back.signer());
        assertEquals(NOW,back.signedAt());assertEquals(NOW+DhtLimits.RECORD_LIFETIME_MILLIS,back.expiresAt());
        assertNull(back.recipientCertificate());

        var revoked=revocationRecord(0,0,0,NOW,0);
        assertEquals(DhtKeys.derive(GROUP,3,ZERO),verify(revoked.encode()).key());

        var history=ManagedDhtRecord.issue(DhtKeys.ADMIN_HISTORY,GROUP,secret(1),admins(2,NOW,1,2),0,2,digest(5),NOW,null);
        var historyBack=verify(history.encode());
        assertArrayEquals(DhtKeys.adminHistorySubject(2),historyBack.subject());
        assertEquals(DhtKeys.derive(GROUP,5,DhtKeys.adminHistorySubject(2)),historyBack.key());

        byte[] member=DhtIdTest.id(55).bytes();
        var wrap=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,member),1,3,digest(5),NOW,certificate());
        var wrapBack=verify(wrap.encode());
        assertArrayEquals(member,wrapBack.subject());assertEquals(DhtKeys.derive(GROUP,4,member),wrapBack.key());
        assertArrayEquals(certificate(),wrapBack.recipientCertificate());assertEquals(6,wrapBack.version());
    }
    @Test void signatureUsesTheManagementPurposeOverTheWholeOuterPayload() {
        var record=revocationRecord(1,1,1,NOW,2);
        assertTrue(record.hasValidSignature());
        assertTrue(SignaturePurpose.DHT_MANAGEMENT.verify(record.signer(),record.payload(),record.signature()));
        assertFalse(Crypto.verify(record.signer(),record.payload(),record.signature()));
        assertEquals(DhtKeys.LATEST_REVOCATIONS,fields(record)[4]==null?0:((Long)fields(record)[4]).intValue());
    }
    @Test void zeroValuesAreWrittenExplicitly() {
        var f=fields(revocationRecord(0,0,0,0,0));
        for(int n:new int[]{1,4,7,8,9,12,13})assertNotNull(f[n]);
        assertEquals(0L,f[7]);assertEquals(0L,f[8]);assertEquals(0L,f[12]);assertEquals(0L,f[13]);assertEquals(DhtLimits.RECORD_LIFETIME_MILLIS,f[9]);
        assertNull(f[15]);
    }
    @Test void expiryIsExactlySignedAtPlusTwentyFourHours() {
        var f=fields(revocationRecord(1,1,1,NOW,1));
        assertEquals(NOW+DhtLimits.RECORD_LIFETIME_MILLIS,f[9]);
        reject(()->verify(change(revocationRecord(1,1,1,NOW,1),9,(Long)f[9]+1)));
        reject(()->verify(change(revocationRecord(1,1,1,NOW,1),9,(Long)f[9]-1)));
    }

    // ---- 厳密な構文 / strict syntax ----
    @Test void unknownDuplicateMissingAndOutOfOrderItemsAreRejected() {
        var base=revocationRecord(1,1,1,NOW,1);var f=fields(base);
        byte[] ok=resign(payload(f,order(14)));verify(ok);
        // 未知の項目 / unknown item
        reject(()->verify(resign(wire(out->{out.write(payload(f,order(14)),0,payload(f,order(14)).length);out.writeUInt32(20,1);}))));
        // 同じ項目が 2 回 / duplicate item
        reject(()->verify(resign(wire(out->{byte[] p=payload(f,order(14));out.write(p,0,p.length);out.writeUInt64(12,0);}))));
        // 項目が足りない・順が違う / missing or out of order
        for(int skip=1;skip<=14;skip++) {
            final int s=skip;
            reject(()->verify(resign(payload(f,Arrays.stream(order(14)).filter(n->n!=s).toArray()))));
        }
        int[] swapped=order(14);swapped[6]=8;swapped[7]=7;
        reject(()->verify(resign(payload(f,swapped))));
        // 外側の余分な項目・足りない項目 / extra or missing envelope items
        reject(()->verify(wire(out->{out.writeByteArray(1,payload(f,order(14)));}) ));
        reject(()->verify(wire(out->{byte[] p=payload(f,order(14));out.writeByteArray(1,p);out.writeByteArray(2,new byte[64]);out.writeByteArray(3,new byte[1]);})));
        reject(()->verify(new byte[0]));reject(()->verify(null));
    }
    @Test void nonCanonicalVarintsAreRejected() {
        var base=revocationRecord(1,1,1,NOW,1);var f=fields(base);
        // schema を 0x81 0x00 のように余分な桁で書く。再符号化との比較で落ちる。
        byte[] p=payload(f,order(14));
        byte[] odd=new byte[p.length+1];odd[0]=p[0];odd[1]=(byte)0x81;odd[2]=0;
        System.arraycopy(p,2,odd,3,p.length-2);
        reject(()->verify(resign(odd)));
    }
    @Test void schemaAndPurposeAndKindAreFixed() {
        var base=revocationRecord(1,1,1,NOW,1);
        reject(()->verify(change(base,1,2L)));
        reject(()->verify(change(base,2,SignaturePurpose.MEMBER_DISCOVERY.purpose())));
        reject(()->verify(change(base,4,1L)));reject(()->verify(change(base,4,7L)));reject(()->verify(change(base,4,0L)));
    }

    // ---- 鍵・宛先・群・署名 / key, subject, group, signature ----
    @Test void groupMismatchKeyMismatchAndSubjectMismatchAreRejected() {
        var base=revocationRecord(1,1,1,NOW,1);
        byte[] other=GROUP.clone();other[0]^=1;
        reject(()->ManagedDhtRecord.verifyStructure(base.encode(),other));
        reject(()->verify(change(base,3,other)));
        reject(()->verify(change(base,5,DhtKeys.derive(GROUP,2,ZERO).bytes())));
        byte[] nonZero=ZERO.clone();nonZero[3]=1;
        reject(()->verify(change(base,10,nonZero)));
        var history=ManagedDhtRecord.issue(DhtKeys.ADMIN_HISTORY,GROUP,secret(1),admins(2,NOW,1,2),0,2,digest(5),NOW,null);
        reject(()->verify(change(history,10,DhtKeys.adminHistorySubject(3))));
        var wrap=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,DhtIdTest.id(55).bytes()),1,3,digest(5),NOW,certificate());
        reject(()->verify(change(wrap,10,DhtIdTest.id(56).bytes())));
    }
    @Test void badSignatureOrWrongSignerOrWrongPurposeIsRejected() {
        var base=revocationRecord(1,1,1,NOW,1);
        byte[] wire=base.encode();wire[wire.length-1]^=1;reject(()->verify(wire));
        // signer を別の鍵にすると署名が合わない / swapping the signer breaks the signature
        var f=fields(base);f[6]=pub(2);
        reject(()->verify(envelope(payload(f,order(14)),base.signature())));
        // 用途の違う署名 / signature with another purpose
        byte[] p=base.payload();
        reject(()->verify(envelope(p,SignaturePurpose.ADMINISTRATORS.sign(secret(1),p))));
        reject(()->verify(envelope(p,Crypto.sign(secret(1),p))));
    }
    @Test void signatureDoesNotCoverOnlyTheInnerRecord() {
        var a=revocationRecord(1,1,1,NOW,1);var b=revocationRecord(1,2,1,NOW,1);
        assertArrayEquals(a.innerRecord(),b.innerRecord());
        assertFalse(Arrays.equals(a.signature(),b.signature()));
    }

    // ---- 内側との一致 / agreement with the inner record ----
    @Test void innerKindGroupVersionAndSubjectMustAgreeWithTheOuter() {
        // 外側の種類と内側の種類が違う / inner kind differs from the outer kind
        var admins=admins(1,NOW,1);
        var f=fields(revocationRecord(1,1,1,NOW,1));f[11]=admins.encode();
        reject(()->verify(resign(payload(f,order(14)))));
        // 外側の版と内側の版が違う / outer and inner versions differ
        reject(()->verify(change(revocationRecord(1,1,1,NOW,1),7,2L)));
        reject(()->verify(change(revocationRecord(1,1,1,NOW,1),7,0L)));
        // 内側の群が違う / inner group differs
        byte[] other=GROUP.clone();other[0]^=1;
        var g=fields(revocationRecord(1,1,1,NOW,1));
        g[11]=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,other,1,NOW,members(1),secret(1)).encode();
        reject(()->verify(resign(payload(g,order(14)))));
        // 内側が壊れている / broken inner record
        var h=fields(revocationRecord(1,1,1,NOW,1));h[11]=new byte[]{1,2,3};
        reject(()->verify(resign(payload(h,order(14)))));
    }
    @Test void keyFiveSubjectMustMatchTheInnerVersionAndKeyFourSubjectTheWrapRecipient() {
        var historyRecord=ManagedDhtRecord.issue(DhtKeys.ADMIN_HISTORY,GROUP,secret(1),admins(2,NOW,1,2),0,2,digest(5),NOW,null);
        var f=fields(historyRecord);f[11]=admins(3,NOW,1,2).encode();
        reject(()->verify(resign(payload(f,order(14)))));
        var wrap=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,DhtIdTest.id(55).bytes()),1,3,digest(5),NOW,certificate());
        var g=fields(wrap);g[11]=wrapped(6,NOW,DhtIdTest.id(56).bytes()).encode();
        reject(()->verify(resign(payload(g,order(15)))));
    }
    @Test void issueRejectsAnInnerRecordOfTheWrongKindOrGroup() {
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),revocations(1,NOW,1),0,1,digest(5),NOW,null));
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),admins(1,NOW,1),0,1,digest(5),NOW,null));
        byte[] other=GROUP.clone();other[0]^=1;
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,other,secret(1),revocations(1,NOW,1),0,1,digest(5),NOW,null));
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),revocations(1,NOW,1),0,1,new byte[31],NOW,null));
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),revocations(1,NOW,1),-1,1,digest(5),NOW,null));
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(1,GROUP,secret(1),revocations(1,NOW,1),0,1,digest(5),NOW,null));
    }

    // ---- 受け手の証明書（項目 15）/ recipient certificate (item 15) ----
    @Test void recipientCertificateIsRequiredOnlyForKindFourAndCoveredByTheSignature() {
        byte[] member=DhtIdTest.id(55).bytes();
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,member),1,3,digest(5),NOW,null));
        for(int kind:new int[]{2,3,5})
            assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(kind,GROUP,secret(1),
                    kind==3?revocations(1,NOW,1):admins(1,NOW,1),0,1,digest(5),NOW,certificate()));
        var wrap=ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,member),1,3,digest(5),NOW,certificate());
        // 項目 15 を落とした種類 4 は断る。 / kind 4 without item 15 is rejected.
        var f=fields(wrap);f[15]=null;reject(()->verify(resign(payload(f,order(15)))));
        // 種類 3 に項目 15 を足したら断る。 / kind 3 with item 15 is rejected.
        var g=fields(revocationRecord(1,1,1,NOW,1));g[15]=certificate();reject(()->verify(resign(payload(g,order(15)))));
        // 受け手の証明書を書き換えると署名が合わない。 / editing the certificate breaks the signature.
        var h=fields(wrap);byte[] edited=((byte[])h[15]).clone();edited[edited.length-1]^=1;h[15]=edited;
        reject(()->verify(envelope(payload(h,order(15)),wrap.signature())));
        // 1 KiB まで通り、1 KiB + 1 は断る。 / up to 1 KiB passes; 1 KiB + 1 does not.
        byte[] kib=new byte[1024];Arrays.fill(kib,(byte)7);
        var edge=fields(wrap);edge[15]=kib;verify(resign(payload(edge,order(15))));
        edge[15]=new byte[1025];reject(()->verify(resign(payload(edge,order(15)))));
        edge[15]=new byte[0];reject(()->verify(resign(payload(edge,order(15)))));
        assertThrows(IllegalArgumentException.class,()->ManagedDhtRecord.issue(DhtKeys.WRAPPED_KEY,GROUP,secret(1),wrapped(6,NOW,member),1,3,digest(5),NOW,new byte[1025]));
    }

    // ---- 大きさ（04 §4.5 の 768 バイトの境）/ sizes (the 768-byte boundary) ----
    private static ManagedDhtRecord widest(int entries) {
        long big=1L<<62;
        return ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),revocations(big,big,entries),big,big,digest(5),big,null);
    }
    @Test void widestNumbersFitOrdinaryStoreUpToSevenRevocationsAndNotEight() {
        assertEquals(755,widest(7).encode().length);assertTrue(widest(7).fitsStore());
        assertEquals(789,widest(8).encode().length);assertFalse(widest(8).fitsStore());
        assertEquals(34,widest(8).encode().length-widest(7).encode().length);
    }
    @Test void realisticNumbersFitOrdinaryStoreUpToEightRevocationsAndNotNine() {
        assertTrue(revocationRecord(1,1,1,NOW,8).fitsStore());assertFalse(revocationRecord(1,1,1,NOW,9).fitsStore());
        assertEquals(34,revocationRecord(1,1,1,NOW,9).encode().length-revocationRecord(1,1,1,NOW,8).encode().length);
    }
    @Test void innerOnlySizeAndOuterSizeAreMeasuredSeparately() {
        // 内側だけが 768 バイトに収まる最大の件数は、外側を付けた最大の件数より多い。
        // The largest entry count whose inner record alone fits in 768 bytes is larger than the one for the outer record.
        int innerMax=0;int outerMax=0;
        for(int n=1;n<=40;n++){
            if(revocations(1,NOW,n).encode().length<=768)innerMax=n;
            if(revocationRecord(1,1,1,NOW,n).fitsStore())outerMax=n;
        }
        assertEquals(8,outerMax);assertTrue(innerMax>outerMax);
        assertFalse(revocationRecord(1,1,1,NOW,innerMax).fitsStore());
    }
    @Test void aLargeRecordParsesUpToTheTransferLimitAndNotBeyond() {
        var big=revocationRecord(1,1,1,NOW,2000);
        assertFalse(big.fitsStore());assertTrue(big.encode().length<DhtWire.MAX_TRANSFER_BYTES);
        verify(big.encode());
        byte[] tooBig=new byte[DhtWire.MAX_TRANSFER_BYTES+1];
        reject(()->verify(tooBig));
    }
    /**
     * 形式 1 の一覧（項目 15・16 がなく、用途の接頭辞なしで署名したもの）を作る。
     * <p>
     * Builds a format-1 list: no items 15 and 16, signed without the purpose prefix.
     */
    static AdminRecords.Record formatOneList(AdminRecords.Record original) {
        byte[] payload=wire(out->{
            out.writeUInt32(1,original.kind().ordinal()+1);out.writeByteArray(2,original.group());out.writeByteArray(3,original.signer());
            out.writeUInt64(4,original.version());out.writeUInt64(5,original.signedAt());
            for(byte[] entry:original.entries())out.writeByteArray(6,entry);
        });
        return AdminRecords.decode(envelope(payload,Crypto.sign(secret(1),payload)));
    }
    /** 形式 1 は使わない。内側が形式 1 の一覧は、外側の署名が正しくても断る（DTAK-9）。 / Format 1 is not used: an inner format-1 list is refused even with a valid outer signature. */
    @Test void innerFormatOneListsAreRefused() {
        var oldAdmins=formatOneList(admins(3,NOW,1,2));
        assertEquals(1,oldAdmins.format());
        reject(()->verify(ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),oldAdmins,1,3,digest(5),NOW,null).encode()));
        reject(()->verify(ManagedDhtRecord.issue(DhtKeys.ADMIN_HISTORY,GROUP,secret(1),oldAdmins,1,3,digest(5),NOW,null).encode()));
        var oldRevocations=formatOneList(revocations(2,NOW,1));
        assertEquals(1,oldRevocations.format());
        reject(()->verify(ManagedDhtRecord.issue(DhtKeys.LATEST_REVOCATIONS,GROUP,secret(1),oldRevocations,1,3,digest(5),NOW,null).encode()));
        // 形式 2 は通る。 / Format 2 passes.
        verify(ManagedDhtRecord.issue(DhtKeys.LATEST_ADMINS,GROUP,secret(1),admins(3,NOW,1,2),1,3,digest(5),NOW,null).encode());
    }
}
