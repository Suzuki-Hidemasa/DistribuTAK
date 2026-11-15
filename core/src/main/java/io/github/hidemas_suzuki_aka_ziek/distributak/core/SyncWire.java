// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.RenewalSchema;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.io.IOException;
import java.util.Arrays;

/** 同期用の平文。ここではセッションの暗号文やDATA番号は扱わない。 */
public final class SyncWire {
    public static final int MAX_MESSAGE_BYTES=73728;
    private SyncWire() {}
    static SyncSchema.SyncEnvelope.Builder envelope() { return SyncSchema.SyncEnvelope.newBuilder().setSchema(1); }
    static ByteString bytes(byte[] value) { return ByteString.copyFrom(value); }
    static SyncSchema.SyncVersion version(CotRecord item) {
        return SyncSchema.SyncVersion.newBuilder().setWallMillis(item.time()).setEudId(bytes(item.author())).build();
    }
    static SyncSchema.SyncInventoryEntry entry(CotRecord item) {
        return SyncSchema.SyncInventoryEntry.newBuilder().setUid(item.uid()).setVersion(version(item))
                .setHash(bytes(item.hash())).setDeleted(item.deleted()).build();
    }
    public static byte[] encode(CotRecord item) {
        var envelope=envelope();
        if(item.deleted())envelope.setTombstone(SyncSchema.SyncTombstone.newBuilder().setUid(item.uid()).setVersion(version(item))
                .setHash(bytes(item.hash())).setHop(item.hop()));
        else envelope.setRecord(SyncSchema.SyncRecord.newBuilder().setUid(item.uid()).setVersion(version(item))
                .setHash(bytes(item.hash())).setHop(item.hop()).setStaleMillis(item.stale()).setXmlUtf8(bytes(item.xml())));
        return envelope.build().toByteArray();
    }
    public static byte[] ack(CotRecord item) {
        return envelope().setAck(SyncSchema.SyncAck.newBuilder().setUid(item.uid()).setVersion(version(item))
                .setHash(bytes(item.hash())).setDeleted(item.deleted())).build().toByteArray();
    }
    /** 更新は項目8だけに載せ、旧版でCoTの同期まで捨てられないようにする。 */
    public static byte[] renewal(byte[] certificate) {
        var record=AdminRecords.decode(certificate);
        if(record.kind()!=AdminRecords.Kind.CERTIFICATE)throw invalid();
        return envelope().setRenewal(RenewalSchema.CertificateRenewal.newBuilder().setCertificate(bytes(certificate))).build().toByteArray();
    }
    /** 更新以外はnull。pluginへprotobufの型を露出しない。 */
    public static byte[] renewalCertificate(byte[] wire) {
        var value=parse(wire);return value.hasRenewal()?value.getRenewal().getCertificate().toByteArray():null;
    }
    private static int messageSize(int field,int size){return CodedOutputStream.computeTagSize(field)+CodedOutputStream.computeUInt32SizeNoTag(size)+size;}
    /** XMLを直列化し直さず、protobufの既知フィールドの長さを数える。 */
    static int storedSize(CotRecord item,long until){
        int version=34+(item.time()==0?0:CodedOutputStream.computeUInt64Size(1,item.time()));
        int body=CodedOutputStream.computeStringSize(1,item.uid())+messageSize(2,version)+34;
        if(item.hop()!=0)body+=CodedOutputStream.computeUInt32Size(4,item.hop());
        if(!item.deleted()){
            if(item.stale()!=0)body+=CodedOutputStream.computeUInt64Size(5,item.stale());
            if(item.xmlSize()!=0)body+=messageSize(6,item.xmlSize());
        }
        int envelope=2+messageSize(item.deleted()?3:2,body);
        int stored=messageSize(1,envelope)+(until==0?0:CodedOutputStream.computeUInt64Size(2,until));
        return messageSize(6,stored);
    }
    static int originSize(String uid,SyncState.Origin kind){
        if(kind==SyncState.Origin.UNKNOWN)return 0;
        return messageSize(7,CodedOutputStream.computeStringSize(1,uid)+CodedOutputStream.computeUInt32Size(2,kind.ordinal()));
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("同期のメッセージの形式が違います"); }
    /** schema1は全階層で既知のフィールドだけを許す（ADR0030答え168(8)(i)）。 */
    private enum Shape {
        VERSION(0,2),RECORD(2,2,2,0,0,2),IDENTITY(2,2,2,0),
        INVENTORY(2,0,0,2),REQUEST(2,0,2),FRAGMENT(2,2,0,0,0,2),
        RENEWAL(2),ENVELOPE(0,2,2,2,2,2,2,2),STORED(2,0),ORIGIN(2,0),SNAPSHOT(2,2,2,0,0,2,2);
        final int[] wires;Shape(int... wires){this.wires=wires;}
    }
    private static Shape child(Shape parent,int field){
        return switch(parent){
            case ENVELOPE -> switch(field){case 2->Shape.RECORD;case 3,4->Shape.IDENTITY;case 5->Shape.INVENTORY;case 6->Shape.REQUEST;case 7->Shape.FRAGMENT;case 8->Shape.RENEWAL;default->null;};
            case RECORD,IDENTITY -> field==2?Shape.VERSION:null;
            case INVENTORY -> field==4?Shape.IDENTITY:null;
            case REQUEST -> field==3?Shape.IDENTITY:null;
            case STORED -> field==1?Shape.ENVELOPE:null;
            case SNAPSHOT -> field==6?Shape.STORED:field==7?Shape.ORIGIN:null;
            default -> null;
        };
    }
    private static void preflight(CodedInputStream input,Shape shape,int depth)throws IOException {
        if(depth>16)throw invalid();int bodies=0,entries=0,records=0,origins=0;
        for(int tag;(tag=input.readTag())!=0;) {
            int field=tag>>>3;
            if(field<1||field>shape.wires.length||(tag&7)!=shape.wires[field-1])throw invalid();
            if(shape==Shape.ENVELOPE&&field>=2&&++bodies>1)throw invalid();
            if((shape==Shape.INVENTORY&&field==4||shape==Shape.REQUEST&&field==3)&&++entries>64)throw invalid();
            if(shape==Shape.SNAPSHOT&&(field==6&&++records>SyncState.MAX_UIDS||field==7&&++origins>SyncState.MAX_UIDS))throw invalid();
            Shape nested=child(shape,field);
            if(nested!=null){
                int limit=input.pushLimit(input.readRawVarint32());
                preflight(input,nested,depth+1);
                input.popLimit(limit);
            } else if(!input.skipField(tag))throw invalid();
        }
    }
    static void preflightSnapshot(byte[] bytes)throws IOException {preflight(CodedInputStream.newInstance(bytes),Shape.SNAPSHOT,0);}
    public static SyncSchema.SyncEnvelope parse(byte[] wire) {
        if(wire==null||wire.length==0||wire.length>MAX_MESSAGE_BYTES)throw invalid();
        try {
            preflight(CodedInputStream.newInstance(wire),Shape.ENVELOPE,0);var input=CodedInputStream.newInstance(wire);
            input.setSizeLimit(MAX_MESSAGE_BYTES);input.setRecursionLimit(16);
            var value=SyncSchema.SyncEnvelope.parseFrom(input);input.checkLastTagWas(0);
            if(!input.isAtEnd()||value.getSchema()!=1||value.getBodyCase()==SyncSchema.SyncEnvelope.BodyCase.BODY_NOT_SET
                    ||!Arrays.equals(wire,value.toByteArray()))throw invalid();
            return value;
        } catch(IOException e) { throw invalid(); }
    }
    public static CotRecord decodeRecord(byte[] wire) { return decodeRecord(parse(wire)); }
    static CotRecord decodeRecord(SyncSchema.SyncEnvelope envelope) {
        CotRecord item;byte[] hash;
        if(envelope.hasRecord()) {
            var record=envelope.getRecord();if(!record.hasVersion())throw invalid();
            item=CotRecord.record(record.getUid(),record.getVersion().getWallMillis(),record.getVersion().getEudId().toByteArray(),
                    record.getStaleMillis(),record.getXmlUtf8().toByteArray(),record.getHop());hash=record.getHash().toByteArray();
        } else if(envelope.hasTombstone()) {
            var record=envelope.getTombstone();if(!record.hasVersion())throw invalid();
            item=CotRecord.tombstone(record.getUid(),record.getVersion().getWallMillis(),record.getVersion().getEudId().toByteArray(),record.getHop());
            hash=record.getHash().toByteArray();
        } else throw invalid();
        if(hash.length!=32||!Crypto.equal(hash,item.hash()))throw invalid();return item;
    }
    static void validateEntry(SyncSchema.SyncInventoryEntry entry) {
        validateIdentity(entry.getUid(),entry.hasVersion()?entry.getVersion():null,entry.getHash());
    }
    static void validateIdentity(String uid,SyncSchema.SyncVersion version,ByteString hash) {
        int length=CotXml.utf8(uid).length;
        if(length==0||length>CotRecord.MAX_UID_BYTES||version==null||version.getWallMillis()<0
                ||version.getEudId().size()!=32||hash.size()!=32)throw invalid();
    }
}
