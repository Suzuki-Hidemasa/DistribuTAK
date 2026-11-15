// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SignaturePurpose;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * 身元の鍵で署名する発見記録。外側はpayload(1), signature(2)。
 * payloadはschema(1), purpose(2), group_id(3), kind(4), record_key(5), identity_key(6),
 * node_id(7), version(8), signed_at(9), expires_at(10), handshake_key(11),
 * identity_signature(12), ipv4(13), port(14)。0も明示し、受信したpayloadそのものを検査する。
 */
public final class DiscoveryRecord {
    public static final int MAX_BYTES=768;
    public static final long FUTURE_MILLIS=300_000;
    private static final byte[] PURPOSE=SignaturePurpose.MEMBER_DISCOVERY.purpose();
    private record Body(byte[] group,byte[] key,byte[] identity,byte[] node,long version,long signed,long expires,
                        byte[] handshake,byte[] identitySignature,byte[] ip,int port){}
    private final Body body;
    private final byte[] payload,signature,encoded;
    private DiscoveryRecord(Body body,byte[] payload,byte[] signature) {
        this.body=body;this.payload=payload.clone();this.signature=signature.clone();
        encoded=encode(out->{out.writeByteArray(1,payload);out.writeByteArray(2,signature);});
        if(encoded.length>MAX_BYTES)throw rejected(DiscoveryStatus.INVALID);
    }
    @FunctionalInterface private interface Writer {void write(CodedOutputStream out)throws IOException;}
    private static byte[] encode(Writer writer) {
        try{var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);writer.write(out);out.flush();return bytes.toByteArray();}
        catch(IOException impossible){throw rejected(DiscoveryStatus.INVALID);}
    }
    private static byte[] canonical(Body b) {
        return encode(out->{
            out.writeUInt32(1,2);out.writeByteArray(2,PURPOSE);out.writeByteArray(3,b.group);out.writeUInt32(4,DhtKeys.MEMBER_DISCOVERY);
            out.writeByteArray(5,b.key);out.writeByteArray(6,b.identity);out.writeByteArray(7,b.node);out.writeUInt64(8,b.version);
            out.writeUInt64(9,b.signed);out.writeUInt64(10,b.expires);out.writeByteArray(11,b.handshake);
            out.writeByteArray(12,b.identitySignature);out.writeByteArray(13,b.ip);out.writeUInt32(14,b.port);
        });
    }
    private static void length(byte[] value,int expected){if(value==null||value.length!=expected)throw rejected(DiscoveryStatus.INVALID);}
    private static void shape(Body b) {
        for(byte[] bytes:new byte[][]{b.group,b.key,b.identity,b.node,b.handshake})length(bytes,32);
        length(b.identitySignature,64);length(b.ip,4);
        if(b.version<0||b.signed<0||b.expires<0||b.expires<=b.signed||b.port<1||b.port>65535)throw rejected(DiscoveryStatus.INVALID);
        try{if(b.expires>Math.addExact(b.signed,DhtLimits.RECORD_LIFETIME_MILLIS))throw rejected(DiscoveryStatus.INVALID);}
        catch(ArithmeticException overflow){throw rejected(DiscoveryStatus.INVALID);}
    }
    public static DiscoveryRecord issue(byte[] group,byte[] identitySecret,byte[] handshakeKey,byte[] ipv4,int port,long version,long signedAt) {
        length(group,32);length(identitySecret,32);length(handshakeKey,32);length(ipv4,4);
        if(version<0||version==Long.MAX_VALUE||signedAt<0)throw rejected(DiscoveryStatus.INVALID);
        long expires;try{expires=Math.addExact(signedAt,DhtLimits.RECORD_LIFETIME_MILLIS);}catch(ArithmeticException overflow){throw rejected(DiscoveryStatus.INVALID);}
        byte[] identity=Crypto.ed25519Public(identitySecret);DhtId node=DhtId.fromIdentityPublicKey(identity);
        var body=new Body(group.clone(),DhtKeys.derive(group,DhtKeys.MEMBER_DISCOVERY,node.bytes()).bytes(),identity,node.bytes(),version,signedAt,expires,
                handshakeKey.clone(),SignaturePurpose.identityProof(identitySecret,group,handshakeKey),ipv4.clone(),port);
        shape(body);byte[] payload=canonical(body);return new DiscoveryRecord(body,payload,SignaturePurpose.MEMBER_DISCOVERY.sign(identitySecret,payload));
    }
    private static void tag(CodedInputStream in,int field,int wire)throws IOException {
        if(in.readTag()!=(field<<3|wire))throw rejected(DiscoveryStatus.INVALID);
    }
    private static byte[] bytes(CodedInputStream in,int field)throws IOException{tag(in,field,2);return in.readByteArray();}
    private static long number(CodedInputStream in,int field)throws IOException{tag(in,field,0);return in.readUInt64();}
    /** 大きさと構文だけを検査する。署名の計算はここでは行わない。 */
    static DiscoveryRecord parse(byte[] wire) {
        if(wire==null||wire.length>MAX_BYTES)throw rejected(DiscoveryStatus.INVALID);
        try {
            var outer=CodedInputStream.newInstance(wire);byte[] payload=bytes(outer,1),signature=bytes(outer,2);length(signature,64);
            if(!outer.isAtEnd())throw rejected(DiscoveryStatus.INVALID);
            var in=CodedInputStream.newInstance(payload);
            if(number(in,1)!=2||!Arrays.equals(bytes(in,2),PURPOSE))throw rejected(DiscoveryStatus.INVALID);
            byte[] group=bytes(in,3);if(number(in,4)!=DhtKeys.MEMBER_DISCOVERY)throw rejected(DiscoveryStatus.INVALID);
            byte[] key=bytes(in,5),identity=bytes(in,6),node=bytes(in,7);
            long version=number(in,8),signed=number(in,9),expires=number(in,10);
            byte[] handshake=bytes(in,11),identitySignature=bytes(in,12),ip=bytes(in,13);long port=number(in,14);
            if(!in.isAtEnd()||port<1||port>65535)throw rejected(DiscoveryStatus.INVALID);
            var body=new Body(group,key,identity,node,version,signed,expires,handshake,identitySignature,ip,(int)port);shape(body);
            var record=new DiscoveryRecord(body,payload,signature);
            if(!Arrays.equals(payload,canonical(body))||!Arrays.equals(wire,record.encoded))throw rejected(DiscoveryStatus.INVALID);
            return record;
        }catch(IOException malformed){throw rejected(DiscoveryStatus.INVALID);}
    }
    /** STOREとFIND_VALUEで共通の検査。失効の判定と壁時計を呼び出し元から渡す。 */
    public static DiscoveryRecord verify(byte[] wire,byte[] expectedGroup,Clock clock,Predicate<DhtId> revoked) {
        try {
            DiscoveryRecord record=parse(wire);Body b=record.body;length(expectedGroup,32);long now=clock.millis();
            if(now<0||!Arrays.equals(expectedGroup,b.group)||!record.nodeId().equals(DhtId.fromIdentityPublicKey(b.identity))
                    ||!record.key().equals(DhtKeys.derive(b.group,DhtKeys.MEMBER_DISCOVERY,b.node)))throw rejected(DiscoveryStatus.INVALID);
            // 署名の検査を期限・失効より先にする。偽の署名の記録が EXPIRED・REVOKED を名のっても INVALID にする（核 C1）。
            if(!SignaturePurpose.verifyIdentity(b.group,b.identity,b.handshake,b.identitySignature)||!SignaturePurpose.MEMBER_DISCOVERY.verify(b.identity,record.payload,record.signature))throw rejected(DiscoveryStatus.INVALID);
            if(b.signed>now&&b.signed-now>FUTURE_MILLIS)throw rejected(DiscoveryStatus.INVALID);
            if(now>=b.expires)throw rejected(DiscoveryStatus.EXPIRED);
            if(revoked.test(record.nodeId()))throw rejected(DiscoveryStatus.REVOKED);
            return record;
        }catch(DiscoveryRejected rejected){throw rejected;}
        catch(RuntimeException invalid){throw rejected(DiscoveryStatus.INVALID);}
    }
    static DiscoveryRejected rejected(DiscoveryStatus status){return new DiscoveryRejected(status);}
    public DhtId key(){return new DhtId(body.key);}
    public DhtId nodeId(){return new DhtId(body.node);}
    public long version(){return body.version;}
    public long signedAt(){return body.signed;}
    public long expiresAt(){return body.expires;}
    public byte[] identityKey(){return body.identity.clone();}
    public byte[] handshakeKey(){return body.handshake.clone();}
    public byte[] identitySignature(){return body.identitySignature.clone();}
    public byte[] ipv4(){return body.ip.clone();}
    public int port(){return body.port;}
    public byte[] payload(){return payload.clone();}
    public byte[] signature(){return signature.clone();}
    public byte[] encode(){return encoded.clone();}
    int encodedSize(){return encoded.length;}
    byte[] payloadDigest(){return Crypto.blake2s(payload);}
    @Override public String toString(){return "DHT discovery record";}
}
