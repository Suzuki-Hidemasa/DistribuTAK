// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SignaturePurpose;
import java.io.ByteArrayOutputStream;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DiscoveryRecordTest {
    static final long NOW=1_700_000_000_000L;
    static final byte[] GROUP=new byte[32],IP={(byte)192,(byte)168,1,2};
    static final byte[] HANDSHAKE=Crypto.x25519Public(new byte[32]);
    static byte[] secret(int n){byte[] b=new byte[32];for(int i=0;i<4;i++)b[28+i]=(byte)(n>>>(24-i*8));return b;}
    static Clock clock(long now){return Clock.fixed(Instant.ofEpochMilli(now),ZoneOffset.UTC);}
    static DiscoveryRecord record(int member,long version,long signedAt) {
        return DiscoveryRecord.issue(GROUP,secret(member),HANDSHAKE,IP,50000,version,signedAt);
    }
    static DiscoveryRecord verify(byte[] wire,long now){return DiscoveryRecord.verify(wire,GROUP,clock(now),id->false);}
    @FunctionalInterface interface Output {void write(CodedOutputStream out)throws Exception;}
    static byte[] wire(Output writer) {
        try{var b=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(b);writer.write(out);out.flush();return b.toByteArray();}
        catch(Exception e){throw new AssertionError(e);}
    }
    static byte[] envelope(byte[] payload,byte[] signature){return wire(out->{out.writeByteArray(1,payload);out.writeByteArray(2,signature);});}
    static boolean numeric(int field){return field==1||field==4||field==8||field==9||field==10||field==14;}
    static Object[] fields(DiscoveryRecord record) {
        try {
            var in=CodedInputStream.newInstance(record.payload());Object[] result=new Object[15];
            while(!in.isAtEnd()){int field=in.readTag()>>>3;result[field]=numeric(field)?in.readUInt64():in.readByteArray();}return result;
        }catch(Exception e){throw new AssertionError(e);}
    }
    static byte[] payload(Object[] fields,int... order) {
        return wire(out->{for(int n:order)if(numeric(n))out.writeUInt64(n,(Long)fields[n]);else out.writeByteArray(n,(byte[])fields[n]);});
    }
    static int[] order(){int[] order=new int[14];for(int i=0;i<14;i++)order[i]=i+1;return order;}
    static byte[] change(DiscoveryRecord record,int field,Object value) {
        var f=fields(record);f[field]=value;byte[] bytes=payload(f,order());return envelope(bytes,SignaturePurpose.MEMBER_DISCOVERY.sign(secret(1),bytes));
    }
    static void reject(DiscoveryStatus expected,Runnable action) {
        var e=assertThrows(DiscoveryRejected.class,action::run);assertEquals(expected,e.status());
        assertEquals("発見記録を受け付けられません",e.getMessage());
    }
    @Test void validRecordRoundTripsAndUsesBothPurposeSeparatedSignatures() {
        var original=record(1,3,NOW);var value=verify(original.encode(),NOW);
        assertArrayEquals(original.encode(),value.encode());assertEquals(3,value.version());
        assertEquals(DhtId.fromIdentityPublicKey(Crypto.ed25519Public(secret(1))),value.nodeId());
        assertEquals(DhtKeys.derive(GROUP,1,value.nodeId().bytes()),value.key());
        assertTrue(SignaturePurpose.verifyIdentity(GROUP,value.identityKey(),value.handshakeKey(),value.identitySignature()));
        assertTrue(SignaturePurpose.MEMBER_DISCOVERY.verify(value.identityKey(),value.payload(),value.signature()));
        assertEquals(NOW+DhtLimits.RECORD_LIFETIME_MILLIS,value.expiresAt());assertEquals(50000,value.port());
    }
    @Test void zeroVersionAndZeroSignedTimeAreExplicitCanonicalFields() {
        var value=record(1,0,0);assertEquals(0L,fields(value)[8]);assertEquals(0L,fields(value)[9]);
        assertArrayEquals(value.encode(),verify(value.encode(),0).encode());
    }
    @Test void sizeLimitsReject768And769BytesDuringStructuralParsing() {
        assertEquals(768,DiscoveryRecord.MAX_BYTES);assertTrue(record(1,1,NOW).encode().length<768);
        for(int size:new int[]{768,769})reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(new byte[size]));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(null));
    }
    @Test void unknownPayloadFieldsAreRejectedBeforeSignatureChecking() {
        var value=record(1,1,NOW);byte[] bytes=Crypto.concat(value.payload(),wire(out->out.writeUInt32(15,1)));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(envelope(bytes,new byte[64])));
    }
    @Test void duplicatedAndReorderedFieldsAreRejected() {
        var value=record(1,1,NOW);var f=fields(value);int[] duplicated=Arrays.copyOf(order(),15);duplicated[14]=14;
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(envelope(payload(f,duplicated),value.signature())));
        int[] reversed=order();reversed[0]=2;reversed[1]=1;
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(envelope(payload(f,reversed),value.signature())));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(Crypto.concat(value.encode(),wire(out->out.writeByteArray(2,value.signature())))));
    }
    @Test void trailingBytesUnknownEnvelopeFieldsAndTruncationAreRejected() {
        byte[] bytes=record(1,1,NOW).encode();
        for(byte[] invalid:new byte[][]{Crypto.concat(bytes,new byte[]{0}),Crypto.concat(bytes,wire(out->out.writeUInt32(3,1))),Arrays.copyOf(bytes,bytes.length-1)})
            reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(invalid));
    }
    @Test void nonMinimalIntegerEncodingIsRejectedEvenWithAValidSignature() {
        var value=record(1,1,NOW);byte[] p=value.payload();
        byte[] overlong=Crypto.concat(new byte[]{8,(byte)0x81,0},Arrays.copyOfRange(p,2,p.length));
        reject(DiscoveryStatus.INVALID,()->verify(envelope(overlong,Crypto.sign(secret(1),overlong)),NOW));
    }
    @Test void missingFieldsWrongLengthsAndUnknownSchemasOrKindsAreRejected() {
        var value=record(1,1,NOW);int[] missing=Arrays.copyOf(order(),13);
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.parse(envelope(payload(fields(value),missing),value.signature())));
        for(int field:new int[]{3,5,6,7,11,12,13}) {
            reject(DiscoveryStatus.INVALID,()->verify(change(value,field,new byte[1]),NOW));
        }
        for(long schema:new long[]{1,3})reject(DiscoveryStatus.INVALID,()->verify(change(value,1,schema),NOW));
        reject(DiscoveryStatus.INVALID,()->verify(change(value,4,2L),NOW));
        reject(DiscoveryStatus.INVALID,()->verify(change(value,2,new byte[]{65}),NOW));
    }
    @Test void keyAndNodeIdMustMatchTheirDerivations() {
        var value=record(1,1,NOW);byte[] other=DhtIdTest.id(99).bytes();
        reject(DiscoveryStatus.INVALID,()->verify(change(value,5,other),NOW));
        reject(DiscoveryStatus.INVALID,()->verify(change(value,7,other),NOW));
    }
    @Test void payloadAndSignatureSingleByteTamperingAreRejected() {
        var value=record(1,1,NOW);byte[] payload=value.payload();payload[payload.length-1]^=1;
        reject(DiscoveryStatus.INVALID,()->verify(envelope(payload,value.signature()),NOW));
        byte[] signature=value.signature();signature[0]^=1;
        reject(DiscoveryStatus.INVALID,()->verify(envelope(value.payload(),signature),NOW));
    }
    @Test void handshakeIdentitySignatureMustVerifyEvenWhenOuterSignatureIsValid() {
        var value=record(1,1,NOW);byte[] identitySignature=value.identitySignature();identitySignature[0]^=1;
        reject(DiscoveryStatus.INVALID,()->verify(change(value,12,identitySignature),NOW));
    }
    @Test void wrongGroupAndRevokedIdentityAreRejected() {
        var value=record(1,1,NOW);byte[] group=GROUP.clone();group[0]=1;
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.verify(value.encode(),group,clock(NOW),id->false));
        reject(DiscoveryStatus.REVOKED,()->DiscoveryRecord.verify(value.encode(),GROUP,clock(NOW),value.nodeId()::equals));
    }
    @Test void expirationIsStrictAtTheExactMillisecond() {
        var value=record(1,1,NOW);assertNotNull(verify(value.encode(),value.expiresAt()-1));
        reject(DiscoveryStatus.EXPIRED,()->verify(value.encode(),value.expiresAt()));
    }
    /** 核 C1 手順 1: 署名が偽の記録は、期限・失効を名のっても INVALID（署名の検査が期限・失効より先）。 */
    @Test void forgedSignatureIsInvalidEvenWhenTheRecordLooksExpiredOrRevoked() {
        var value=record(1,1,NOW);byte[] bad=value.signature();bad[0]^=1;byte[] forged=envelope(value.payload(),bad);
        reject(DiscoveryStatus.INVALID,()->verify(forged,value.expiresAt()));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.verify(forged,GROUP,clock(NOW),id->true));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.verify(forged,GROUP,clock(value.expiresAt()),id->true));
        byte[] badIdentity=value.identitySignature();badIdentity[0]^=1;byte[] forgedIdentity=change(value,12,badIdentity);
        reject(DiscoveryStatus.INVALID,()->verify(forgedIdentity,value.expiresAt()));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.verify(forgedIdentity,GROUP,clock(NOW),id->true));
    }
    @Test void validSignatureKeepsExpiredBeforeRevokedAndRevokedAfterSignatureChecks() {
        var value=record(1,1,NOW);
        reject(DiscoveryStatus.EXPIRED,()->DiscoveryRecord.verify(value.encode(),GROUP,clock(value.expiresAt()),id->true));
        reject(DiscoveryStatus.REVOKED,()->DiscoveryRecord.verify(value.encode(),GROUP,clock(NOW),id->true));
    }
    @Test void revocationCheckerExceptionBecomesInvalidWithoutLeakingDetails() {
        var value=record(1,1,NOW);
        var e=assertThrows(DiscoveryRejected.class,()->DiscoveryRecord.verify(value.encode(),GROUP,clock(NOW),id->{throw new IllegalStateException("secret-detail");}));
        assertEquals(DiscoveryStatus.INVALID,e.status());assertFalse(String.valueOf(e.getMessage()).contains("secret-detail"));
    }
    @Test void lifetimesMustBePositiveAndNoLongerThanTwentyFourHours() {
        var value=record(1,1,NOW);
        reject(DiscoveryStatus.INVALID,()->verify(change(value,10,value.expiresAt()+1),NOW));
        reject(DiscoveryStatus.INVALID,()->verify(change(value,10,NOW),NOW));
        assertNotNull(verify(change(value,10,NOW+1),NOW));
    }
    @Test void futureSignatureAllowsExactlyFiveMinutesAndNegativeWallClockIsRejected() {
        var edge=record(1,1,NOW+300_000);assertNotNull(verify(edge.encode(),NOW));
        reject(DiscoveryStatus.INVALID,()->verify(record(1,1,NOW+300_001).encode(),NOW));
        reject(DiscoveryStatus.INVALID,()->verify(record(1,1,0).encode(),-1));
    }
    @Test void negativeIntegersAndOverflowingTimesCannotEnterRecords() {
        var value=record(1,1,NOW);
        for(int field:new int[]{8,9,10})reject(DiscoveryStatus.INVALID,()->verify(change(value,field,Long.MIN_VALUE),NOW));
        reject(DiscoveryStatus.INVALID,()->record(1,1,Long.MAX_VALUE));
        reject(DiscoveryStatus.INVALID,()->verify(change(value,9,Long.MAX_VALUE),NOW));
    }
    @Test void issuingTheMaximumVersionFailsWithoutWrappingToZero() {
        reject(DiscoveryStatus.INVALID,()->record(1,Long.MAX_VALUE,NOW));
        reject(DiscoveryStatus.INVALID,()->record(1,-1,NOW));
    }
    @Test void addressTypesAreNotFilteredButShapeAndPortAreChecked() {
        assertNotNull(DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,new byte[]{127,0,0,1},1,1,NOW));
        for(int port:new int[]{0,65536,-1})reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,IP,port,1,NOW));
        reject(DiscoveryStatus.INVALID,()->DiscoveryRecord.issue(GROUP,secret(1),HANDSHAKE,new byte[16],1,1,NOW));
    }
    @Test void publicArraysAndDiagnosticTextDoNotExposeMutableRecordState() {
        var value=record(1,1,NOW);byte[] original=value.encode();value.encode()[0]^=1;value.payload()[0]^=1;
        value.identityKey()[0]^=1;value.signature()[0]^=1;value.ipv4()[0]^=1;
        assertArrayEquals(original,value.encode());assertEquals("DHT discovery record",value.toString());
    }
}
