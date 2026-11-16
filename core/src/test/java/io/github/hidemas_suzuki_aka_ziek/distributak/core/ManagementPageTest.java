// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ManagementPageTest {
    static byte[] bytes(int size,int seed){byte[] value=new byte[size];new java.util.Random(seed).nextBytes(value);return value;}
    @FunctionalInterface interface Writer {void write(CodedOutputStream out)throws IOException;}
    static byte[] wire(Writer writer){
        try{var buffer=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(buffer);writer.write(out);out.flush();return buffer.toByteArray();}
        catch(IOException impossible){throw new AssertionError(impossible);}
    }
    static ManagementPage page(){return ManagementPage.split(ManagementPage.Kind.REVOCATION,new byte[16],new byte[32],bytes(2050,1),0).get(0);}
    static byte[] envelope(int field,byte[] body){
        var management=wire(out->{out.writeUInt32(1,1);out.writeByteArray(field,body);});
        return wire(out->{out.writeUInt32(1,3);out.writeByteArray(10,management);});
    }
    static byte[] changed(ManagementPage page,int field,Object value){
        Object[] fields={null,1,page.kind().number(),page.operationId(),page.group(),page.objectDigest(),
                page.totalBytes(),page.pageIndex(),page.pageCount(),page.data(),page.totalEntries()};
        fields[field]=value;
        return wire(out->{for(int i=1;i<fields.length;i++){
            if(fields[i]==null)continue;
            if(fields[i] instanceof byte[] data)out.writeByteArray(i,data);
            else out.writeUInt32(i,(Integer)fields[i]);
        }});
    }
    @Test void allPageKindsRoundTripThroughTheirAssignedEnvelopeFields()throws Exception {
        for(var kind:ManagementPage.Kind.values()){
            var p=ManagementPage.split(kind,bytes(16,1),bytes(32,2),bytes(1025,3),32).get(0);
            assertArrayEquals(p.encode(),ManagementPage.decode(p.encode()).encode());
            assertArrayEquals(p.envelope(),ManagementPage.decodeEnvelope(p.envelope()).envelope());
            var parsed=SyncSchema.SyncEnvelope.parseFrom(p.envelope());
            assertEquals(3,parsed.getSchema());assertEquals(kind.envelopeField(),parsed.getManagement().getBodyCase().getNumber());
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decodeEnvelope(envelope(kind==ManagementPage.Kind.REVOCATION?4:3,p.encode())));
        }
    }
    @Test void largestPageIsExactly1142BytesInsideThe1176ByteEnvelopeLimit() {
        var p=new ManagementPage(ManagementPage.Kind.REVOCATION,new byte[16],new byte[32],new byte[32],
                3*1024*1024,3070,3072,new byte[1024],65536);
        assertEquals(1132,p.encode().length);assertEquals(1142,p.envelope().length);assertTrue(p.envelope().length<=1176);
    }
    @Test void allFieldsIncludingZeroAreRequiredAndUnknownOrDuplicateFieldsAreRejected() {
        var p=page();
        for(int field=1;field<=10;field++){
            final int omitted=field;
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(changed(p,omitted,null)));
        }
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(Crypto.concat(p.encode(),new byte[]{88,1})));
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(Crypto.concat(p.encode(),new byte[]{80,0})));
        byte[] nonminimal=Crypto.concat(new byte[]{8,(byte)0x81,0},Arrays.copyOfRange(p.encode(),2,p.encode().length));
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(nonminimal));
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decodeEnvelope(Crypto.concat(p.envelope(),new byte[]{96,0})));
    }
    @Test void fixedByteLengthsKindsAndAllPageBoundariesAreStrict() {
        var p=page();
        for(int field:new int[]{3,4,5}){
            final int f=field;
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(changed(p,f,new byte[f==3?15:31])));
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(changed(p,f,new byte[f==3?17:33])));
        }
        for(int[] change:new int[][]{{1,0},{1,2},{2,0},{2,5},{6,0},{6,3*1024*1024+1},{7,-1},{7,3},{8,0},{8,3073},{8,2},{10,-1},{10,65537}})
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(changed(p,change[0],change[1])));
        for(int length:new int[]{0,1023,1025})
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(changed(p,9,new byte[length])));
        var last=ManagementPage.split(p.kind(),p.operationId(),p.group(),bytes(1025,9),0).get(1);
        assertEquals(1,last.data().length);
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decode(changed(last,9,new byte[2])));
        assertEquals(3072,ManagementPage.split(p.kind(),p.operationId(),p.group(),new byte[3*1024*1024],65536).size());
        assertThrows(IllegalArgumentException.class,()->ManagementPage.split(p.kind(),p.operationId(),p.group(),new byte[0],0));
    }
    @Test void reservedUnknownOrMixedBodiesAndSchemasAreRejected() {
        var p=page();
        for(int field:new int[]{2,6,8,9,10,11,12})
            assertThrows(IllegalArgumentException.class,()->ManagementPage.decodeEnvelope(envelope(field,p.encode())));
        byte[] wrong=p.envelope();wrong[1]=2;
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decodeEnvelope(wrong));
        byte[] mixed=wire(out->{out.writeUInt32(1,1);out.writeByteArray(3,p.encode());out.writeByteArray(4,p.encode());});
        assertThrows(IllegalArgumentException.class,()->ManagementPage.decodeEnvelope(wire(out->{out.writeUInt32(1,3);out.writeByteArray(10,mixed);})));
    }
    @Test void ackIsCanonicalPackedAndContainsOneToFourSortedDistinctIndices()throws Exception {
        var ack=new ManagementPageAck(bytes(32,1),bytes(16,2),bytes(32,3),new int[]{0,127,128,3071},false);
        assertArrayEquals(ack.encode(),ManagementPageAck.decode(ack.encode()).encode());
        assertArrayEquals(ack.envelope(),ManagementPageAck.decodeEnvelope(ack.envelope()).envelope());
        assertEquals(11,SyncSchema.SyncEnvelope.parseFrom(ack.envelope()).getManagement().getBodyCase().getNumber());
        for(int[] bad:new int[][]{{},{0,1,2,3,4},{0,0},{2,1},{-1},{3072}})
            assertThrows(IllegalArgumentException.class,()->new ManagementPageAck(new byte[32],new byte[16],new byte[32],bad,false));
        assertThrows(IllegalArgumentException.class,()->new ManagementPageAck(new byte[31],new byte[16],new byte[32],new int[]{0},false));
        assertThrows(IllegalArgumentException.class,()->new ManagementPageAck(new byte[32],new byte[15],new byte[32],new int[]{0},false));
        assertThrows(IllegalArgumentException.class,()->new ManagementPageAck(new byte[32],new byte[16],new byte[31],new int[]{0},false));
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(Crypto.concat(ack.encode(),new byte[]{48,0})));
        var unpacked=wire(out->{out.writeUInt32(1,1);out.writeByteArray(2,new byte[32]);out.writeByteArray(3,new byte[16]);out.writeByteArray(4,new byte[32]);out.writeUInt32(5,0);});
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decode(unpacked));
        assertThrows(IllegalArgumentException.class,()->ManagementPageAck.decodeEnvelope(envelope(6,ack.encode())));
    }
    @Test void byteArraysAreDefensivelyCopiedAndStringsRevealNoContents() {
        var p=page();byte[] encoded=p.encode();p.data()[0]^=1;p.operationId()[0]^=1;p.group()[0]^=1;p.objectDigest()[0]^=1;
        assertArrayEquals(encoded,p.encode());assertEquals("Management page",p.toString());
        int[] indices={0};var ack=new ManagementPageAck(new byte[32],new byte[16],new byte[32],indices,false);
        indices[0]=5;ack.pageIndices()[0]=4;assertArrayEquals(new int[]{0},ack.pageIndices());
        assertEquals("Management page acknowledgement",ack.toString());
    }
    @Test void existingRenewalAndAdministrationParsersContinueToRefuseEveryNewBody() {
        for(var kind:ManagementPage.Kind.values()){
            var p=ManagementPage.split(kind,new byte[16],new byte[32],new byte[]{1},0).get(0);
            assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(p.envelope()));
            assertThrows(IllegalArgumentException.class,()->AdminControl.decode(p.envelope()));
        }
        var ack=new ManagementPageAck(new byte[32],new byte[16],new byte[32],new int[]{0},false);
        assertThrows(IllegalArgumentException.class,()->RenewalMessage.decode(ack.envelope()));
        assertThrows(IllegalArgumentException.class,()->AdminControl.decode(ack.envelope()));
    }
}
