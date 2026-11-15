// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.CotRecord;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionPacket;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncWire;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** 核 C2: DHT の線の形（SyncEnvelope 項目 9。schema 2）。厳しく読み、正規の形で書く。 */
class DhtWireTest {
    static byte[] fill(int length,int value){byte[] bytes=new byte[length];Arrays.fill(bytes,(byte)value);return bytes;}
    static final byte[] GROUP=fill(32,7);
    static final byte[] REQUEST=fill(16,9);
    static final long NOW=Instant.parse("2026-11-12T00:00:00Z").toEpochMilli();
    static CotRecord cot() {
        long stale=NOW+60000;
        byte[] author=new byte[32];author[0]=1;
        String xml="<event version=\"2.0\" uid=\"test\" type=\"a-f-G\" time=\"2026-11-12T00:00:00Z\" start=\"2026-11-12T00:00:00Z\" stale=\""+Instant.ofEpochMilli(stale)+"\" how=\"h-e\"><point lat=\"0\" lon=\"0\" hae=\"9999999\" ce=\"9999999\" le=\"9999999\"/><detail/></event>";
        return CotRecord.record("test",NOW,author,stale,xml.getBytes(StandardCharsets.UTF_8),1);
    }
    static DhtId id(int value){return new DhtId(fill(32,value));}
    static DhtWire.NodeContact contact(int n){return new DhtWire.NodeContact(id(n),fill(32,n+1),new byte[]{10,0,0,(byte)n},40000+n);}
    static byte[] wrap(SyncSchema.DhtEnvelope envelope){
        return SyncSchema.SyncEnvelope.newBuilder().setSchema(2).setDht(envelope).build().toByteArray();
    }
    static SyncSchema.DhtEnvelope.Builder base(){
        return SyncSchema.DhtEnvelope.newBuilder().setSchema(1).setGroupId(ByteString.copyFrom(GROUP)).setRequestId(ByteString.copyFrom(REQUEST));
    }
    static byte[] pingWith(java.util.function.UnaryOperator<SyncSchema.DhtEnvelope.Builder> change){
        return wrap(change.apply(base().setOperation(SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance())).build());
    }
    static void rejected(byte[] wire){
        var failure=assertThrows(IllegalArgumentException.class,()->DhtWire.parse(wire));
        assertEquals("DHTのメッセージの形式が違います",failure.getMessage());
    }

    @Test void everyOperationRoundTrips() {
        var ping=DhtWire.parse(DhtWire.ping(GROUP,REQUEST));
        assertEquals(DhtWire.Op.PING,ping.op());assertArrayEquals(GROUP,ping.groupId());assertArrayEquals(REQUEST,ping.requestId());
        assertEquals(DhtWire.Op.PONG,DhtWire.parse(DhtWire.pong(GROUP,REQUEST)).op());
        var findNode=DhtWire.parse(DhtWire.findNode(GROUP,REQUEST,id(3),1));
        assertEquals(DhtWire.Op.FIND_NODE,findNode.op());assertEquals(id(3),findNode.target());assertEquals(1,findNode.page());
        var nodes=DhtWire.parse(DhtWire.nodes(GROUP,REQUEST,id(3),0,true,List.of(contact(1),contact(2))));
        assertEquals(DhtWire.Op.NODES,nodes.op());assertEquals(id(3),nodes.target());assertEquals(0,nodes.page());assertTrue(nodes.last());
        assertEquals(2,nodes.contacts().size());assertEquals(id(2),nodes.contacts().get(1).node());
        assertArrayEquals(new byte[]{10,0,0,2},nodes.contacts().get(1).ipv4());assertEquals(40002,nodes.contacts().get(1).port());
        assertArrayEquals(fill(32,3),nodes.contacts().get(1).handshakeKey());
        var findValue=DhtWire.parse(DhtWire.findValue(GROUP,REQUEST,id(4)));
        assertEquals(DhtWire.Op.FIND_VALUE,findValue.op());assertEquals(id(4),findValue.target());
        byte[] record=fill(100,5);
        var value=DhtWire.parse(DhtWire.value(GROUP,REQUEST,id(4),record));
        assertEquals(DhtWire.Op.VALUE,value.op());assertArrayEquals(record,value.record());
        var store=DhtWire.parse(DhtWire.store(GROUP,REQUEST,id(4),record));
        assertEquals(DhtWire.Op.STORE,store.op());assertArrayEquals(record,store.record());assertEquals(id(4),store.target());
        for(var status:DhtWire.StoreStatus.values()) {
            var result=DhtWire.parse(DhtWire.storeResult(GROUP,REQUEST,id(4),status));
            assertEquals(DhtWire.Op.STORE_RESULT,result.op());assertEquals(status,result.status());
        }
    }
    @Test void transferAndAckRoundTrip() {
        byte[] transferId=fill(16,2),digest=fill(32,3),piece=fill(1024,4);
        var transfer=DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,transferId,digest,2048+10,2,3,fill(10,4)));
        assertEquals(DhtWire.Op.TRANSFER,transfer.op());assertEquals(DhtWire.TransferKind.STORE,transfer.transferKind());
        assertArrayEquals(transferId,transfer.transferId());assertArrayEquals(digest,transfer.digest());
        assertEquals(2058,transfer.totalBytes());assertEquals(2,transfer.index());assertEquals(3,transfer.count());
        assertArrayEquals(fill(10,4),transfer.piece());assertArrayEquals(transferId,transfer.requestId());
        var first=DhtWire.parse(DhtWire.transfer(GROUP,DhtWire.TransferKind.VALUE,transferId,digest,2058,0,3,piece));
        assertEquals(DhtWire.TransferKind.VALUE,first.transferKind());assertArrayEquals(piece,first.piece());
        var ack=DhtWire.parse(DhtWire.transferAck(GROUP,transferId,digest,3,new byte[]{5}));
        assertEquals(DhtWire.Op.TRANSFER_ACK,ack.op());assertEquals(3,ack.count());assertArrayEquals(new byte[]{5},ack.received());
        assertArrayEquals(digest,ack.digest());assertArrayEquals(transferId,ack.transferId());
    }
    @Test void isDhtLooksOnlyAtTheSchemaAndBodyTags() {
        assertTrue(DhtWire.isDht(DhtWire.ping(GROUP,REQUEST)));
        assertTrue(DhtWire.isDht(DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,fill(16,2),fill(32,3),10,0,1,fill(10,4))));
        assertFalse(DhtWire.isDht(null));assertFalse(DhtWire.isDht(new byte[0]));assertFalse(DhtWire.isDht(new byte[]{8,2}));
        assertFalse(DhtWire.isDht(SyncWire.ack(cot())));
        assertFalse(DhtWire.isDht(SyncWire.encode(cot())));
    }
    @Test void cotAndDhtDoNotParseEachOther() {
        byte[] dht=DhtWire.ping(GROUP,REQUEST);
        var failure=assertThrows(IllegalArgumentException.class,()->SyncWire.parse(dht));
        assertEquals("同期のメッセージの形式が違います",failure.getMessage());
        rejected(SyncWire.ack(cot()));
        rejected(SyncWire.encode(cot()));
    }
    @Test void schemaAndBodyMixesAreRefused() {
        var envelope=base().setOperation(SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance()).build();
        for(int schema:new int[]{0,1,3,4})rejected(SyncSchema.SyncEnvelope.newBuilder().setSchema(schema).setDht(envelope).build().toByteArray());
        var record=SyncWire.parse(SyncWire.encode(cot()));
        rejected(record.toBuilder().setSchema(2).build().toByteArray());
        rejected(SyncSchema.SyncEnvelope.newBuilder().setSchema(2).build().toByteArray());
        rejected(SyncSchema.SyncEnvelope.newBuilder().setSchema(2).setAck(SyncSchema.SyncAck.getDefaultInstance()).build().toByteArray());
        rejected(base().build().toByteArray());
        rejected(wrap(base().setSchema(2).setOperation(SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance()).build()));
        rejected(wrap(base().setSchema(0).setOperation(SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance()).build()));
    }
    @Test void headerFieldsAreChecked() {
        rejected(pingWith(b->b.setGroupId(ByteString.copyFrom(fill(31,1)))));
        rejected(pingWith(b->b.setGroupId(ByteString.EMPTY)));
        rejected(pingWith(b->b.setRequestId(ByteString.copyFrom(fill(15,1)))));
        rejected(pingWith(b->b.setRequestId(ByteString.copyFrom(fill(17,1)))));
        rejected(pingWith(b->b.setOperation(SyncSchema.DhtOperation.DHT_PONG)));
        rejected(pingWith(b->b.setOperation(SyncSchema.DhtOperation.DHT_OPERATION_UNSPECIFIED)));
        rejected(pingWith(b->b.setOperationValue(99)));
        rejected(pingWith(b->b.clearOperation()));
    }
    @Test void bodiesAreChecked() {
        byte[] t=fill(32,3);
        // 検査器: 範囲外のページ・長さ違いの対象
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_FIND_NODE).setFindNode(SyncSchema.DhtFindNode.newBuilder().setTarget(ByteString.copyFrom(t)).setPage(2)).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_FIND_NODE).setFindNode(SyncSchema.DhtFindNode.newBuilder().setTarget(ByteString.copyFrom(fill(31,3)))).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_FIND_VALUE).setFindValue(SyncSchema.DhtFindValue.newBuilder().setKey(ByteString.copyFrom(fill(33,3)))).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_FIND_VALUE).setFindValue(SyncSchema.DhtFindValue.getDefaultInstance()).build()));
        // 記録の上限
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_STORE).setStore(SyncSchema.DhtStore.newBuilder().setKey(ByteString.copyFrom(t)).setSignedRecord(ByteString.copyFrom(fill(769,1)))).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_STORE).setStore(SyncSchema.DhtStore.newBuilder().setKey(ByteString.copyFrom(t))).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_VALUE).setValue(SyncSchema.DhtValue.newBuilder().setKey(ByteString.copyFrom(t)).setSignedRecord(ByteString.copyFrom(fill(769,1)))).build()));
        // 結果の状態
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_STORE_RESULT).setStoreResult(SyncSchema.DhtStoreResult.newBuilder().setKey(ByteString.copyFrom(t))).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_STORE_RESULT).setStoreResult(SyncSchema.DhtStoreResult.newBuilder().setKey(ByteString.copyFrom(t)).setStatusValue(77)).build()));
    }
    @Test void nodesContactsAreChecked() {
        byte[] t=fill(32,3);
        java.util.function.Function<SyncSchema.DhtNodeContact.Builder,byte[]> with=c->wrap(base().setOperation(SyncSchema.DhtOperation.DHT_NODES)
            .setNodes(SyncSchema.DhtNodes.newBuilder().setTarget(ByteString.copyFrom(t)).addContacts(c)).build());
        java.util.function.Supplier<SyncSchema.DhtNodeContact.Builder> good=()->SyncSchema.DhtNodeContact.newBuilder()
            .setNodeId(ByteString.copyFrom(fill(32,1))).setHandshakeKey(ByteString.copyFrom(fill(32,2))).setIpv4(ByteString.copyFrom(new byte[]{10,0,0,1})).setPort(5000);
        assertEquals(1,DhtWire.parse(with.apply(good.get())).contacts().size());
        rejected(with.apply(good.get().setPort(0)));
        rejected(with.apply(good.get().setPort(65536)));
        rejected(with.apply(good.get().setIpv4(ByteString.copyFrom(new byte[]{10,0,0}))));
        rejected(with.apply(good.get().setNodeId(ByteString.copyFrom(fill(31,1)))));
        rejected(with.apply(good.get().setHandshakeKey(ByteString.copyFrom(fill(33,1)))));
        var many=SyncSchema.DhtNodes.newBuilder().setTarget(ByteString.copyFrom(t));
        for(int i=0;i<10;i++)many.addContacts(good.get());
        assertEquals(10,DhtWire.parse(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_NODES).setNodes(many).build())).contacts().size());
        many.addContacts(good.get());
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_NODES).setNodes(many).build()));
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_NODES).setNodes(SyncSchema.DhtNodes.newBuilder().setTarget(ByteString.copyFrom(t)).setPage(2)).build()));
    }
    @Test void transferFieldsAreChecked() {
        byte[] tid=fill(16,2),digest=fill(32,3);
        java.util.function.Function<SyncSchema.DhtTransfer.Builder,byte[]> with=transfer->wrap(base().setRequestId(ByteString.copyFrom(tid))
            .setOperation(SyncSchema.DhtOperation.DHT_TRANSFER).setTransfer(transfer).build());
        java.util.function.Supplier<SyncSchema.DhtTransfer.Builder> good=()->SyncSchema.DhtTransfer.newBuilder().setOperation(SyncSchema.DhtTransferKind.DHT_TRANSFER_STORE)
            .setTransferId(ByteString.copyFrom(tid)).setDigest(ByteString.copyFrom(digest)).setTotalBytes(2058).setIndex(1).setCount(3).setPiece(ByteString.copyFrom(fill(1024,1)));
        assertEquals(1,DhtWire.parse(with.apply(good.get())).index());
        rejected(with.apply(good.get().clearOperation()));
        rejected(with.apply(good.get().setOperationValue(9)));
        rejected(with.apply(good.get().setTransferId(ByteString.copyFrom(fill(15,2)))));
        rejected(with.apply(good.get().setDigest(ByteString.copyFrom(fill(31,3)))));
        rejected(with.apply(good.get().setTotalBytes(0)));
        rejected(with.apply(good.get().setTotalBytes(DhtWire.MAX_TRANSFER_BYTES+1)));
        rejected(with.apply(good.get().setCount(2)));             // 2058 バイトには 3 断片が要る
        rejected(with.apply(good.get().setCount(4)));
        rejected(with.apply(good.get().setIndex(3)));             // index は count 未満
        rejected(with.apply(good.get().setPiece(ByteString.copyFrom(fill(1023,1)))));  // 途中の断片は 1024 バイト
        rejected(with.apply(good.get().setIndex(2).setPiece(ByteString.copyFrom(fill(11,1)))));   // 最後は 2058-2048=10 バイト
        rejected(with.apply(good.get().setIndex(2).setPiece(ByteString.EMPTY)));
        assertEquals(10,DhtWire.parse(with.apply(good.get().setIndex(2).setPiece(ByteString.copyFrom(fill(10,1))))).piece().length);
        // request_id は transfer_id と同じ
        rejected(wrap(base().setOperation(SyncSchema.DhtOperation.DHT_TRANSFER).setTransfer(good.get()).build()));
        // 最大: 3 MiB + 4096 バイトは 3076 断片
        var biggest=good.get().setTotalBytes(DhtWire.MAX_TRANSFER_BYTES).setCount(3076).setIndex(3075);
        assertEquals(3076,DhtWire.parse(with.apply(biggest.setPiece(ByteString.copyFrom(fill(1024,1))))).count());
    }
    @Test void ackFieldsAreChecked() {
        byte[] tid=fill(16,2),digest=fill(32,3);
        java.util.function.Function<SyncSchema.DhtTransferAck.Builder,byte[]> with=ack->wrap(base().setRequestId(ByteString.copyFrom(tid))
            .setOperation(SyncSchema.DhtOperation.DHT_TRANSFER_ACK).setTransferAck(ack).build());
        java.util.function.Supplier<SyncSchema.DhtTransferAck.Builder> good=()->SyncSchema.DhtTransferAck.newBuilder()
            .setTransferId(ByteString.copyFrom(tid)).setDigest(ByteString.copyFrom(digest)).setCount(10).setReceived(ByteString.copyFrom(new byte[]{(byte)0xff,3}));
        assertEquals(10,DhtWire.parse(with.apply(good.get())).count());
        rejected(with.apply(good.get().setCount(0)));
        rejected(with.apply(good.get().setCount(3077)));
        rejected(with.apply(good.get().setReceived(ByteString.copyFrom(new byte[]{(byte)0xff}))));          // 長さが ceil(count/8) と違う
        rejected(with.apply(good.get().setReceived(ByteString.copyFrom(new byte[]{(byte)0xff,4}))));        // 最後の余りの bit が立っている
        rejected(with.apply(good.get().setTransferId(ByteString.copyFrom(fill(17,2)))));
        rejected(with.apply(good.get().setDigest(ByteString.copyFrom(fill(30,3)))));
        var biggest=good.get().setCount(3076).setReceived(ByteString.copyFrom(fill(385,0)));
        assertEquals(385,DhtWire.parse(with.apply(biggest)).received().length);
    }
    @Test void nonCanonicalAndUnknownFieldsAreRefused() {
        byte[] ping=DhtWire.ping(GROUP,REQUEST);
        rejected(Arrays.copyOf(ping,ping.length+1));
        rejected(null);rejected(new byte[0]);rejected(new byte[SessionPacket.MAX_PLAINTEXT+1]);
        // 外側（SyncEnvelope）に未知の項目 15
        byte[] extra=Arrays.copyOf(ping,ping.length+2);extra[ping.length]=0x78;extra[ping.length+1]=1;
        rejected(extra);
        // DhtEnvelope の中に未知の項目 15
        var unknown=base().setOperation(SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance()).build();
        byte[] inner=unknown.toByteArray();
        byte[] withUnknown=Arrays.copyOf(inner,inner.length+2);withUnknown[inner.length]=0x78;withUnknown[inner.length+1]=1;
        rejected(rewrap(withUnknown));
        // 本文が 2 つ
        var two=base().setOperation(SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance());
        byte[] twoBodies=concat(two.build().toByteArray(),new byte[]{0x32,0});    // 項目 6（pong）の空
        rejected(rewrap(twoBodies));
        // 項目 1 を 2 回書く
        byte[] twice=concat(new byte[]{0x08,1},inner);
        rejected(rewrap(twice));
        // 重なりを悪用した入れ子の深さ
        byte[] deep=new byte[200];Arrays.fill(deep,(byte)0x4a);
        rejected(deep);
    }
    static byte[] concat(byte[] a,byte[] b){byte[] out=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,out,a.length,b.length);return out;}
    /** DhtEnvelope の本体の線に、schema 2 の外枠を付ける。 */
    static byte[] rewrap(byte[] dhtBody){
        var buffer=new java.io.ByteArrayOutputStream();
        try{
            var stream=com.google.protobuf.CodedOutputStream.newInstance(buffer);
            stream.writeUInt32(1,2);stream.writeByteArray(9,dhtBody);stream.flush();
        }catch(java.io.IOException failed){throw new AssertionError(failed);}
        return buffer.toByteArray();
    }

    @Test void largestMessagesFitInOneDataPacket() {
        byte[] transfer=DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,fill(16,2),fill(32,3),DhtWire.MAX_TRANSFER_BYTES,3075,3076,fill(1024,1));
        assertTrue(transfer.length<=SessionPacket.MAX_PLAINTEXT,"transfer "+transfer.length);
        assertTrue(transfer.length>1100&&transfer.length<1176,"transfer "+transfer.length);
        List<DhtWire.NodeContact> contacts=new ArrayList<>();
        for(int i=0;i<10;i++)contacts.add(new DhtWire.NodeContact(id(i+1),fill(32,i),new byte[]{(byte)255,(byte)255,(byte)255,(byte)254},65535));
        assertTrue(DhtWire.nodes(GROUP,REQUEST,id(1),1,true,contacts).length<=SessionPacket.MAX_PLAINTEXT);
        assertTrue(DhtWire.store(GROUP,REQUEST,id(1),fill(DiscoveryRecord.MAX_BYTES,1)).length<=SessionPacket.MAX_PLAINTEXT);
        assertTrue(DhtWire.value(GROUP,REQUEST,id(1),fill(DiscoveryRecord.MAX_BYTES,1)).length<=SessionPacket.MAX_PLAINTEXT);
        assertEquals(SessionPacket.MAX_PLAINTEXT,DhtWire.MAX_BYTES);
        assertEquals(3076*1024,DhtWire.MAX_TRANSFER_BYTES);
    }
    @Test void encodersRefuseInvalidArguments() {
        assertThrows(IllegalArgumentException.class,()->DhtWire.ping(fill(31,1),REQUEST));
        assertThrows(IllegalArgumentException.class,()->DhtWire.ping(GROUP,fill(15,1)));
        assertThrows(IllegalArgumentException.class,()->DhtWire.findNode(GROUP,REQUEST,id(1),2));
        assertThrows(IllegalArgumentException.class,()->DhtWire.store(GROUP,REQUEST,id(1),fill(769,1)));
        List<DhtWire.NodeContact> eleven=new ArrayList<>();for(int i=0;i<11;i++)eleven.add(contact(i+1));
        assertThrows(IllegalArgumentException.class,()->DhtWire.nodes(GROUP,REQUEST,id(1),0,true,eleven));
        assertThrows(IllegalArgumentException.class,()->DhtWire.transfer(GROUP,DhtWire.TransferKind.STORE,fill(16,2),fill(32,3),2058,0,3,fill(10,1)));
        assertThrows(IllegalArgumentException.class,()->new DhtWire.NodeContact(id(1),fill(32,1),new byte[]{1,2,3,4},0));
    }
    @Test void parsedObjectsNeverPrintTheirContents() {
        var message=DhtWire.parse(DhtWire.nodes(GROUP,REQUEST,id(3),0,true,List.of(contact(1))));
        assertEquals("DHT message",message.toString());
        assertEquals("DHT node contact",message.contacts().get(0).toString());
    }
    @Test void anyBytesAreRejectedOrParsedWithoutOtherExceptions() {
        var random=new java.util.Random(12345);
        byte[] valid=DhtWire.nodes(GROUP,REQUEST,id(3),0,true,List.of(contact(1),contact(2)));
        for(int i=0;i<3000;i++) {
            byte[] mutated=valid.clone();
            int changes=1+random.nextInt(3);
            for(int j=0;j<changes;j++)mutated[random.nextInt(mutated.length)]=(byte)random.nextInt(256);
            if(random.nextInt(5)==0)mutated=Arrays.copyOf(mutated,random.nextInt(mutated.length));
            try{DhtWire.parse(mutated);}catch(IllegalArgumentException refused){assertEquals("DHTのメッセージの形式が違います",refused.getMessage());}
        }
    }
}
