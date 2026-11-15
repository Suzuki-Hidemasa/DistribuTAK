// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedInputStream;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.WireFormat;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SessionPacket;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * DHT のメッセージの線の形（核 C2。ADR 0030 答え 181）。既存の DATA の SyncEnvelope の項目 9 に載せる。
 * 外側（SyncEnvelope）の schema は 2。CoT の同期（schema 1）とは項目で分かれ、混ぜた形は断る。
 * 読むときは、決めた形（入れ子の深さ・項目の型・重ね書き・正規の符号化）だけを受ける。
 * 形が違うときの例外の文は固定で、番地・番号・鍵・メッセージの中身は出さない。
 */
public final class DhtWire {
    /** DATA の平文の最大。1 通に入らない形は作らない。 */
    public static final int MAX_BYTES=SessionPacket.MAX_PLAINTEXT;
    public static final int PIECE_BYTES=1024;
    public static final int MAX_PIECES=3076;
    public static final int MAX_TRANSFER_BYTES=MAX_PIECES*PIECE_BYTES;
    public static final int MAX_CONTACTS=10;
    public static final int ID_BYTES=32,REQUEST_BYTES=16,DIGEST_BYTES=32;
    private static final int OUTER_SCHEMA=2,INNER_SCHEMA=1;
    private static final String FIXED="DHTのメッセージの形式が違います";

    public enum Op { PING,PONG,FIND_NODE,NODES,FIND_VALUE,VALUE,STORE,STORE_RESULT,TRANSFER,TRANSFER_ACK }
    public enum StoreStatus { ACCEPTED,DUPLICATE,OLD,INVALID,FULL,UNSUPPORTED }
    public enum TransferKind { STORE,VALUE }

    /** NODES に載せる相手 1 件。番地と鍵は文字列にしない。 */
    public static final class NodeContact {
        private final DhtId node;
        private final byte[] handshakeKey,ipv4;
        private final int port;
        public NodeContact(DhtId node,byte[] handshakeKey,byte[] ipv4,int port) {
            if(node==null||handshakeKey==null||handshakeKey.length!=ID_BYTES||ipv4==null||ipv4.length!=4||port<1||port>65535)throw invalid();
            this.node=node;this.handshakeKey=handshakeKey.clone();this.ipv4=ipv4.clone();this.port=port;
        }
        public DhtId node(){return node;}
        public byte[] handshakeKey(){return handshakeKey.clone();}
        public byte[] ipv4(){return ipv4.clone();}
        public int port(){return port;}
        @Override public String toString(){return "DHT node contact";}
    }

    /** 読んだメッセージ。どの操作でも使う項目だけを持つ。 */
    public static final class Message {
        private Op op;
        private byte[] groupId,requestId;
        private DhtId target;
        private int page;
        private boolean last;
        private List<NodeContact> contacts=List.of();
        private byte[] record;
        private StoreStatus status;
        private TransferKind transferKind;
        private byte[] transferId,digest,piece,received;
        private int totalBytes,index,count;
        private Message(){}
        public Op op(){return op;}
        public byte[] groupId(){return groupId.clone();}
        public byte[] requestId(){return requestId.clone();}
        public DhtId target(){return target;}
        public int page(){return page;}
        public boolean last(){return last;}
        public List<NodeContact> contacts(){return contacts;}
        public byte[] record(){return record==null?null:record.clone();}
        public StoreStatus status(){return status;}
        public TransferKind transferKind(){return transferKind;}
        public byte[] transferId(){return transferId==null?null:transferId.clone();}
        public byte[] digest(){return digest==null?null:digest.clone();}
        public int totalBytes(){return totalBytes;}
        public int index(){return index;}
        public int count(){return count;}
        public byte[] piece(){return piece==null?null:piece.clone();}
        public byte[] received(){return received==null?null:received.clone();}
        @Override public String toString(){return "DHT message";}
    }

    private DhtWire(){}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException(FIXED);}

    /** 先頭の 3 バイト（schema=2 と項目 9）だけで DHT の線かどうかを見分ける。形の検査は parse が行う。 */
    public static boolean isDht(byte[] wire) {
        return wire!=null&&wire.length>=3&&wire[0]==0x08&&wire[1]==0x02&&wire[2]==0x4A;
    }

    // ---- 読む ----

    private enum Shape {
        ROOT(0,-1,-1,-1,-1,-1,-1,-1,2),
        DHT(0,2,2,0,2,2,2,2,2,2,2,2,2,2),
        EMPTY(),
        FIND_NODE(2,0),
        NODES(2,0,0,2),
        CONTACT(2,2,2,0),
        FIND_VALUE(2),
        VALUE(2,2),
        STORE(2,2),
        STORE_RESULT(2,0),
        TRANSFER(0,2,2,0,0,0,2),
        ACK(2,2,0,2);
        final int[] wires;
        Shape(int... wires){this.wires=wires;}
    }
    private static Shape child(Shape parent,int field) {
        if(parent==Shape.ROOT&&field==9)return Shape.DHT;
        if(parent==Shape.NODES&&field==4)return Shape.CONTACT;
        if(parent!=Shape.DHT||field<5)return null;
        switch(field) {
            case 5: case 6: return Shape.EMPTY;
            case 7: return Shape.FIND_NODE;
            case 8: return Shape.NODES;
            case 9: return Shape.FIND_VALUE;
            case 10: return Shape.VALUE;
            case 11: return Shape.STORE;
            case 12: return Shape.STORE_RESULT;
            case 13: return Shape.TRANSFER;
            default: return Shape.ACK;
        }
    }
    private static void preflight(CodedInputStream in,Shape shape,int depth) throws IOException {
        if(depth>3)throw invalid();
        int seen=0,bodies=0,contacts=0;
        while(true) {
            int tag=in.readTag();
            if(tag==0)return;
            int field=WireFormat.getTagFieldNumber(tag),type=WireFormat.getTagWireType(tag);
            if(field<1||field>shape.wires.length||shape.wires[field-1]!=type)throw invalid();
            boolean repeated=shape==Shape.NODES&&field==4;
            if(repeated) {
                if(++contacts>MAX_CONTACTS)throw invalid();
            } else {
                int bit=1<<field;
                if((seen&bit)!=0)throw invalid();
                seen|=bit;
            }
            if(shape==Shape.DHT&&field>=5&&++bodies>1)throw invalid();
            if(type==WireFormat.WIRETYPE_VARINT) {
                in.readRawVarint64();
                continue;
            }
            int length=in.readRawVarint32();
            Shape next=child(shape,field);
            if(next==null) {
                in.skipRawBytes(length);
            } else {
                int old=in.pushLimit(length);
                preflight(in,next,depth+1);
                if(in.getBytesUntilLimit()!=0)throw invalid();
                in.popLimit(old);
            }
        }
    }

    public static Message parse(byte[] wire) {
        if(wire==null||wire.length==0||wire.length>MAX_BYTES)throw invalid();
        try {
            CodedInputStream in=CodedInputStream.newInstance(wire);
            preflight(in,Shape.ROOT,0);
            if(!in.isAtEnd())throw invalid();
            SyncSchema.SyncEnvelope envelope=SyncSchema.SyncEnvelope.parseFrom(wire);
            if(envelope.getSchema()!=OUTER_SCHEMA||envelope.getBodyCase()!=SyncSchema.SyncEnvelope.BodyCase.DHT)throw invalid();
            if(!Arrays.equals(wire,envelope.toByteArray()))throw invalid();
            return check(envelope.getDht());
        } catch(InvalidProtocolBufferException malformed) {
            throw invalid();
        } catch(IOException malformed) {
            throw invalid();
        }
    }

    private static boolean length(ByteString value,int expected){return value.size()==expected;}
    private static byte[] bytes(ByteString value){return value.toByteArray();}
    private static void require(boolean condition){if(!condition)throw invalid();}
    private static int pieces(long total){return (int)((total+PIECE_BYTES-1)/PIECE_BYTES);}

    private static Message check(SyncSchema.DhtEnvelope envelope) {
        require(envelope.getSchema()==INNER_SCHEMA);
        require(length(envelope.getGroupId(),ID_BYTES)&&length(envelope.getRequestId(),REQUEST_BYTES));
        Message message=new Message();
        message.groupId=bytes(envelope.getGroupId());
        message.requestId=bytes(envelope.getRequestId());
        SyncSchema.DhtEnvelope.BodyCase body=envelope.getBodyCase();
        switch(envelope.getOperation()) {
            case DHT_PING:
                require(body==SyncSchema.DhtEnvelope.BodyCase.PING);
                message.op=Op.PING;
                break;
            case DHT_PONG:
                require(body==SyncSchema.DhtEnvelope.BodyCase.PONG);
                message.op=Op.PONG;
                break;
            case DHT_FIND_NODE: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.FIND_NODE);
                var value=envelope.getFindNode();
                require(length(value.getTarget(),ID_BYTES)&&value.getPage()<=1);
                message.op=Op.FIND_NODE;message.target=new DhtId(bytes(value.getTarget()));message.page=value.getPage();
                break;
            }
            case DHT_NODES: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.NODES);
                var value=envelope.getNodes();
                require(length(value.getTarget(),ID_BYTES)&&value.getPage()<=1&&value.getContactsCount()<=MAX_CONTACTS);
                List<NodeContact> contacts=new ArrayList<>();
                for(var contact:value.getContactsList()) {
                    require(length(contact.getNodeId(),ID_BYTES)&&length(contact.getHandshakeKey(),ID_BYTES)&&length(contact.getIpv4(),4)
                        &&contact.getPort()>=1&&contact.getPort()<=65535);
                    contacts.add(new NodeContact(new DhtId(bytes(contact.getNodeId())),bytes(contact.getHandshakeKey()),bytes(contact.getIpv4()),contact.getPort()));
                }
                message.op=Op.NODES;message.target=new DhtId(bytes(value.getTarget()));message.page=value.getPage();
                message.last=value.getLast();message.contacts=List.copyOf(contacts);
                break;
            }
            case DHT_FIND_VALUE: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.FIND_VALUE);
                var value=envelope.getFindValue();
                require(length(value.getKey(),ID_BYTES));
                message.op=Op.FIND_VALUE;message.target=new DhtId(bytes(value.getKey()));
                break;
            }
            case DHT_VALUE: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.VALUE);
                var value=envelope.getValue();
                require(length(value.getKey(),ID_BYTES)&&value.getSignedRecord().size()>=1&&value.getSignedRecord().size()<=DiscoveryRecord.MAX_BYTES);
                message.op=Op.VALUE;message.target=new DhtId(bytes(value.getKey()));message.record=bytes(value.getSignedRecord());
                break;
            }
            case DHT_STORE: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.STORE);
                var value=envelope.getStore();
                require(length(value.getKey(),ID_BYTES)&&value.getSignedRecord().size()>=1&&value.getSignedRecord().size()<=DiscoveryRecord.MAX_BYTES);
                message.op=Op.STORE;message.target=new DhtId(bytes(value.getKey()));message.record=bytes(value.getSignedRecord());
                break;
            }
            case DHT_STORE_RESULT: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.STORE_RESULT);
                var value=envelope.getStoreResult();
                require(length(value.getKey(),ID_BYTES));
                message.op=Op.STORE_RESULT;message.target=new DhtId(bytes(value.getKey()));
                switch(value.getStatus()) {
                    case DHT_STORE_ACCEPTED: message.status=StoreStatus.ACCEPTED;break;
                    case DHT_STORE_DUPLICATE: message.status=StoreStatus.DUPLICATE;break;
                    case DHT_STORE_OLD: message.status=StoreStatus.OLD;break;
                    case DHT_STORE_INVALID: message.status=StoreStatus.INVALID;break;
                    case DHT_STORE_FULL: message.status=StoreStatus.FULL;break;
                    case DHT_STORE_UNSUPPORTED: message.status=StoreStatus.UNSUPPORTED;break;
                    default: throw invalid();
                }
                break;
            }
            case DHT_TRANSFER: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.TRANSFER);
                var value=envelope.getTransfer();
                switch(value.getOperation()) {
                    case DHT_TRANSFER_STORE: message.transferKind=TransferKind.STORE;break;
                    case DHT_TRANSFER_VALUE: message.transferKind=TransferKind.VALUE;break;
                    default: throw invalid();
                }
                require(length(value.getTransferId(),REQUEST_BYTES)&&length(value.getDigest(),DIGEST_BYTES));
                require(envelope.getRequestId().equals(value.getTransferId()));
                long total=value.getTotalBytes()&0xFFFFFFFFL;
                require(total>=1&&total<=MAX_TRANSFER_BYTES);
                int count=pieces(total);
                require(value.getCount()==count);
                require(value.getIndex()>=0&&value.getIndex()<count);
                int expected=value.getIndex()<count-1?PIECE_BYTES:(int)(total-(long)(count-1)*PIECE_BYTES);
                require(value.getPiece().size()==expected);
                message.op=Op.TRANSFER;message.transferId=bytes(value.getTransferId());message.digest=bytes(value.getDigest());
                message.totalBytes=(int)total;message.index=value.getIndex();message.count=count;message.piece=bytes(value.getPiece());
                break;
            }
            case DHT_TRANSFER_ACK: {
                require(body==SyncSchema.DhtEnvelope.BodyCase.TRANSFER_ACK);
                var value=envelope.getTransferAck();
                require(length(value.getTransferId(),REQUEST_BYTES)&&length(value.getDigest(),DIGEST_BYTES));
                require(envelope.getRequestId().equals(value.getTransferId()));
                long count=value.getCount()&0xFFFFFFFFL;
                require(count>=1&&count<=MAX_PIECES);
                int size=(int)((count+7)/8);
                require(value.getReceived().size()==size);
                int spare=(int)(size*8-count);
                if(spare>0) {
                    int last=value.getReceived().byteAt(size-1)&0xFF;
                    require((last>>>(8-spare))==0);
                }
                message.op=Op.TRANSFER_ACK;message.transferId=bytes(value.getTransferId());message.digest=bytes(value.getDigest());
                message.count=(int)count;message.received=bytes(value.getReceived());
                break;
            }
            default:
                throw invalid();
        }
        return message;
    }

    // ---- 書く（書いたあとに自分で読み直して、不正なものは出さない） ----

    private static SyncSchema.DhtEnvelope.Builder header(byte[] groupId,byte[] requestId,SyncSchema.DhtOperation operation) {
        if(groupId==null||groupId.length!=ID_BYTES||requestId==null||requestId.length!=REQUEST_BYTES)throw invalid();
        return SyncSchema.DhtEnvelope.newBuilder().setSchema(INNER_SCHEMA).setGroupId(ByteString.copyFrom(groupId))
            .setRequestId(ByteString.copyFrom(requestId)).setOperation(operation);
    }
    private static byte[] finish(SyncSchema.DhtEnvelope.Builder envelope) {
        byte[] wire=SyncSchema.SyncEnvelope.newBuilder().setSchema(OUTER_SCHEMA).setDht(envelope).build().toByteArray();
        parse(wire);
        return wire;
    }
    private static ByteString id(DhtId value){return ByteString.copyFrom(Objects.requireNonNull(value).bytes());}

    public static byte[] ping(byte[] groupId,byte[] requestId) {
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_PING).setPing(SyncSchema.DhtPing.getDefaultInstance()));
    }
    public static byte[] pong(byte[] groupId,byte[] requestId) {
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_PONG).setPong(SyncSchema.DhtPong.getDefaultInstance()));
    }
    public static byte[] findNode(byte[] groupId,byte[] requestId,DhtId target,int page) {
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_FIND_NODE)
            .setFindNode(SyncSchema.DhtFindNode.newBuilder().setTarget(id(target)).setPage(page)));
    }
    public static byte[] nodes(byte[] groupId,byte[] requestId,DhtId target,int page,boolean last,List<NodeContact> contacts) {
        var body=SyncSchema.DhtNodes.newBuilder().setTarget(id(target)).setPage(page).setLast(last);
        for(NodeContact contact:Objects.requireNonNull(contacts)) {
            body.addContacts(SyncSchema.DhtNodeContact.newBuilder().setNodeId(id(contact.node)).setHandshakeKey(ByteString.copyFrom(contact.handshakeKey))
                .setIpv4(ByteString.copyFrom(contact.ipv4)).setPort(contact.port));
        }
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_NODES).setNodes(body));
    }
    public static byte[] findValue(byte[] groupId,byte[] requestId,DhtId key) {
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_FIND_VALUE).setFindValue(SyncSchema.DhtFindValue.newBuilder().setKey(id(key))));
    }
    public static byte[] value(byte[] groupId,byte[] requestId,DhtId key,byte[] signedRecord) {
        if(signedRecord==null)throw invalid();
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_VALUE)
            .setValue(SyncSchema.DhtValue.newBuilder().setKey(id(key)).setSignedRecord(ByteString.copyFrom(signedRecord))));
    }
    public static byte[] store(byte[] groupId,byte[] requestId,DhtId key,byte[] signedRecord) {
        if(signedRecord==null)throw invalid();
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_STORE)
            .setStore(SyncSchema.DhtStore.newBuilder().setKey(id(key)).setSignedRecord(ByteString.copyFrom(signedRecord))));
    }
    public static byte[] storeResult(byte[] groupId,byte[] requestId,DhtId key,StoreStatus status) {
        SyncSchema.DhtStoreStatus wire;
        switch(Objects.requireNonNull(status)) {
            case ACCEPTED: wire=SyncSchema.DhtStoreStatus.DHT_STORE_ACCEPTED;break;
            case DUPLICATE: wire=SyncSchema.DhtStoreStatus.DHT_STORE_DUPLICATE;break;
            case OLD: wire=SyncSchema.DhtStoreStatus.DHT_STORE_OLD;break;
            case INVALID: wire=SyncSchema.DhtStoreStatus.DHT_STORE_INVALID;break;
            case FULL: wire=SyncSchema.DhtStoreStatus.DHT_STORE_FULL;break;
            default: wire=SyncSchema.DhtStoreStatus.DHT_STORE_UNSUPPORTED;break;
        }
        return finish(header(groupId,requestId,SyncSchema.DhtOperation.DHT_STORE_RESULT)
            .setStoreResult(SyncSchema.DhtStoreResult.newBuilder().setKey(id(key)).setStatus(wire)));
    }
    /** request_id は transfer_id と同じ値にする。 */
    public static byte[] transfer(byte[] groupId,TransferKind kind,byte[] transferId,byte[] digest,int totalBytes,int index,int count,byte[] piece) {
        if(transferId==null||digest==null||piece==null)throw invalid();
        var body=SyncSchema.DhtTransfer.newBuilder()
            .setOperation(Objects.requireNonNull(kind)==TransferKind.STORE?SyncSchema.DhtTransferKind.DHT_TRANSFER_STORE:SyncSchema.DhtTransferKind.DHT_TRANSFER_VALUE)
            .setTransferId(ByteString.copyFrom(transferId)).setDigest(ByteString.copyFrom(digest))
            .setTotalBytes(totalBytes).setIndex(index).setCount(count).setPiece(ByteString.copyFrom(piece));
        return finish(header(groupId,transferId,SyncSchema.DhtOperation.DHT_TRANSFER).setTransfer(body));
    }
    public static byte[] transferAck(byte[] groupId,byte[] transferId,byte[] digest,int count,byte[] received) {
        if(transferId==null||digest==null||received==null)throw invalid();
        var body=SyncSchema.DhtTransferAck.newBuilder().setTransferId(ByteString.copyFrom(transferId)).setDigest(ByteString.copyFrom(digest))
            .setCount(count).setReceived(ByteString.copyFrom(received));
        return finish(header(groupId,transferId,SyncSchema.DhtOperation.DHT_TRANSFER_ACK).setTransferAck(body));
    }
}
