// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class JoinMessagesFix1Test {
    // 汎用のprotobuf読み取りで各項目の位置だけを取り、1項目だけを変える材料にする。
    static List<byte[]> fields(byte[] wire) throws Exception {
        var in=CodedInputStream.newInstance(wire);List<byte[]> fields=new ArrayList<>();
        while(!in.isAtEnd()) { int start=in.getTotalBytesRead();int tag=in.readTag();assertTrue(in.skipField(tag));fields.add(Arrays.copyOfRange(wire,start,in.getTotalBytesRead())); }
        return fields;
    }
    static byte[] concatenate(List<byte[]> fields) { return Crypto.concat(fields.toArray(new byte[0][])); }
    static Map<String,byte[]> mutations(byte[] good) throws Exception {
        var parts=fields(good);Map<String,byte[]> cases=new LinkedHashMap<>();
        cases.put("知らない項目",Crypto.concat(good,new byte[]{(byte)0x98,6,1})); // field99、値1。
        var duplicate=new ArrayList<>(parts);duplicate.add(2,parts.get(1));cases.put("途中の単一項目の重複",concatenate(duplicate));
        var reordered=new ArrayList<>(parts);Collections.swap(reordered,1,2);cases.put("番号順の違い",concatenate(reordered));
        cases.put("値の整数が最短でない",Crypto.concat(new byte[]{8,(byte)(good[1]|128),0},Arrays.copyOfRange(good,2,good.length)));
        var missing=new ArrayList<>(parts);missing.remove(parts.size()/2);cases.put("途中の項目の欠け",concatenate(missing));
        cases.put("余分な末尾",Crypto.concat(good,new byte[]{0}));
        byte[] kind=good.clone();kind[1]=(byte)(good[1]+1);cases.put("違う種類",kind);
        return cases;
    }
    static void checkTable(String type,byte[] good,Consumer<byte[]> decoder) throws Exception {
        assertDoesNotThrow(()->decoder.accept(good),type+"の正しい対照");
        for(var entry:mutations(good).entrySet()) assertThrows(IllegalArgumentException.class,()->decoder.accept(entry.getValue()),type+": "+entry.getKey());
    }
    @Test void allThreeMessageTypesRejectEachSingleCanonicalFormMutation() throws Exception {
        try(var request=new JoinMessages.Request(key(1),key(2),key(3),new byte[64],new byte[]{48,49,50,51,52,53,54,55},key(4))) {
            checkTable("JoinRequest",request.encode(),wire->{try(var parsed=JoinMessages.request(wire)) { assertArrayEquals(wire,parsed.encode()); }});
        }
        var response=new JoinMessages.Response(key(1),List.of(new byte[]{1}),new byte[64],new byte[]{2},new byte[]{3},new byte[]{4});
        checkTable("JoinResponse",response.encode(),wire->assertArrayEquals(wire,JoinMessages.response(wire).encode()));
        for(boolean reply:new boolean[]{false,true}) {
            var packet=new JoinMessages.Packet(reply,key(1),key(2),new byte[16],new byte[reply ? 64 : 0]);
            checkTable(reply ? "JoinPacket返事" : "JoinPacket求め",packet.encode(),wire->assertArrayEquals(wire,JoinMessages.packet(wire,reply).encode()));
        }
    }
    static byte[] responseWire(int field,byte[] record) throws Exception {
        var buffer=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(buffer);
        out.writeUInt32(1,2);out.writeByteArray(2,key(1));out.writeByteArray(3,field==3 ? record : new byte[]{1});out.writeByteArray(4,new byte[64]);
        for(int current=5;current<=7;current++) out.writeByteArray(current,current==field ? record : new byte[]{(byte)current});
        out.flush();return buffer.toByteArray();
    }
    static JoinMessages.Response responseObject(int field,byte[] record) {
        return new JoinMessages.Response(key(1),List.of(field==3 ? record : new byte[]{1}),new byte[64],
                field==5 ? record : new byte[]{5},field==6 ? record : new byte[]{6},field==7 ? record : new byte[]{7});
    }
    @Test void eachOpaqueRecordSlotAcceptsThreeMiBAndRejectsOneMoreForSize() throws Exception {
        // ここではSignedRecord欄の長さだけを見る。中の署名の検査は加入の試験で別に行う。
        byte[] exact=new byte[AdminRecords.MAX_RECORD_BYTES], oneMore=new byte[AdminRecords.MAX_RECORD_BYTES+1];
        for(int field:new int[]{3,5,6,7}) {
            byte[] good=responseWire(field,exact), bad=responseWire(field,oneMore);
            assertTrue(bad.length<JoinMessages.MAX_RESPONSE,"全体の上限では落ちない材料");
            assertArrayEquals(good,JoinMessages.response(good).encode());assertArrayEquals(good,responseObject(field,exact).encode());
            var decode=assertThrows(IllegalArgumentException.class,()->JoinMessages.response(bad));
            var encode=assertThrows(IllegalArgumentException.class,()->responseObject(field,oneMore));
            assertTrue(decode.getMessage().contains("上限"),"欄"+field+": decodeの拒否は大きさによる");
            assertTrue(encode.getMessage().contains("上限"),"欄"+field+": 生成の拒否は大きさによる");
        }
    }
    @Test void closingPacketWipesOwnedCopiesWithoutChangingCallerArrays() throws Exception {
        byte[] id=key(1), enc=key(2), ciphertext=new byte[16], signature=new byte[64];Arrays.fill(ciphertext,(byte)7);Arrays.fill(signature,(byte)8);
        var packet=JoinMessages.packet(new JoinMessages.Packet(true,id,enc,ciphertext,signature).encode(),true);
        byte[] prefix=SecretAssertions.bytes(packet,"receivedPrefix");
        packet.close();
        SecretAssertions.zero(packet.invitation);SecretAssertions.zero(packet.enc);SecretAssertions.zero(packet.ciphertext);SecretAssertions.zero(packet.signature);SecretAssertions.zero(prefix);
        assertArrayEquals(key(1),id);assertArrayEquals(key(2),enc);assertEquals(7,ciphertext[0]);assertEquals(8,signature[0]);
    }
}
