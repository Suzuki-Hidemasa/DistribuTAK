// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.util.*;

/** DTJ版1。認証は組み立てたJoinPacketに対して既存の核が行う。 */
final class JoinWire {
    static final int HEADER=64,MAX=1232,CHUNK=1168,REQUEST=1,READY=2,FETCH=3,DATA=4;
    private JoinWire() {}
    static boolean isJoin(byte[] wire) { return wire!=null&&wire.length>=4&&wire[0]=='D'&&wire[1]=='T'&&wire[2]=='J'&&wire[3]==1; }
    record Frame(int kind,byte[] invitation,byte[] transfer,int index,int total,byte[] body) implements AutoCloseable {
        @Override public void close() { Crypto.wipe(invitation);Crypto.wipe(transfer);Crypto.wipe(body); }
        @Override public String toString() { return "JoinFrame"; }
    }
    static Frame decode(byte[] wire) {
        if(wire==null||wire.length<HEADER||wire.length>MAX||!isJoin(wire)) throw invalid();
        ByteBuffer in=ByteBuffer.wrap(wire);in.position(4);int kind=in.get()&255;
        if(in.get()!=0||(in.getShort()&65535)!=wire.length||kind<REQUEST||kind>DATA) throw invalid();
        byte[] id=new byte[32],transfer=new byte[16];in.get(id);in.get(transfer);int index=in.getInt(),total=in.getInt();
        if(index<0||total<=0||total>JoinHandshake.MAX_RESPONSE_BYTES) throw invalid();
        int count=count(total),body=wire.length-HEADER;
        if(kind==REQUEST&&(index!=0||total!=body||body>CHUNK) || kind==READY&&(index!=0||body!=0)
                || kind==FETCH&&(wire.length!=MAX||index>=count)
                || kind==DATA&&(index>=count||body!=Math.min(CHUNK,total-index*CHUNK))) throw invalid();
        if(kind==FETCH) for(int i=HEADER;i<wire.length;i++) if(wire[i]!=0) throw invalid();
        return new Frame(kind,id,transfer,index,total,Arrays.copyOfRange(wire,HEADER,wire.length));
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("入るための枠が違います"); }
    static int count(int total) { return (total+CHUNK-1)/CHUNK; }
    private static byte[] encode(int kind,byte[] id,byte[] transfer,int index,int total,byte[] body) {
        Crypto.length(id,32);Crypto.length(transfer,16);
        byte[] wire=new byte[HEADER+body.length];
        ByteBuffer.wrap(wire).put(new byte[]{'D','T','J',1}).put((byte)kind).put((byte)0).putShort((short)wire.length)
                .put(id).put(transfer).putInt(index).putInt(total).put(body);
        try(var checked=decode(wire)) { return wire; } catch(RuntimeException e) { Crypto.wipe(wire);throw e; }
    }
    static byte[] request(byte[] id,byte[] transfer,byte[] packet) { return encode(REQUEST,id,transfer,0,packet.length,packet); }
    static byte[] ready(byte[] id,byte[] transfer,int total) { return encode(READY,id,transfer,0,total,new byte[0]); }
    static byte[] fetch(byte[] id,byte[] transfer,int total,int index) { return encode(FETCH,id,transfer,index,total,new byte[CHUNK]); }
    static byte[] data(byte[] id,byte[] transfer,byte[] packet,int index) {
        if(index<0||index>=count(packet.length)) throw invalid();
        byte[] piece=Arrays.copyOfRange(packet,index*CHUNK,Math.min(packet.length,(index+1)*CHUNK));
        try { return encode(DATA,id,transfer,index,packet.length,piece); } finally { Crypto.wipe(piece); }
    }
    static final class Assembly implements AutoCloseable {
        private final byte[] bytes;
        private final BitSet received=new BitSet();
        private int pieces;
        Assembly(int total) {
            if(total<=0||total>JoinHandshake.MAX_RESPONSE_BYTES) throw invalid();bytes=new byte[total];
        }
        int count() { return JoinWire.count(bytes.length); }
        boolean add(Frame frame) {
            if(frame.kind!=DATA||frame.total!=bytes.length||frame.index<0||frame.index>=count()
                    ||frame.body.length!=Math.min(CHUNK,bytes.length-frame.index*CHUNK)) throw invalid();
            if(received.get(frame.index)) return false;
            System.arraycopy(frame.body,0,bytes,frame.index*CHUNK,frame.body.length);received.set(frame.index);pieces++;return true;
        }
        boolean complete() { return pieces==count(); }
        byte[] bytes() { return bytes; }
        @Override public void close() { Crypto.wipe(bytes);received.clear();pieces=0; }
    }
}
