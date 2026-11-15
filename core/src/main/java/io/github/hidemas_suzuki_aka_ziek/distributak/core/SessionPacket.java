// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * 第5段のパケット形式。数値はビッグエンディアン。ソケットは持たない。
 * 1232バイトはIPv6の基本ヘッダーとUDPだけを引いた上限で、拡張ヘッダーやトンネルは含まない。
 * DATAの平文は1176バイトまで。超える中身は分割せず断る（答え155）。
 */
public final class SessionPacket {
    public static final int FIRST=1,SECOND=2,DATA=3;
    public static final int HEADER_SIZE=40,MAX_SIZE=1232,MAX_PLAINTEXT=MAX_SIZE-HEADER_SIZE-16;
    private static final int MAGIC=0x44544b01; // DTK と形式の版 1
    private final int kind;
    private final byte[] id,body;
    private final long version,counter;
    public SessionPacket(int kind,byte[] id,long version,long counter,byte[] body) {
        Crypto.length(id,16);
        if(kind<FIRST || kind>DATA || version<0 || kind!=DATA && counter!=0
                || body==null || body.length>MAX_SIZE-HEADER_SIZE
                || body.length<(kind==FIRST ? 108 : kind==SECOND ? 60 : 16))
            throw new IllegalArgumentException("セッションのパケットの形が違います");
        this.kind=kind;this.id=id.clone();this.version=version;this.counter=counter;this.body=body.clone();
    }
    public int kind() { return kind; }
    public byte[] id() { return id.clone(); }
    public long version() { return version; }
    public long counter() { return counter; }
    public byte[] body() { return body.clone(); }
    public byte[] header() { return header(kind,id,version,counter); }
    static byte[] header(int kind,byte[] id,long version,long counter) {
        return ByteBuffer.allocate(HEADER_SIZE).putInt(MAGIC).putInt(kind).put(id).putLong(version).putLong(counter).array();
    }
    public byte[] encode() { return Crypto.concat(header(),body); }
    public static SessionPacket decode(byte[] wire) {
        if(wire==null || wire.length<HEADER_SIZE || wire.length>MAX_SIZE)
            throw new IllegalArgumentException("セッションのパケットの長さが範囲外です");
        var in=ByteBuffer.wrap(wire);
        if(in.getInt()!=MAGIC) throw new IllegalArgumentException("セッションの形式の版が違います");
        int kind=in.getInt();byte[] id=new byte[16];in.get(id);long version=in.getLong(),counter=in.getLong();
        return new SessionPacket(kind,id,version,counter,Arrays.copyOfRange(wire,HEADER_SIZE,wire.length));
    }
}
