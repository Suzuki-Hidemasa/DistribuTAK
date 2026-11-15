// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.util.Arrays;

/** DTC版1。内側のDTK/DTJのバイト列は変えない。 */
final class CookieWire {
    static final int CHALLENGE=1,PROOF=2,MAX_FIRST=1184;
    private static final int MAGIC=0x44544301;
    private CookieWire() {}
    static boolean isCookie(byte[] wire) { return wire!=null&&wire.length>=3&&wire[0]=='D'&&wire[1]=='T'&&wire[2]=='C'; }
    record Frame(int kind,byte[] hash,byte[] cookie,byte[] first) implements AutoCloseable {
        public void close() { Crypto.wipe(hash);Crypto.wipe(cookie);Crypto.wipe(first); }
        public String toString() { return "CookieFrame"; }
    }
    /** 1=DTK FIRST、2=DTJ REQUEST。ほかの種類や入れ子は認めない。 */
    static int firstKind(byte[] first) {
        if(first==null||first.length>MAX_FIRST)throw invalid();
        if(JoinWire.isJoin(first)) {
            try(var frame=JoinWire.decode(first)) { if(frame.kind()!=JoinWire.REQUEST)throw invalid();return 2; }
        }
        if(SessionPacket.decode(first).kind()!=SessionPacket.FIRST)throw invalid();return 1;
    }
    static byte[] challenge(byte[] hash,byte[] cookie) {
        Crypto.length(hash,32);Crypto.length(cookie,40);
        return ByteBuffer.allocate(80).putInt(MAGIC).putInt(CHALLENGE).put(hash).put(cookie).array();
    }
    static byte[] proof(byte[] cookie,byte[] first) {
        Crypto.length(cookie,40);firstKind(first);
        return ByteBuffer.allocate(48+first.length).putInt(MAGIC).putInt(PROOF).put(cookie).put(first).array();
    }
    static Frame decode(byte[] wire) {
        if(wire==null||wire.length<8||wire.length>1232)throw invalid();
        var in=ByteBuffer.wrap(wire);if(in.getInt()!=MAGIC)throw invalid();int kind=in.getInt();
        if(kind==CHALLENGE) {
            if(wire.length!=80)throw invalid();
            return new Frame(kind,Arrays.copyOfRange(wire,8,40),Arrays.copyOfRange(wire,40,80),null);
        }
        if(kind!=PROOF||wire.length<=48)throw invalid();
        byte[] first=Arrays.copyOfRange(wire,48,wire.length);
        try { firstKind(first);return new Frame(kind,null,Arrays.copyOfRange(wire,8,48),first); }
        catch(RuntimeException e) { Crypto.wipe(first);throw e; }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("クッキーの枠が違います"); }
}
