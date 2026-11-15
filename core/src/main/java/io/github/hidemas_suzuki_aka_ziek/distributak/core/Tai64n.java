// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.time.Instant;

/** WireGuard と同じ Unix 秒 + 定数。うるう秒の表は持たない。 */
public final class Tai64n {
    private static final long OFFSET=0x400000000000000aL;
    private Tai64n() {}
    public static byte[] encode(Instant time) {
        return ByteBuffer.allocate(12).putLong(Math.addExact(time.getEpochSecond(),OFFSET)).putInt(time.getNano()).array();
    }
    public static Instant decode(byte[] value) {
        Crypto.length(value,12); var bytes=ByteBuffer.wrap(value); long seconds=bytes.getLong(); int nanos=bytes.getInt();
        if(nanos<0 || nanos>=1_000_000_000) throw new IllegalArgumentException("TAI64N のナノ秒が範囲外です");
        try { return Instant.ofEpochSecond(Math.subtractExact(seconds,OFFSET),nanos); }
        catch(RuntimeException e) { throw new IllegalArgumentException("TAI64N の秒が範囲外です",e); }
    }
}
