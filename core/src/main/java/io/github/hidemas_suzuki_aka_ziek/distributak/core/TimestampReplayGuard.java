// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;

/** 相手の X25519 公開鍵ごとの最新の値。証明書の検査後に commit する。 */
public final class TimestampReplayGuard {
    private final Map<String,byte[]> newest=new HashMap<>();
    public synchronized void check(byte[] peer, byte[] timestamp) {
        Crypto.length(peer,32); Tai64n.decode(timestamp);
        String id=Hex.toHexString(peer); byte[] previous=newest.get(id);
        if(previous!=null && compareTimestamp(timestamp,previous)<=0) throw new SecurityException("時刻が古いか同じです");
    }
    public synchronized void commit(byte[] peer, byte[] timestamp) {
        check(peer,timestamp);newest.put(Hex.toHexString(peer),timestamp.clone());
    }
    /** 既存の呼び出し用。証明書を検査してから使う。 */
    public synchronized void accept(byte[] peer, byte[] timestamp) { commit(peer,timestamp); }
    /** 相手を忘れる上位の操作から呼ぶ。消した相手の古い握手を再び受け得る。 */
    public synchronized void remove(byte[] peer) { Crypto.length(peer,32);newest.remove(Hex.toHexString(peer)); }
    // TAI64N は検証済みの12バイト。同じ長さの符号なし・辞書順で比べる。
    private static int compareTimestamp(byte[] left, byte[] right) {
        for(int i=0;i<12;i++) {
            int difference=(left[i]&255)-(right[i]&255);
            if(difference!=0) return difference;
        }
        return 0;
    }
}
