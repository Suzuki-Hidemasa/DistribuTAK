// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.time.Instant;

/** RFC 6238、SHA-256、30秒、8桁。計算用の API は任意の空でない鍵を受ける。 */
public final class Totp {
    private Totp() {}
    public static String generate(byte[] secret, Instant time) { return atStep(secret,Math.floorDiv(time.getEpochSecond(),30)); }
    static String atStep(byte[] secret, long step) {
        byte[] code=atStepBytes(secret,step);
        try { return new String(code,java.nio.charset.StandardCharsets.US_ASCII); } finally { Crypto.wipe(code); }
    }
    static byte[] atStepBytes(byte[] secret, long step) {
        if(secret.length==0 || step<0) throw new IllegalArgumentException("TOTP の鍵か時刻が範囲外です");
        byte[] mac=Crypto.hmacSha256(secret,ByteBuffer.allocate(8).putLong(step).array());
        try {
            int offset=mac[31]&15;
            int binary=((mac[offset]&127)<<24)|((mac[offset+1]&255)<<16)|((mac[offset+2]&255)<<8)|(mac[offset+3]&255);
            int value=binary%100_000_000; byte[] code=new byte[8];
            for(int i=7;i>=0;i--) { code[i]=(byte)('0'+value%10); value/=10; }
            return code;
        } finally { Crypto.wipe(mac); }
    }
}
