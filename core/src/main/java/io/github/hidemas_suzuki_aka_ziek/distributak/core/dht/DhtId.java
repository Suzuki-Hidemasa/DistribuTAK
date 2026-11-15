// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.util.Arrays;
import java.util.Objects;

/** 端末番号と記録の鍵。文字列には値を出さない。 */
public final class DhtId implements Comparable<DhtId> {
    public static final int BYTES=32;
    private final byte[] bytes;
    public DhtId(byte[] value) {
        if(value==null||value.length!=BYTES)throw new IllegalArgumentException("DHT番号の長さが違います");
        bytes=value.clone();
    }
    public static DhtId fromIdentityPublicKey(byte[] publicKey) {
        if(publicKey==null||publicKey.length!=BYTES)throw new IllegalArgumentException("身元の公開鍵の長さが違います");
        return new DhtId(Crypto.blake2s(publicKey));
    }
    public byte[] bytes(){return bytes.clone();}
    public byte[] distance(DhtId other) {
        Objects.requireNonNull(other);byte[] value=new byte[BYTES];
        for(int i=0;i<BYTES;i++)value[i]=(byte)(bytes[i]^other.bytes[i]);return value;
    }
    /** 自分との距離はバケットを持たないため-1。 */
    public int bucketIndex(DhtId other) {
        Objects.requireNonNull(other);
        for(int i=0;i<BYTES;i++) {
            int value=(bytes[i]^other.bytes[i])&255;
            if(value!=0)return (BYTES-1-i)*8+31-Integer.numberOfLeadingZeros(value);
        }
        return -1;
    }
    /** この番号をtargetとして、leftとrightの距離を比べる。 */
    public int compareDistance(DhtId left,DhtId right) {
        Objects.requireNonNull(left);Objects.requireNonNull(right);
        for(int i=0;i<BYTES;i++) {
            int a=(bytes[i]^left.bytes[i])&255,b=(bytes[i]^right.bytes[i])&255;
            if(a!=b)return Integer.compare(a,b);
        }
        return 0;
    }
    @Override public int compareTo(DhtId other) {
        Objects.requireNonNull(other);
        for(int i=0;i<BYTES;i++) {int n=Integer.compare(bytes[i]&255,other.bytes[i]&255);if(n!=0)return n;}
        return 0;
    }
    @Override public boolean equals(Object value){return value instanceof DhtId other&&Arrays.equals(bytes,other.bytes);}
    @Override public int hashCode(){return Arrays.hashCode(bytes);}
    @Override public String toString(){return "DHT identifier";}
}
