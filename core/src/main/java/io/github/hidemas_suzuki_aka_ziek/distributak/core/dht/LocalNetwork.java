// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.Arrays;

/**
 * 自分の IPv4 の番地と接頭辞の長さ。DHT で知った番地のうち、使ってよいのは自分と同じサブネットの別の端末だけ
 * （答え 181 の 8・(g)）。plugin が値で渡し、核はネットワークの情報を取りに行かない。接頭辞が分からない・/0・/31・/32 のときは何も使わない。
 */
public final class LocalNetwork {
    public static final int UNKNOWN_PREFIX=-1;
    private final byte[] self;
    private final int prefix;
    public LocalNetwork(byte[] ipv4,int prefixLength) {
        if(ipv4==null||ipv4.length!=4||prefixLength<UNKNOWN_PREFIX||prefixLength>32)throw new IllegalArgumentException("Invalid local network");
        self=ipv4.clone();prefix=prefixLength;
    }
    /** /1〜/30 だけ使う。分からない・/0・/31・/32 は使わない。 */
    public boolean usable(){return prefix>=1&&prefix<=30;}
    public boolean allows(byte[] ipv4,int port) {
        if(!usable()||ipv4==null||ipv4.length!=4||port<1||port>65535)return false;
        int address=toInt(ipv4),own=toInt(self),mask=-1<<(32-prefix);
        if(address==own||(address&mask)!=(own&mask))return false;
        int host=address&~mask;
        if(host==0||host==~mask)return false;
        int first=ipv4[0]&0xff;
        return address!=0&&first!=127&&first<224;
    }
    private static int toInt(byte[] b){return (b[0]&0xff)<<24|(b[1]&0xff)<<16|(b[2]&0xff)<<8|b[3]&0xff;}
    @Override public boolean equals(Object other){return other instanceof LocalNetwork o&&o.prefix==prefix&&Arrays.equals(o.self,self);}
    @Override public int hashCode(){return 31*Arrays.hashCode(self)+prefix;}
    @Override public String toString(){return "Local network";}
}
