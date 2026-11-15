// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.util.Arrays;
import java.util.Objects;

/** 番地の比較の前にIPv4射影をIPv4へそろえる。通常のIPv6のscopeは保つ。 */
final class EndpointAddress {
    private EndpointAddress() {}
    static InetSocketAddress normalize(InetSocketAddress address) {
        Objects.requireNonNull(address);
        if(address.isUnresolved())throw new IllegalArgumentException("解決済みの番地が必要です");
        byte[] ip=address.getAddress().getAddress();
        if(ip.length==16) {
            boolean mapped=true;
            for(int i=0;i<10;i++)mapped&=ip[i]==0;
            mapped&=ip[10]==(byte)255&&ip[11]==(byte)255;
            if(mapped) {
                try { return new InetSocketAddress(InetAddress.getByAddress(Arrays.copyOfRange(ip,12,16)),address.getPort()); }
                catch(UnknownHostException impossible) { throw new IllegalStateException("IPv4の長さが違います"); }
            }
        }
        return address;
    }
    /** JavaのequalsはIPv6のscopeを比べないため、固定した番地の照合はここを通す。 */
    static boolean same(InetSocketAddress left,InetSocketAddress right) {
        if(left==null||right==null)return false;
        var a=normalize(left);var b=normalize(right);
        int aScope=a.getAddress() instanceof Inet6Address v6 ? v6.getScopeId() : 0;
        int bScope=b.getAddress() instanceof Inet6Address v6 ? v6.getScopeId() : 0;
        return a.getPort()==b.getPort()&&aScope==bScope&&Arrays.equals(a.getAddress().getAddress(),b.getAddress().getAddress());
    }
    static boolean compatible(InetAddress local,byte[] remote) {
        // :: だけは両方の族を許す。bindできない環境でIPv4へ開き直さない。
        if(local instanceof Inet6Address&&local.isAnyLocalAddress())return true;
        try { return normalize(new InetSocketAddress(local,0)).getAddress().getAddress().length
                ==normalize(new InetSocketAddress(InetAddress.getByAddress(remote),0)).getAddress().getAddress().length; }
        catch(UnknownHostException e) { throw new IllegalArgumentException("番地の長さが違います"); }
    }
}
