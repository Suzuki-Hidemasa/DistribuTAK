// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.LongSupplier;

/** 口ごとの到達性の証明。身元の認証は行わない（ADR0030答え160）。 */
final class AddressCookies implements AutoCloseable {
    static final long SECOND=1_000_000_000L;
    private static final byte[] DOMAIN="DistribuTAK/address-cookie/v1".getBytes(StandardCharsets.US_ASCII);
    static final class ClockFailure extends RuntimeException {
        ClockFailure() { super("クッキーの手元の時計が使えません"); }
    }
    private final LongSupplier clock;
    private final SecureRandom random=new SecureRandom();
    private final long opened;
    private long last,rotated;
    private byte[] current,previous;
    private boolean closed;
    AddressCookies(LongSupplier clock) {
        this.clock=Objects.requireNonNull(clock);
        try { opened=last=rotated=clock.getAsLong();current=secret(); }
        catch(RandomFailure e) { close();throw e; }
        catch(RuntimeException e) { close();throw new ClockFailure(); }
    }
    private byte[] secret() { byte[] value=new byte[32];try { random.nextBytes(value);return value; }catch(RuntimeException e){Crypto.wipe(value);throw new RandomFailure();} }
    synchronized long refresh() {
        if(closed)throw new IllegalStateException("クッキーの口は閉じています");
        try {
            long now=clock.getAsLong();if(now<last)throw new ClockFailure();last=now;
            long elapsed=Math.subtractExact(now,rotated);
            if(elapsed>=60*SECOND) {
                byte[] next=secret();Crypto.wipe(previous);
                if(elapsed>=120*SECOND) { Crypto.wipe(current);previous=null; }
                else previous=current;
                current=next;rotated=now;
            }
            return Math.subtractExact(now,opened);
        } catch(RandomFailure e) { close();throw e; }
        catch(RuntimeException e) { close();throw new ClockFailure(); }
    }
    synchronized byte[] issue(byte[] first,InetSocketAddress source) {
        long millis=refresh()/1_000_000L;byte[] stamp=ByteBuffer.allocate(8).putLong(millis).array(),hash=null,mac=null;
        try {
            hash=Crypto.blake2s(first);mac=mac(current,stamp,source,hash);return Crypto.concat(stamp,mac);
        } finally { Crypto.wipe(stamp);Crypto.wipe(hash);Crypto.wipe(mac); }
    }
    synchronized boolean verify(byte[] cookie,byte[] first,InetSocketAddress source) {
        long millis=refresh()/1_000_000L;if(cookie==null||cookie.length!=40)return false;
        byte[] stamp=Arrays.copyOf(cookie,8),received=Arrays.copyOfRange(cookie,8,40),hash=null,a=null,b=null;
        try {
            hash=Crypto.blake2s(first);a=mac(current,stamp,source,hash);
            b=previous==null ? new byte[32] : mac(previous,stamp,source,hash);
            boolean currentMatches=Crypto.equal(a,received),previousMatches=Crypto.equal(b,received);
            if(!currentMatches && !(previous!=null&&previousMatches))return false;
            long issued=ByteBuffer.wrap(stamp).getLong();
            // 外から来た時刻は手元時計の故障にしない。MACが合ったあとだけ差を取る。
            if(issued<0||issued>millis)return false;
            try { return Math.subtractExact(millis,issued)<30_000; }catch(ArithmeticException e){return false;}
        } finally { Crypto.wipe(stamp);Crypto.wipe(received);Crypto.wipe(hash);Crypto.wipe(a);Crypto.wipe(b); }
    }
    private byte[] mac(byte[] secret,byte[] stamp,InetSocketAddress address,byte[] hash) {
        var source=EndpointAddress.normalize(address);byte[] ip=source.getAddress().getAddress();
        int scope=source.getAddress() instanceof Inet6Address v6 ? v6.getScopeId() : 0;
        byte[] input=ByteBuffer.allocate(DOMAIN.length+8+1+ip.length+4+2+32).put(DOMAIN).put(stamp)
            .put((byte)(ip.length==4?4:6)).put(ip).putInt(scope).putShort((short)source.getPort()).put(hash).array();
        try { return Crypto.hmacSha256(secret,input); }finally { Crypto.wipe(input);Crypto.wipe(ip); }
    }
    public synchronized void close() { closed=true;Crypto.wipe(current);Crypto.wipe(previous); }
    public String toString() { return "AddressCookies"; }
}
