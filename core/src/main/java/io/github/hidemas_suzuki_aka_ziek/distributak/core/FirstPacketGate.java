// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.util.*;
import java.util.function.LongSupplier;
import org.bouncycastle.util.encoders.Hex;

/** 安い検査・MAC・握手を独立に制限する。番地の記録はMAC検査後だけ作る。 */
final class FirstPacketGate implements AutoCloseable {
    final AddressCookies cookies;
    private final Bucket challenges=new Bucket(512,1024),macs=new Bucket(512,1024),heavy=new Bucket(64,128),overflow=new Bucket(8,32);
    private final Map<String,Source> sources=new HashMap<>();
    private boolean closed;
    private static final class Source {
        final Bucket bucket=new Bucket(16,64);long last;
        Source(long now) { last=now; }
    }
    FirstPacketGate(LongSupplier clock) { cookies=new AddressCookies(clock); }
    synchronized void refresh() { now(); }
    private long now() {
        if(closed)throw new IllegalStateException("1通目の口は閉じています");
        long now=cookies.refresh();sources.values().removeIf(source->now-source.last>=30*AddressCookies.SECOND);return now;
    }
    synchronized byte[] challenge(byte[] first,InetSocketAddress source) {
        CookieWire.firstKind(first);long now=now();
        if(first.length<80||!challenges.available(now))return null;challenges.take();
        byte[] cookie=null,hash=null;
        try { cookie=cookies.issue(first,source);hash=Crypto.blake2s(first);return CookieWire.challenge(hash,cookie); }
        finally { Crypto.wipe(cookie);Crypto.wipe(hash); }
    }
    synchronized boolean accept(byte[] cookie,byte[] first,InetSocketAddress source) {
        CookieWire.firstKind(first);long now=now();
        if(!macs.available(now))return false;macs.take();
        if(!cookies.verify(cookie,first,source))return false;
        String key=sourceKey(source);Source entry=sources.get(key);
        Bucket budget=entry!=null ? entry.bucket : sources.size()<1024 ? null : overflow;
        if(!heavy.available(now)||budget!=null&&!budget.available(now))return false;
        if(entry==null&&budget==null) { entry=new Source(now);sources.put(key,entry);budget=entry.bucket; }
        // 新規bucketにも最初の通過時刻を渡す。
        budget.available(now);heavy.take();budget.take();if(entry!=null)entry.last=now;return true;
    }
    static String sourceKey(InetSocketAddress source) {
        var address=EndpointAddress.normalize(source).getAddress();byte[] ip=address.getAddress();
        if(ip.length==16)Arrays.fill(ip,8,16,(byte)0);
        return Hex.toHexString(ip)+":"+(address instanceof Inet6Address v6?v6.getScopeId():0);
    }
    synchronized int sourceCount() { return sources.size(); }
    public synchronized void close() { closed=true;cookies.close();sources.clear(); }
    public String toString() { return "FirstPacketGate"; }
    private static final class Bucket {
        final int rate,capacity;double tokens;long at;boolean initialized;
        Bucket(int rate,int capacity) { this.rate=rate;this.capacity=capacity;tokens=capacity; }
        boolean available(long now) {
            if(initialized)tokens=Math.min(capacity,tokens+(now-at)/(double)AddressCookies.SECOND*rate);
            initialized=true;at=now;return tokens>=1;
        }
        void take() { tokens--; }
    }
}
