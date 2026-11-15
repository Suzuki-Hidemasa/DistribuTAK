// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AddressCookiesTest {
    static final InetSocketAddress SOURCE=new InetSocketAddress("127.0.0.1",12000);
    static byte[] first(int size) { return new SessionPacket(SessionPacket.FIRST,new byte[16],0,0,new byte[size-40]).encode(); }
    @Test void cookieBindsEveryInputAndHasStrictAgeAndRotation() throws Exception {
        var time=new AtomicLong();byte[] first=first(200);
        try(var cookies=new AddressCookies(time::get);var other=new AddressCookies(time::get)) {
            byte[] cookie=cookies.issue(first,SOURCE);
            assertTrue(cookies.verify(cookie,first,SOURCE));assertFalse(other.verify(cookie,first,SOURCE));
            for(var source:List.of(new InetSocketAddress("127.0.0.2",12000),new InetSocketAddress("127.0.0.1",12001),new InetSocketAddress("::1",12000)))
                assertFalse(cookies.verify(cookie,first,source));
            byte[] changed=first.clone();changed[199]^=1;assertFalse(cookies.verify(cookie,changed,SOURCE));
            byte[] corrupt=cookie.clone();corrupt[39]^=1;assertFalse(cookies.verify(corrupt,first,SOURCE));
            time.set(29_999_999_999L);assertTrue(cookies.verify(cookie,first,SOURCE));
            time.set(30_000_000_000L);assertFalse(cookies.verify(cookie,first,SOURCE));
            time.set(59_000_000_000L);byte[] late=cookies.issue(first,SOURCE);
            byte[] old=(byte[])SessionManagerTest.field(cookies,"current");
            time.set(60_000_000_000L);assertTrue(cookies.verify(late,first,SOURCE));
            time.set(120_000_000_000L);assertFalse(cookies.verify(late,first,SOURCE));assertArrayEquals(new byte[32],old);
            byte[] current=(byte[])SessionManagerTest.field(cookies,"current");time.set(240_000_000_000L);cookies.refresh();assertArrayEquals(new byte[32],current);
            byte[] finalKey=(byte[])SessionManagerTest.field(cookies,"current");cookies.close();assertArrayEquals(new byte[32],finalKey);
        }
    }
    @Test void forgedTimestampDoesNotBecomeAClockFailureButLocalFailureWipesSecrets() throws Exception {
        var time=new AtomicLong(100);byte[] first=first(200);
        try(var cookies=new AddressCookies(time::get)) {
            byte[] cookie=cookies.issue(first,SOURCE);
            for(long n:new long[]{Long.MIN_VALUE,Long.MAX_VALUE,-1,1}) {
                byte[] bad=cookie.clone();ByteBuffer.wrap(bad).putLong(n);assertFalse(cookies.verify(bad,first,SOURCE));
            }
            assertTrue(cookies.verify(cookie,first,SOURCE));byte[] key=(byte[])SessionManagerTest.field(cookies,"current");
            time.set(99);assertThrows(AddressCookies.ClockFailure.class,cookies::refresh);assertArrayEquals(new byte[32],key);
        }
        var broken=new AtomicBoolean();
        try(var cookies=new AddressCookies(()->{if(broken.get())throw new IllegalStateException("試験");return 0;})) {
            byte[] key=(byte[])SessionManagerTest.field(cookies,"current");broken.set(true);
            assertThrows(AddressCookies.ClockFailure.class,cookies::refresh);assertArrayEquals(new byte[32],key);
        }
    }
    @Test void mappedAndNativeShareCookiesButIpv6ScopeDoesNot() throws Exception {
        var time=new AtomicLong();byte[] wire=first(200),mapped=new byte[16];mapped[10]=(byte)255;mapped[11]=(byte)255;mapped[12]=127;mapped[15]=1;
        try(var c=new AddressCookies(time::get)) {
            byte[] cookie=c.issue(wire,SOURCE);
            assertTrue(c.verify(cookie,wire,new InetSocketAddress(Inet6Address.getByAddress(null,mapped,0),12000)));
            byte[] link=new byte[16];link[0]=(byte)0xfe;link[1]=(byte)0x80;link[15]=1;
            var a=new InetSocketAddress(Inet6Address.getByAddress(null,link,1),12000);
            var b=new InetSocketAddress(Inet6Address.getByAddress(null,link,2),12000);
            assertFalse(c.verify(c.issue(wire,a),wire,b));
        }
    }
    @Test void outerFrameAcceptsOnlyFirstMessagesAndExactSizeLimit() {
        byte[] first=first(1184),cookie=new byte[40];
        byte[] proof=CookieWire.proof(cookie,first);assertEquals(1232,proof.length);
        try(var frame=CookieWire.decode(proof)) { assertArrayEquals(first,frame.first());assertArrayEquals(cookie,frame.cookie());assertEquals(CookieWire.PROOF,frame.kind()); }
        byte[] challenge=CookieWire.challenge(Crypto.blake2s(first),cookie);assertEquals(80,challenge.length);
        assertThrows(IllegalArgumentException.class,()->CookieWire.proof(cookie,first(1185)));
        byte[] tooLong=Arrays.copyOf(proof,1233);assertThrows(IllegalArgumentException.class,()->CookieWire.decode(tooLong));
        for(int size:new int[]{0,3,7,47,79})assertThrows(IllegalArgumentException.class,()->CookieWire.decode(Arrays.copyOf(challenge,size)));
        for(int position:new int[]{0,3,7}) { byte[] bad=challenge.clone();bad[position]^=127;assertThrows(IllegalArgumentException.class,()->CookieWire.decode(bad)); }
        for(byte[] bad:List.of(challenge,proof,new SessionPacket(SessionPacket.SECOND,new byte[16],0,0,new byte[60]).encode(),new SessionPacket(SessionPacket.DATA,new byte[16],0,0,new byte[16]).encode(),JoinWire.ready(new byte[32],new byte[16],1),JoinWire.fetch(new byte[32],new byte[16],1,0),JoinWire.data(new byte[32],new byte[16],new byte[1],0)))
            assertThrows(IllegalArgumentException.class,()->CookieWire.proof(cookie,bad));
        assertFalse(CookieWire.decode(challenge).toString().contains(Arrays.toString(cookie)));
    }
    @Test void gatesKeepInvalidProofsOutOfHeavyBudgetAndBoundSourceTable() throws Exception {
        var time=new AtomicLong();byte[] first=first(200);
        try(var gate=new FirstPacketGate(time::get)) {
            for(int i=0;i<2000;i++) { var source=source(i);gate.challenge(first,source);assertFalse(gate.accept(new byte[40],first,source)); }
            assertEquals(0,gate.sourceCount());time.set(3_000_000_000L);
            byte[] challenge=gate.challenge(first,SOURCE);assertNotNull(challenge);
            try(var frame=CookieWire.decode(challenge)) { assertTrue(gate.accept(frame.cookie(),first,SOURCE)); }
            assertEquals(1,gate.sourceCount());
        }
        try(var gate=new FirstPacketGate(time::get)) {
            for(int i=0;i<1024;i++) {
                time.addAndGet(20_000_000L);var source=source(i);
                try(var frame=CookieWire.decode(gate.challenge(first,source))) { assertTrue(gate.accept(frame.cookie(),first,source)); }
            }
            assertEquals(1024,gate.sourceCount());
            byte[] cookie;
            try(var frame=CookieWire.decode(gate.challenge(first,source(2000)))) { cookie=frame.cookie().clone(); }
            for(int i=0;i<32;i++)assertTrue(gate.accept(cookie,first,source(2000)));
            assertFalse(gate.accept(cookie,first,source(2000)));assertEquals(1024,gate.sourceCount());
            time.addAndGet(125_000_000L);assertTrue(gate.accept(cookie,first,source(2000)));
            time.addAndGet(30_000_000_000L);gate.challenge(first,SOURCE);assertEquals(0,gate.sourceCount());
        }
    }
    @Test void challengeMacGlobalAndSourceBucketsRefillIndependently() {
        var time=new AtomicLong();byte[] first=first(200);
        try(var gate=new FirstPacketGate(time::get)) {
            byte[] cookie;
            try(var frame=CookieWire.decode(gate.challenge(first,SOURCE))) { cookie=frame.cookie().clone(); }
            for(int i=1;i<1024;i++)assertNotNull(gate.challenge(first,SOURCE));assertNull(gate.challenge(first,SOURCE));
            for(int i=0;i<128;i++)assertFalse(gate.accept(new byte[40],first,SOURCE));
            for(int i=0;i<64;i++)assertTrue(gate.accept(cookie,first,SOURCE));
            assertFalse(gate.accept(cookie,first,SOURCE));
            var another=source(8);byte[] otherCookie=gate.cookies.issue(first,another);assertTrue(gate.accept(otherCookie,first,another));
            time.addAndGet(62_500_000L);assertTrue(gate.accept(cookie,first,SOURCE));
            for(int i=0;i<1100;i++)gate.accept(new byte[40],first,SOURCE);
            assertFalse(gate.accept(cookie,first,SOURCE));time.addAndGet(1_000_000_000L);assertTrue(gate.accept(cookie,first,SOURCE));
        }
    }
    static InetSocketAddress source(int i) { return new InetSocketAddress("127."+(i/65536)+"."+((i/256)%256)+"."+(i%256),10000); }
    @Test void validMacWithFutureOrExtremeTimestampIsRejectedWithoutClosing() throws Exception {
        var time=new AtomicLong();byte[] first=first(200);
        try(var cookies=new AddressCookies(time::get)) {
            var method=AddressCookies.class.getDeclaredMethod("mac",byte[].class,byte[].class,InetSocketAddress.class,byte[].class);method.setAccessible(true);
            for(long value:new long[]{1,Long.MAX_VALUE,Long.MIN_VALUE,-1}) {
                byte[] stamp=ByteBuffer.allocate(8).putLong(value).array();
                byte[] mac=(byte[])method.invoke(cookies,SessionManagerTest.field(cookies,"current"),stamp,SOURCE,Crypto.blake2s(first));
                assertFalse(cookies.verify(Crypto.concat(stamp,mac),first,SOURCE));Crypto.wipe(mac);
            }
            assertTrue(cookies.verify(cookies.issue(first,SOURCE),first,SOURCE));
        }
    }
    @Test void globalHeavyLimitAndIpv6PrefixCanonicalizationHaveRecovery() throws Exception {
        var time=new AtomicLong();byte[] first=first(200);
        try(var gate=new FirstPacketGate(time::get)) {
            for(int n=0;n<2;n++) {
                var source=source(n);byte[] cookie=gate.cookies.issue(first,source);
                for(int i=0;i<64;i++)assertTrue(gate.accept(cookie,first,source));
            }
            var another=source(2);byte[] cookie=gate.cookies.issue(first,another);
            assertFalse(gate.accept(cookie,first,another));assertEquals(2,gate.sourceCount());
            time.set(15_625_000L);assertTrue(gate.accept(cookie,first,another));
        }
        byte[] v6=InetAddress.getByName("::1").getAddress();var firstIp=new InetSocketAddress(Inet6Address.getByAddress(null,v6,1),1);v6[15]=2;
        var samePrefix=new InetSocketAddress(Inet6Address.getByAddress(null,v6,1),2);var scope=new InetSocketAddress(Inet6Address.getByAddress(null,v6,2),2);
        assertEquals(FirstPacketGate.sourceKey(firstIp),FirstPacketGate.sourceKey(samePrefix));assertNotEquals(FirstPacketGate.sourceKey(firstIp),FirstPacketGate.sourceKey(scope));
        v6[0]=1;assertNotEquals(FirstPacketGate.sourceKey(firstIp),FirstPacketGate.sourceKey(new InetSocketAddress(Inet6Address.getByAddress(null,v6,1),1)));
        byte[] mapped=new byte[16];mapped[10]=(byte)255;mapped[11]=(byte)255;mapped[12]=127;mapped[15]=1;
        assertEquals(FirstPacketGate.sourceKey(SOURCE),FirstPacketGate.sourceKey(new InetSocketAddress(Inet6Address.getByAddress(null,mapped,0),1)));
    }

    @Test void cookieSecretsAreAbsentFromTextExceptionsAndLogs() throws Exception {
        var time=new AtomicLong();var bytes=new java.io.ByteArrayOutputStream();var originalOut=System.out;var originalErr=System.err;
        try(var cookies=new AddressCookies(time::get);var capture=new java.io.PrintStream(bytes)) {
            byte[] first=first(200),cookie=cookies.issue(first,SOURCE),key=(byte[])SessionManagerTest.field(cookies,"current");
            String cookieText=org.bouncycastle.util.encoders.Hex.toHexString(cookie),keyText=org.bouncycastle.util.encoders.Hex.toHexString(key);
            System.setOut(capture);System.setErr(capture);
            try {
                try(var frame=CookieWire.decode(CookieWire.challenge(Crypto.blake2s(first),cookie))) {
                    for(String text:List.of(cookies.toString(),frame.toString(),new UdpEndpoint.Datagram(cookie,SOURCE).toString())) {
                        assertFalse(text.contains(cookieText));assertFalse(text.contains(keyText));assertFalse(text.contains(Arrays.toString(cookie)));
                    }
                }
                byte[] bad=new byte[]{'D','T','C',1};
                String message=assertThrows(IllegalArgumentException.class,()->CookieWire.decode(bad)).getMessage();
                assertFalse(message.contains(cookieText));assertFalse(message.contains(keyText));assertFalse(cookies.verify(new byte[40],first,SOURCE));
            } finally { System.setOut(originalOut);System.setErr(originalErr); }
            assertEquals(0,bytes.size());
        } finally { System.setOut(originalOut);System.setErr(originalErr); }
    }

}
