// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.net.*;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpointTest.*;

class UdpEndpointDualStackTest {
    static InetSocketAddress mapped(int port) throws Exception {
        byte[] ip=new byte[16];ip[10]=(byte)255;ip[11]=(byte)255;ip[12]=127;ip[15]=1;
        return new InetSocketAddress(Inet6Address.getByAddress(null,ip,-1),port);
    }
    @Test void mappedAddressesHaveOneCanonicalRepresentationAndPreserveV6Scope() throws Exception {
        var v4=new InetSocketAddress("127.0.0.1",12345);
        assertEquals(v4,EndpointAddress.normalize(mapped(12345)));
        assertEquals(v4,EndpointAddress.normalize(v4));
        assertTrue(EndpointAddress.compatible(InetAddress.getByName("::"),new byte[4]));
        assertFalse(EndpointAddress.compatible(InetAddress.getByName("::1"),new byte[4]));
        byte[] scoped=new byte[16];scoped[0]=(byte)0xfe;scoped[1]=(byte)0x80;scoped[15]=1;
        var v6=new InetSocketAddress(Inet6Address.getByAddress(null,scoped,7),12345);
        assertEquals(7,((Inet6Address)EndpointAddress.normalize(v6).getAddress()).getScopeId());
        var f=new UdpEndpointTest();
        try(var node=f.new Node(1,"127.0.0.1")) {
            node.endpoint.setPeerAddress(new byte[32],mapped(12345));
            assertEquals(v4,node.endpoint.peerAddress(new byte[32]));
        }
    }
    /** IPv4しか使わないJavaを別プロセスで起動し、IPv6のbindの失敗が隠れないことを確かめる。 */
    @Test void ipv6UnavailableFailsToOpenWithoutV4Fallback() throws Exception {
        String testClasses=Path.of(getClass().getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String mainClasses=Path.of(UdpEndpoint.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        var process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin","java").toString(),
            "-Djava.net.preferIPv4Stack=true","-cp",testClasses+java.io.File.pathSeparator+mainClasses,NoIpv6.class.getName())
            .redirectErrorStream(true).start();
        try {
            assertTrue(process.waitFor(5,TimeUnit.SECONDS),"IPv6を使えない環境の試験が終了しませんでした");
            assertEquals(0,process.exitValue(),new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
        } finally { process.destroyForcibly(); }
    }
    public static class NoIpv6 {
        public static void main(String[] args) throws Exception {
            // :: のbindは両用の試験1件に限る。この失敗の試験は::1を使う。
            try(var socket=new DatagramSocket(new InetSocketAddress(InetAddress.getByName("::1"),0))) {
                new UdpEndpoint.SocketIo(socket);
                throw new AssertionError("IPv4だけの環境でIPv6の口が作られました");
            } catch(SocketException expected) { }
        }
    }
    /** :: の bind はこの試験の1ソケットだけ。宛先は必ずループバックを明示する。 */
    @Test void oneWildcardEndpointExchangesWithBothFamilies() throws Exception {
        var f=new UdpEndpointTest();UdpEndpointTest.Node center;
        try { center=f.new Node(1,"::"); }
        catch(SocketException e) { Assumptions.abort("IPv6の::にbindできません: "+e.getClass().getSimpleName());return; }
        try(center;var v4=f.new Node(2,"127.0.0.1");var v6=f.new Node(3,"::1")) {
            center.link(v4);center.link(v6);
            v4.endpoint.rememberPeer(center.cert);v6.endpoint.rememberPeer(center.cert);
            v4.endpoint.setPeerAddress(center.id,new InetSocketAddress("127.0.0.1",center.socket.getLocalPort()));
            v6.endpoint.setPeerAddress(center.id,new InetSocketAddress("::1",center.socket.getLocalPort()));
            v4.endpoint.start(center.id);v6.endpoint.start(center.id);
            await(()->center.endpoint.isEstablished(v4.id)&&center.endpoint.isEstablished(v6.id)
                &&v4.endpoint.isEstablished(center.id)&&v6.endpoint.isEstablished(center.id));
            assertTrue(v4.endpoint.send(center.id,new byte[]{4}));assertArrayEquals(new byte[]{4},take(center));
            assertTrue(v6.endpoint.send(center.id,new byte[]{6}));assertArrayEquals(new byte[]{6},take(center));
            assertTrue(center.endpoint.send(v4.id,new byte[]{14}));assertArrayEquals(new byte[]{14},take(v4));
            assertTrue(center.endpoint.send(v6.id,new byte[]{16}));assertArrayEquals(new byte[]{16},take(v6));
            assertEquals(v4.address(),center.endpoint.peerAddress(v4.id));assertEquals(v6.address(),center.endpoint.peerAddress(v6.id));
        }
    }
    @Test void ipv6RealSocketDiscards65000BytesWithoutTruncatingToValidPrefix() throws Exception {
        var f=new UdpEndpointTest();
        try(var a=f.new Node(1,"::1");var b=f.new Node(2,"::1")) {
            f.connect(a,b);
            byte[] valid=a.sessions.send(b.id,new byte[1176]).get(0).packet();
            long before=b.endpoint.rejectedPackets();byte[] oversized=Arrays.copyOf(valid,65000);
            a.socket.send(new DatagramPacket(oversized,oversized.length,b.address()));
            await(()->b.endpoint.rejectedPackets()>before);assertTrue(b.inbox.isEmpty());
            a.socket.send(new DatagramPacket(valid,valid.length,b.address()));assertEquals(1176,take(b).length);
            assertFalse(b.socket.isClosed());
        }
    }
}
