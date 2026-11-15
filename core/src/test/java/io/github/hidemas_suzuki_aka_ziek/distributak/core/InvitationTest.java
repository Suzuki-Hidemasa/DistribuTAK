// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class InvitationTest {
    @Test void identityAndUla() {
        byte[] pub=CryptoTest.hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        // Python 標準ライブラリ hashlib.blake2s による独立した照合値。
        assertArrayEquals(CryptoTest.hex("08fe4a69ab7c0e902c9066fa60a34f6a7864779a3acc9198bddf22688a85dc00"),DeviceIdentity.id(pub));
        byte[] address=DeviceIdentity.ula(pub);
        assertEquals((byte)0xfd,address[0]);assertArrayEquals(Arrays.copyOf(DeviceIdentity.id(pub),15),Arrays.copyOfRange(address,1,16));
    }
    @Test void roundTripIpv4AndIpv6() {
        for(int len:new int[]{4,16}) {
            try(var invitation=new Invitation(new byte[len],65535,new byte[32],new byte[32],TotpTest.SECRET, new byte[32])) {
                String url=InvitationUrl.encode(invitation);assertFalse(url.contains("="));
                try(var decoded=InvitationUrl.decode(url)) {
                    assertArrayEquals(new byte[len],decoded.adminAddress()); assertEquals(65535,decoded.udpPort());
                    assertArrayEquals(TotpTest.SECRET,decoded.totpSecret()); assertArrayEquals(new byte[32],decoded.handshakePublicKey());
                }
                assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url+"="));
                assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url.replace("join#","join/path#")));
            }
        }
    }
    @Test void groupIsMandatoryAndDefensivelyCopied()throws Exception {
        byte[] group=new byte[32];group[0]=1;
        try(var invitation=new Invitation(new byte[4],65535,new byte[32],new byte[32],TotpTest.SECRET,group)) {
            group[0]=2;assertEquals(1,invitation.groupId()[0]);byte[] read=invitation.groupId();read[0]=3;assertEquals(1,invitation.groupId()[0]);
            var raw=Base64.getUrlDecoder().decode(InvitationUrl.encode(invitation).substring(19));
            byte[] missing=Arrays.copyOf(raw,raw.length-16-34);
            assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url(missing)));
        }
    }
    static String url(byte[] body) {
        return "distributak://join#"+Base64.getUrlEncoder().withoutPadding().encodeToString(Crypto.concat(body,Crypto.blake2s128(body)));
    }
    @Test void checksumMalformedUnknownDuplicateAndLengths() {
        try(var invitation=new Invitation(new byte[4],1,new byte[32],new byte[32],TotpTest.SECRET, new byte[32])) {
            String url=InvitationUrl.encode(invitation);
            byte[] raw=Base64.getUrlDecoder().decode(url.substring(url.indexOf('#')+1));
            raw[5]^=1;
            assertThrows(SecurityException.class,()->InvitationUrl.decode("distributak://join#"+Base64.getUrlEncoder().withoutPadding().encodeToString(raw)));
            byte[] body=Base64.getUrlDecoder().decode(url.substring(url.indexOf('#')+1));body=Arrays.copyOf(body,body.length-16);
            byte[] valid=body;
            assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url(Crypto.concat(valid,new byte[]{48,1}))));
            assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url(Crypto.concat(valid,new byte[]{16,1}))));
            assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url(new byte[]{10,127})));
            assertThrows(IllegalArgumentException.class,()->InvitationUrl.decode(url(new byte[0])));
        }
        assertThrows(IllegalArgumentException.class,()->new Invitation(new byte[5],1,new byte[32],new byte[32],new byte[32], new byte[32]));
        assertThrows(IllegalArgumentException.class,()->new Invitation(new byte[4],0,new byte[32],new byte[32],new byte[32], new byte[32]));
        assertThrows(IllegalArgumentException.class,()->new Invitation(new byte[4],1,new byte[31],new byte[32],new byte[32], new byte[32]));
        assertThrows(IllegalArgumentException.class,()->new Invitation(new byte[4],1,new byte[32],new byte[32],new byte[31], new byte[32]));
    }
}
