// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class InvitationTest {
    @Test void identityAndUla() {
        // 公開鍵は CryptoTest の ed25519 の試験と同じ（乱数から作った値）。
        // The public key is the same randomly generated one as in the CryptoTest ed25519 test.
        byte[] pub=CryptoTest.hex("2ce8cd084440d7a7ca45d179736e8e236fa055fd50d94d0cba46ac9b4cb454d5");
        // Python 標準ライブラリ hashlib.blake2s による独立した照合値。
        // Cross-check value computed independently with Python hashlib.blake2s.
        assertArrayEquals(CryptoTest.hex("359742c399f78b7f39bc17222b72d79c25df791705967d5a2248551b034d65ab"),DeviceIdentity.id(pub));
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
