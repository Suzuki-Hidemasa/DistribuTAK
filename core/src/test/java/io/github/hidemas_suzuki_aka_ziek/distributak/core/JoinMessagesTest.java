// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordsTest.key;

class JoinMessagesTest {
    @Test void requestRoundTripAndStrictShape() {
        try(var request=new JoinMessages.Request(key(1),key(2),key(3),new byte[64],new byte[]{48,49,50,51,52,53,54,55},key(4))) {
            byte[] wire=request.encode();
            try(var parsed=JoinMessages.request(wire)) { assertArrayEquals(wire,parsed.encode()); }
            for(byte[] bad:List.of(Crypto.concat(wire,new byte[]{72,1}),Crypto.concat(wire,new byte[]{8,1}),
                    Crypto.concat(new byte[]{(byte)136,0},Arrays.copyOfRange(wire,1,wire.length)),new byte[JoinMessages.MAX_REQUEST+1]))
                assertThrows(IllegalArgumentException.class,()->JoinMessages.request(bad));
        }
    }
    @Test void responseRoundTripRejectsUnknownDuplicateAndChainLimit() {
        var response=new JoinMessages.Response(key(1),List.of(new byte[]{1}),new byte[64],new byte[]{2},new byte[]{3},new byte[]{4});
        byte[] wire=response.encode();assertArrayEquals(wire,JoinMessages.response(wire).encode());
        assertThrows(IllegalArgumentException.class,()->JoinMessages.response(Crypto.concat(wire,new byte[]{64,1})));
        assertThrows(IllegalArgumentException.class,()->JoinMessages.response(Crypto.concat(wire,new byte[]{34,0})));
        assertThrows(IllegalArgumentException.class,()->new JoinMessages.Response(key(1),Collections.nCopies(JoinMessages.MAX_CHAIN+1,new byte[]{1}),new byte[64],new byte[]{2},new byte[]{3},new byte[]{4}));
        assertThrows(IllegalArgumentException.class,()->JoinMessages.response(new byte[JoinMessages.MAX_RESPONSE+1]));
    }
    @Test void packetCanonicalFormAndRequestOwnedBuffersAreCleared() throws Exception {
        for(boolean reply:new boolean[]{false,true}) {
            var packet=new JoinMessages.Packet(reply,key(1),key(2),new byte[16],new byte[reply ? 64 : 0]);
            byte[] wire=packet.encode();var parsed=JoinMessages.packet(wire,reply);
            assertArrayEquals(wire,parsed.encode());assertArrayEquals(packet.signedBytes(),parsed.signedBytes());
            for(byte[] bad:List.of(Crypto.concat(wire,new byte[]{48,1}),Crypto.concat(wire,new byte[]{8,(byte)(reply ? 4 : 3)}),
                    Crypto.concat(new byte[]{(byte)136,0},Arrays.copyOfRange(wire,1,wire.length))))
                assertThrows(IllegalArgumentException.class,()->JoinMessages.packet(bad,reply));
        }
        var request=new JoinMessages.Request(key(1),key(2),key(3),new byte[64],new byte[]{48,49,50,51,52,53,54,55},key(4));
        try(var parsed=JoinMessages.request(request.encode())) {
            byte[] code=parsed.code, proof=parsed.proof, signed=SecretAssertions.bytes(parsed,"receivedPrefix");
            parsed.close();SecretAssertions.zero(code);SecretAssertions.zero(proof);SecretAssertions.zero(signed);
        } finally { request.close(); }
    }
}
