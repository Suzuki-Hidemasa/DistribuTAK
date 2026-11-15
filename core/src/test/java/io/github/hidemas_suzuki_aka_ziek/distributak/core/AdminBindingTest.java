// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AdminBindingTest {
    final byte[] key=new byte[32],member=new byte[32],proof=new byte[]{8,1};
    @Test void unknownExplicitlyContainsOnlyKeyAndState() {
        var binding=AdminBinding.unknown(key);assertEquals(AdminBinding.State.UNKNOWN,binding.state());
        byte[] wire=binding.encode();assertEquals(36,wire.length);assertEquals(16,wire[34]);assertEquals(0,wire[35]);
        assertNull(binding.memberId());assertNull(binding.possessionProof());
        assertTrue(java.util.Arrays.equals(wire,AdminBinding.decode(wire).encode()));
    }
    @Test void unknownRejectsPresenceOfEitherBoundFieldEvenWhenEmpty() {
        byte[] wire=AdminBinding.unknown(key).encode();
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(Crypto.concat(wire,new byte[]{26,0})));
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(Crypto.concat(wire,new byte[]{34,0})));
    }
    @Test void boundRetainsTheExactProofBytesAndMember() {
        var binding=AdminBinding.bound(key,member,proof);var decoded=AdminBinding.decode(binding.encode());
        assertEquals(AdminBinding.State.BOUND,decoded.state());assertTrue(java.util.Arrays.equals(member,decoded.memberId()));
        assertTrue(java.util.Arrays.equals(proof,decoded.possessionProof()));
    }
    @Test void boundRequiresMemberAndNonemptyProof() {
        assertThrows(IllegalArgumentException.class,()->AdminBinding.bound(key,new byte[31],proof));
        assertThrows(IllegalArgumentException.class,()->AdminBinding.bound(key,member,new byte[0]));
        byte[] wire=AdminBinding.unknown(key).encode();wire[35]=1;
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(wire));
    }
    @Test void unknownStateDuplicateAndUnknownFieldsAreRejected() {
        byte[] wire=AdminBinding.unknown(key).encode(),state=wire.clone();state[35]=2;
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(state));
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(Crypto.concat(wire,new byte[]{16,0})));
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(Crypto.concat(wire,new byte[]{40,0})));
    }
    @Test void noncanonicalIntegerAndShortKeyAreRejected() {
        byte[] wire=AdminBinding.unknown(key).encode();
        assertThrows(IllegalArgumentException.class,()->AdminBinding.decode(Crypto.concat(java.util.Arrays.copyOf(wire,35),new byte[]{(byte)128,0})));
        assertThrows(IllegalArgumentException.class,()->AdminBinding.unknown(new byte[31]));
    }
    @Test void inputAndOutputAreDefensiveCopies() {
        var binding=AdminBinding.bound(key,member,proof);byte[] original=binding.encode();
        key[0]=1;member[0]=1;proof[0]=1;binding.administratorKey()[0]=2;binding.memberId()[0]=2;binding.possessionProof()[0]=2;
        assertTrue(java.util.Arrays.equals(original,binding.encode()));
    }
}
