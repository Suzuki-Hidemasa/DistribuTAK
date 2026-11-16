// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RosterPlaintextWipeTest {
    @Test void temporaryCopyIsWipedAfterSuccessfulDigest(){
        byte[] copy={1,2,3};
        var result=ManagementPageAssembler.digestAndWipe(copy,value->{assertSame(copy,value);return new byte[]{4};});
        assertArrayEquals(new byte[]{4},result);assertArrayEquals(new byte[3],copy);
    }
    @Test void temporaryCopyIsWipedWhenDigestThrows(){
        byte[] copy={1,2,3};var failure=new IllegalStateException();
        assertSame(failure,assertThrows(IllegalStateException.class,()->ManagementPageAssembler.digestAndWipe(copy,value->{throw failure;})));
        assertArrayEquals(new byte[3],copy);
    }
}
