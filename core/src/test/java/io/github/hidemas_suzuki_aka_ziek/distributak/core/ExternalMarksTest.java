// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExternalMarksTest {
    static ExternalMarks marks(){return new ExternalMarks(new byte[32],CotRecordTest.id(1));}
    @Test void queuedFingerprintUsesExactlyTheSameDigestAndNeverPrintsIt(){
        var marks=marks();var fingerprint=ExternalMarks.fingerprint("queued");assertTrue(marks.addFingerprint(fingerprint));assertTrue(marks.contains("queued"));assertTrue(marks.containsFingerprint(fingerprint));
        var direct=marks();direct.add("queued");assertArrayEquals(direct.encode(),marks.encode());assertEquals("External UID fingerprint",fingerprint.toString());
    }
    @Test void fullRegistryRoundTripsAtExactBoundaryAndOverflowCannotPermitNewUid(){
        var marks=marks();for(int i=0;i<65536;i++)assertTrue(marks.add("external-"+i));
        assertTrue(marks.full());assertFalse(marks.add("overflow"));assertTrue(marks.add("external-0"));
        byte[] wire=marks.encode();assertEquals(1572968,wire.length);
        var restored=ExternalMarks.decode(wire,new byte[32],CotRecordTest.id(1));
        assertTrue(restored.contains("external-0"));assertTrue(restored.full());assertEquals(65536,restored.size());
        assertThrows(IllegalArgumentException.class,()->ExternalMarks.decode(Arrays.copyOf(wire,wire.length+1),new byte[32],CotRecordTest.id(1)));
    }
    @Test void wrongHeaderScopeCountOrderingAndDuplicatesAreRejected(){
        var marks=marks();marks.add("first");marks.add("second");byte[] good=marks.encode();
        assertEquals(2,ExternalMarks.decode(good,new byte[32],CotRecordTest.id(1)).size());
        for(int at:new int[]{0,6,8,36,68,103}){byte[] bad=good.clone();bad[at]^=1;assertThrows(IllegalArgumentException.class,()->ExternalMarks.decode(bad,new byte[32],CotRecordTest.id(1)));}
        byte[] duplicate=good.clone();System.arraycopy(duplicate,104,duplicate,128,24);
        assertThrows(IllegalArgumentException.class,()->ExternalMarks.decode(duplicate,new byte[32],CotRecordTest.id(1)));
        byte[] reversed=good.clone();System.arraycopy(good,104,reversed,128,24);System.arraycopy(good,128,reversed,104,24);
        assertThrows(IllegalArgumentException.class,()->ExternalMarks.decode(reversed,new byte[32],CotRecordTest.id(1)));
        assertThrows(IllegalArgumentException.class,()->ExternalMarks.decode(good,CotRecordTest.id(2),CotRecordTest.id(1)));
        assertThrows(IllegalArgumentException.class,()->ExternalMarks.decode(good,new byte[32],CotRecordTest.id(2)));
        assertFalse(new String(good,java.nio.charset.StandardCharsets.ISO_8859_1).contains("first"));
    }
    @Test void copyCannotMutateCommittedMarksAndHashesUse128BitBlake2sWithDomain(){
        var marks=marks();marks.add("known");var copy=marks.copy();copy.add("later");assertFalse(marks.contains("later"));
        byte[] digest=Arrays.copyOfRange(marks.encode(),104,120);
        var hash=new org.bouncycastle.crypto.digests.Blake2sDigest(128);byte[] input=Crypto.concat("DistribuTAK external uid v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII),new byte[]{0},"known".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        hash.update(input,0,input.length);byte[] expected=new byte[16];hash.doFinal(expected,0);assertArrayEquals(expected,digest);
        assertFalse(Arrays.equals(Arrays.copyOf(Crypto.blake2s(input),16),digest));
    }
}
