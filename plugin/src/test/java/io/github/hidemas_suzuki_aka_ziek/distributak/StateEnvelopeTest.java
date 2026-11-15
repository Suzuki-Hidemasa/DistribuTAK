// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class StateEnvelopeTest {
    static class TestCipher implements StateEnvelope.CipherBox {
        final javax.crypto.SecretKey key;
        TestCipher(){this(new SecretKeySpec(new byte[32],"AES"));}
        TestCipher(javax.crypto.SecretKey key){this.key=key;}
        public StateEnvelope.Sealed seal(byte[] plain,byte[] aad) throws Exception {
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key);cipher.updateAAD(aad);
            return new StateEnvelope.Sealed(cipher.getIV(),cipher.doFinal(plain));
        }
        public byte[] open(byte[] iv,byte[] ciphertext,byte[] aad) throws Exception {
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key,new GCMParameterSpec(128,iv));
            cipher.updateAAD(aad);return cipher.doFinal(ciphertext);
        }
    }
    @Test public void authenticEnvelopeRoundTripsAndRejectsTamperVersionAndAad() throws Exception {
        var envelope=new StateEnvelope(new TestCipher());byte[] plain={1,2,3,4};
        byte[] wire=envelope.seal(plain);assertArrayEquals(plain,envelope.open(wire));
        for(int offset:new int[]{0,4,8,wire.length-1}) {
            byte[] bad=wire.clone();bad[offset]^=1;
            assertThrows(Exception.class,()->envelope.open(bad));
        }
        var wrongAad=new StateEnvelope(new TestCipher(){@Override public byte[] open(byte[] iv,byte[] ct,byte[] aad)throws Exception{
            byte[] changed=aad.clone();changed[0]^=1;return super.open(iv,ct,changed);
        }});
        assertThrows(Exception.class,()->wrongAad.open(wire));
        assertThrows(Exception.class,()->envelope.open(Arrays.copyOf(wire,wire.length-1)));
        assertArrayEquals(plain,envelope.open(wire));
    }
    @Test public void failedAtomicWriteLeavesOldEnvelopeAndWipesPreparedPlaintext() throws Exception {
        var envelope=new StateEnvelope(new TestCipher());var target=new MemoryTarget();
        byte[] old=envelope.seal(new byte[]{1});target.value=old;
        target.fail=true;byte[] prepared={2};
        assertThrows(Exception.class,()->envelope.save(prepared,target));
        assertArrayEquals(new byte[]{0},prepared);assertArrayEquals(new byte[]{1},envelope.open(target.value));
        assertTrue(target.rolledBack);
        target.fail=false;envelope.save(new byte[]{3},target);
        assertArrayEquals(new byte[]{3},envelope.open(target.value));
    }
    static class MemoryTarget implements StateEnvelope.AtomicTarget {
        byte[] value,pending;boolean fail,rolledBack;
        public void begin(){pending=null;}
        public void write(byte[] bytes)throws Exception { pending=bytes.clone();if(fail)throw new java.io.IOException(); }
        public void commit(){value=pending;pending=null;}
        public void rollback(){pending=null;rolledBack=true;}
    }
}
