// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import javax.crypto.KeyGenerator;
import java.util.concurrent.FutureTask;
import static org.junit.Assert.*;

/** Keystoreの代わりにPCのAES鍵を使い、同じ別名の削除と作り直しの順を確かめる。 */
public class JoinedKeyRecoveryTest {
    @Test public void incompleteJoinDeletesWrappingKeyAndBothFilesBeforeAliasReuse()throws Exception {
        for(int at=0;at<5;at++) {
            var keygen=KeyGenerator.getInstance("AES");keygen.init(256);
            var wrappingKey=new javax.crypto.SecretKey[]{keygen.generateKey()};
            var envelope=new StateEnvelope(new StateEnvelope.CipherBox(){
                public StateEnvelope.Sealed seal(byte[] plain,byte[] aad)throws Exception {
                    if(wrappingKey[0]==null)wrappingKey[0]=keygen.generateKey();
                    return new StateEnvelopeTest.TestCipher(wrappingKey[0]).seal(plain,aad);
                }
                public byte[] open(byte[] iv,byte[] ciphertext,byte[] aad)throws Exception {
                    if(wrappingKey[0]==null)throw new SecurityException();
                    return new StateEnvelopeTest.TestCipher(wrappingKey[0]).open(iv,ciphertext,aad);
                }
            });
            var state=new StateEnvelopeTest.MemoryTarget();var joining=new StateEnvelopeTest.MemoryTarget();
            var disk=new StoreRecoveryTest.Disk(){
                @Override public void deleteKey(){super.deleteKey();wrappingKey[0]=null;}
                @Override public void deleteRecords(){super.deleteRecords();state.value=null;joining.value=null;}
            };
            var staged=new StagedState(envelope,new byte[]{1},joining,()->joining.value.clone(),
                    ()->{disk.checkpoint();joining.value=null;},state);
            byte[] old=joining.value.clone();var oldKey=wrappingKey[0];
            disk.complete=true;disk.abrupt=true;disk.crash=at;
            var done=new FutureTask<Object>(()->null);done.run();
            assertThrows(AssertionError.class,()->StoreRecovery.acceptJoined(done,disk,
                    ()->{staged.commit();disk.checkpoint();},()->{disk.complete=false;disk.checkpoint();}));
            disk.crash=-1;StoreRecovery.resume(disk);
            if(at<4) {
                assertNull(wrappingKey[0]);assertNull(state.value);assertNull(joining.value);assertTrue(disk.complete);
                var next=new StagedState(envelope,new byte[]{2},joining,()->joining.value.clone(),()->joining.value=null,state);
                next.commit();assertNotSame(oldKey,wrappingKey[0]);
                assertArrayEquals(new byte[]{2},envelope.open(state.value));
                assertThrows(Exception.class,()->envelope.open(old));
            }else {
                assertSame(oldKey,wrappingKey[0]);assertArrayEquals(new byte[]{1},envelope.open(state.value));
                assertNull(joining.value);assertFalse(disk.complete);
            }
        }
    }
}
