// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.File;
import java.nio.file.*;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;
import static org.junit.Assert.*;

public class ColdFileStoreTest {
    static byte[] key(int value){byte[] key=new byte[32];key[0]=(byte)value;return key;}
    static ColdFileStore store(File dir,long bytes,int files){return new ColdFileStore(dir,new StateEnvelope(new StateEnvelopeTest.TestCipher()),new byte[32],key(1),bytes,files);}
    @Test public void encryptedRoundTripCorruptionMissingAndStartupCleanup()throws Exception {
        File dir=Files.createTempDirectory("distributak-spill-").toFile();
        try{
            var store=store(dir,1024*1024,10);byte[] plain="<event uid=\"fixture-private\"/>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(store.put(key(1),plain));assertArrayEquals(plain,store.get(key(1)));assertEquals(1,store.files());
            File file=dir.listFiles()[0];byte[] wire=Files.readAllBytes(file.toPath());assertFalse(new String(wire,java.nio.charset.StandardCharsets.ISO_8859_1).contains("fixture-private"));
            wire[wire.length-1]^=1;Files.write(file.toPath(),wire);assertNull(store.get(key(1)));assertEquals(0,store.files());
            assertTrue(store.put(key(2),plain));Files.delete(dir.listFiles()[0].toPath());assertNull(store.get(key(2)));
            assertTrue(store.put(key(3),plain));Files.write(new File(dir,"abandoned.new").toPath(),new byte[]{1});
            var restarted=store(dir,1024*1024,10);assertEquals(0,restarted.files());assertEquals(0,dir.list().length);assertNull(restarted.get(key(3)));
            restarted.close();
        }finally{for(File f:dir.listFiles())f.delete();dir.delete();}
    }
    @Test public void entryFileAndByteBoundsRejectWithoutLosingExistingData()throws Exception {
        File dir=Files.createTempDirectory("distributak-spill-quota-").toFile();
        try{
            var store=store(dir,1024*1024,3);byte[] plain=new byte[64];assertTrue(store.put(key(1),plain));long size=store.bytes();
            assertFalse(store.put(key(9),new byte[262144]));assertTrue(store.put(key(2),plain));assertFalse(store.put(key(3),plain));assertArrayEquals(plain,store.get(key(1)));store.close();
            var bytes=store(dir,size+1,10);assertTrue(bytes.put(key(1),plain));assertFalse(bytes.put(key(2),plain));assertEquals(size,bytes.bytes());assertArrayEquals(plain,bytes.get(key(1)));bytes.close();
        }finally{for(File f:dir.listFiles())f.delete();dir.delete();}
    }
    @Test public void eraseAndInitialRecoveryClearEverySpillIncludingAbandonedTemporaryFiles()throws Exception {
        File root=Files.createTempDirectory("distributak-spill-erase-").toFile();File dir=new File(root,"sync-cache");assertTrue(dir.mkdir());
        try{Files.write(new File(dir,"cache.bin").toPath(),new byte[]{1});Files.write(new File(dir,"cache.bin.new").toPath(),new byte[]{1});
            StoreFiles.deleteRecords(root,file->{});assertEquals(0,dir.list().length);
        }finally{for(File f:dir.listFiles())f.delete();dir.delete();root.delete();}
    }
    @Test public void wrongScopeCannotLoadAndIoIsConfinedToOwnerWorker()throws Exception {
        File dir=Files.createTempDirectory("distributak-spill-scope-").toFile();
        try{
            var old=store(dir,1024*1024,10);assertTrue(old.put(key(1),new byte[]{1}));File file=dir.listFiles()[0];byte[] wire=Files.readAllBytes(file.toPath());String name=file.getName();
            var other=new ColdFileStore(dir,new StateEnvelope(new StateEnvelopeTest.TestCipher()),key(2),key(1),1024*1024,10);
            Files.write(new File(dir,name).toPath(),wire);assertNull(other.get(key(1)));
            var error=new AtomicReference<Throwable>();Thread thread=new Thread(()->{try{other.put(key(1),new byte[]{1});}catch(Throwable e){error.set(e);}});thread.start();thread.join();assertTrue(error.get() instanceof IllegalStateException);other.close();
        }finally{for(File f:dir.listFiles())f.delete();dir.delete();}
    }
}
