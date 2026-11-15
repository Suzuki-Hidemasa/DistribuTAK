// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.*;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import static org.junit.Assert.*;

public class StoreFilesTest {
    @Test public void markerRecoveryDeletesSyncFilesAcrossAllEraseAndInitialRecoverySteps()throws Exception {
        for(boolean initial:new boolean[]{false,true})for(int at=0;at<7;at++) {
            Path directory=Files.createTempDirectory("distributak-sync-recovery-");
            try {
                for(String base:new String[]{"sync.bin","external.bin"})for(String suffix:new String[]{"",".bak",".new"})Files.write(directory.resolve(base+suffix),new byte[]{1});
                var disk=new StoreRecoveryTest.Disk();disk.initial=initial;disk.crash=at;disk.abrupt=true;
                var target=new StoreRecovery.EraseTarget(){
                    public boolean pending(){return disk.pending();}
                    public void markPending(){disk.markPending();}
                    public void stop(){disk.stop();}
                    public void deleteKey(){disk.deleteKey();}
                    public void deleteRecords()throws Exception{StoreFiles.deleteRecords(directory.toFile(),file->{});disk.deleteRecords();}
                    public void markComplete(){disk.markComplete();}
                    public void wipeMemory(){disk.wipeMemory();}
                    public void clearPending(){disk.clearPending();}
                };
                assertThrows(AssertionError.class,()->StoreRecovery.erase(target));
                disk.crash=-1;StoreRecovery.resume(target);
                assertFalse(disk.pending);assertFalse(disk.key);assertEquals(!initial,disk.complete);
                for(String base:new String[]{"sync.bin","external.bin"})for(String suffix:new String[]{"",".bak",".new"})assertFalse(Files.exists(directory.resolve(base+suffix)));
            } finally {
                try(var files=Files.list(directory)){for(Path file:files.toList())Files.deleteIfExists(file);}
                Files.deleteIfExists(directory);
            }
        }
    }
    @Test public void eraseAndInitialRecoveryRemoveSyncBaseBackupAndNewAtEveryBoundary()throws Exception {
        for(int stop=0;stop<5;stop++) {
            Path directory=Files.createTempDirectory("distributak-store-files-");
            try {
                for(String base:new String[]{"joining.bin","state.bin","settings.bin","sync.bin","external.bin"})
                    for(String suffix:new String[]{"",".bak",".new"})Files.write(directory.resolve(base+suffix),new byte[]{1});
                int boundary=stop;var count=new AtomicInteger();
                assertThrows(IOException.class,()->StoreFiles.deleteRecords(directory.toFile(),file->{if(count.getAndIncrement()==boundary)throw new IOException();}));
                StoreFiles.deleteRecords(directory.toFile(),file->{});
                try(var files=Files.list(directory)){assertEquals(0,files.count());}
                StoreFiles.deleteRecords(directory.toFile(),file->{});
            } finally {
                try(var files=Files.list(directory)){for(Path file:files.toList())Files.deleteIfExists(file);}
                Files.deleteIfExists(directory);
            }
        }
    }
}
