// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.nio.file.*;
import java.io.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import static org.junit.Assert.*;

public class DiskManagementFilesTest {
    @Test public void committedGenerationsAreImmutableAndOrphanNumbersAreSkipped()throws Exception{
        Path directory=Files.createTempDirectory("dtak-management-test-");
        try{
            var syncs=new AtomicInteger();var files=new DiskManagementFiles(directory.toFile(),syncs::incrementAndGet);
            assertEquals(1,files.nextGeneration());byte[] initial=new byte[64];files.write(1,initial);
            assertEquals(1,syncs.get());assertThrows(IOException.class,()->files.write(1,new byte[64]));assertArrayEquals(initial,files.read(1));
            Files.write(directory.resolve("management-5.bin.part"),new byte[0]);assertEquals(6,files.nextGeneration());files.write(6,new byte[64]);
            assertTrue(Files.exists(directory.resolve("management-1.bin")));files.cleanup(6);
            assertFalse(Files.exists(directory.resolve("management-1.bin")));assertFalse(Files.exists(directory.resolve("management-5.bin.part")));
            assertEquals(7,files.nextGeneration());
        }finally{try(var paths=Files.list(directory)){for(Path path:paths.toList())Files.delete(path);}Files.delete(directory);}
    }
    @Test public void eraseRemovesAllManagementAndMarkerFilesButKeepsUnrelatedFiles()throws Exception{
        Path directory=Files.createTempDirectory("dtak-erase-test-");
        try{
            Files.write(directory.resolve("management-1.bin"),new byte[64]);Files.write(directory.resolve("management-2.bin.part"),new byte[64]);
            Files.write(directory.resolve("stop-marker.bin"),new byte[256]);Files.write(directory.resolve("unrelated"),new byte[1]);
            StoreFiles.deleteRecords(directory.toFile(),file->{});assertTrue(Files.exists(directory.resolve("unrelated")));
            try(var paths=Files.list(directory)){assertEquals(1,paths.count());}
        }finally{try(var paths=Files.list(directory)){for(Path path:paths.toList())Files.delete(path);}Files.delete(directory);}
    }
}
