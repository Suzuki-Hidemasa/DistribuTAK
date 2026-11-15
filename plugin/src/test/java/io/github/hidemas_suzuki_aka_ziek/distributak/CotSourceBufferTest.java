// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.Set;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.ExternalMarks;
import org.junit.Test;
import static org.junit.Assert.*;

public class CotSourceBufferTest {
    @Test public void latestPositionReplacesOldAndExternalUidCancelsQueuedPosition() {
        var buffer=new CotSourceBuffer();buffer.position("self",new byte[]{1});buffer.position("self",new byte[]{2});
        try(var batch=buffer.take()){assertArrayEquals(new byte[]{2},batch.xml);assertEquals("self",batch.uid);}
        buffer.position("self",new byte[]{3});buffer.external("self");
        try(var batch=buffer.take()){assertNull(batch.xml);assertEquals(Set.of(ExternalMarks.fingerprint("self")),batch.external);}
    }
    @Test public void fingerprintsDeduplicateAndKeepMainGuardUntilWorkerCommitsBatch(){
        var buffer=new CotSourceBuffer();assertTrue(buffer.external("outside"));assertTrue(buffer.external("outside"));assertTrue(buffer.knownExternal("outside"));
        try(var batch=buffer.take()){assertEquals(1,batch.external.size());assertEquals(ExternalMarks.fingerprint("outside"),batch.external.iterator().next());assertTrue(buffer.knownExternal("outside"));batch.committed();}
        assertFalse(buffer.knownExternal("outside"));
        buffer.external("self");buffer.position("self",new byte[]{1});try(var batch=buffer.take()){assertNull(batch.xml);}
    }
    @Test public void failedWorkerBatchKeepsMainGuardUntilStop(){
        var buffer=new CotSourceBuffer();buffer.external("outside");try(var batch=buffer.take()){assertTrue(buffer.knownExternal("outside"));}
        assertTrue(buffer.knownExternal("outside"));buffer.clear();assertFalse(buffer.knownExternal("outside"));
    }
    @Test public void worstUidQueueTransfersOwnershipAndReportsRetainedPcHeap()throws Exception{
        System.gc();long before=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();var buffer=new CotSourceBuffer();
        for(int n=0;n<65536;n++)assertTrue(buffer.external(String.format(java.util.Locale.ROOT,"%06d",n)+"x".repeat(250)));
        try(var batch=buffer.take()){
            assertEquals(65536,batch.external.size());for(int n=65536;n<131072;n++)assertTrue(buffer.external(String.format(java.util.Locale.ROOT,"%06d",n)+"x".repeat(250)));
            assertFalse(buffer.external("overflow"));System.gc();long after=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
            var path=java.nio.file.Path.of("../../../../out/reviews/20261112-distributak-cot-sync-fix1/source-buffer-memory-fix2.txt").toAbsolutePath().normalize();java.nio.file.Files.createDirectories(path.getParent());
            java.nio.file.Files.write(path,("PC fixture UID UTF8=256; pending=65536, in_flight=65536; fingerprints shared on take, no UID strings or set copy retained\npost_gc_before="+before+" post_gc_after="+after+" delta="+(after-before)+"\nConservative live accounting with 64-bit uncompressed references: two sets <= 16 MiB; compressed-reference estimate ~10 MiB, plus latest XML <=64KiB. Android not measured.\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }buffer.clear();
    }
    @Test public void finiteExternalQueueDoesNotGrowAndCloseWipesSnapshot() {
        var buffer=new CotSourceBuffer();for(int i=0;i<65536;i++)assertTrue(buffer.external("u"+i));
        assertFalse(buffer.external("overflow"));try(var batch=buffer.take()){assertTrue(batch.overflow);assertEquals(65536,batch.external.size());}buffer.clear();buffer.position("self",new byte[]{1});
        var batch=buffer.take();batch.close();assertArrayEquals(new byte[]{0},batch.xml);
        buffer.position("self",new byte[65537]);try(var empty=buffer.take()){assertNull(empty.xml);}
    }
}
