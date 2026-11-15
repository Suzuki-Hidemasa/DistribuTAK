// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.FileOutputStream;
import java.nio.file.*;
import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;

public class SyncPersistenceTimingTest {
    @Test public void exactFourMiBAtomicEnvelopeRoundTripsAndReportsPcSaveTime()throws Exception {
        Path dir=Files.createTempDirectory("distributak-save-timing-"),base=dir.resolve("sync.bin"),next=dir.resolve("sync.bin.new");
        var envelope=new StateEnvelope(new StateEnvelopeTest.TestCipher()).withMaximum(StateEnvelope.SYNC_MAX_BYTES);
        var target=new StateEnvelope.AtomicTarget(){
            FileOutputStream stream;
            public void begin()throws Exception{stream=new FileOutputStream(next.toFile());}
            public void write(byte[] wire)throws Exception{stream.write(wire);}
            public void commit()throws Exception{stream.getFD().sync();stream.close();stream=null;Files.move(next,base,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
            public void rollback(){try{if(stream!=null)stream.close();Files.deleteIfExists(next);}catch(Exception ignored){}}
        };
        try {
            long[] elapsed=new long[5];
            for(int run=-1;run<elapsed.length;run++){
                byte[] plain=new byte[4194266];long start=System.nanoTime();envelope.save(plain,target);long duration=System.nanoTime()-start;
                if(run>=0)elapsed[run]=duration;assertEquals(4194304,Files.size(base));assertArrayEquals(new byte[4194266],envelope.open(Files.readAllBytes(base)));
            }
            long[] sorted=elapsed.clone();Arrays.sort(sorted);
            Path output=Path.of("../out/reviews/20261112-distributak-cot-sync/persistence-benchmark-fix1.txt").toAbsolutePath().normalize();Files.createDirectories(output.getParent());
            Files.write(output,("PC only; AES-256-GCM + atomic file write + file fsync + rename; envelope bytes=4194304; warmup=1\n"
                +"runs_ns="+Arrays.toString(elapsed)+"\nmedian_ms="+sorted[2]/1_000_000.0+"\nmax_ms="+sorted[4]/1_000_000.0+"\nAndroid Keystore/storage timing is unmeasured.\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } finally {Files.deleteIfExists(next);Files.deleteIfExists(base);Files.deleteIfExists(dir);}
    }
}
