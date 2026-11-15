// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.nio.file.*;
import java.io.*;
import java.time.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.Test;
import static org.junit.Assert.*;

public class SyncSaveReuseTest {
    static final long NOW=10_000_000_000L;
    static byte[] local(){byte[] id=new byte[32];id[0]=1;return id;}
    static final class Disk implements SyncSpill {
        final ColdFileStore disk;int reads;boolean refuse;
        Disk(Path path,StateEnvelope envelope){disk=new ColdFileStore(path.toFile(),envelope,new byte[32],local(),ColdFileStore.DEFAULT_BYTES,ColdFileStore.DEFAULT_FILES);}
        public boolean put(byte[] key,byte[] value){return !refuse&&disk.put(key,value);}public byte[] get(byte[] key){reads++;return disk.get(key);}public void remove(byte[] key){disk.remove(key);}public void clear(){disk.clear();}public long bytes(){return disk.bytes();}public int files(){return disk.files();}
    }
    static final class Primary implements CotSync.Store {
        final StateEnvelope envelope;final Path base,next;int opens;byte[] lastEncoded;
        Primary(Path root,StateEnvelope envelope){base=root.resolve("sync.bin");next=root.resolve("sync.bin.new");this.envelope=envelope.withMaximum(StateEnvelope.SYNC_MAX_BYTES);}
        public boolean encoded(){return true;}
        public byte[] loadEncoded()throws Exception{opens++;return envelope.open(Files.readAllBytes(base));}
        public SyncState load()throws Exception{byte[] plain=loadEncoded();try{return SyncState.decode(plain,new byte[32],local());}finally{Crypto.wipe(plain);}}
        public void save(SyncState state)throws Exception{write(state.encode());}
        public void saveEncoded(SyncState state,byte[] encoded)throws Exception{lastEncoded=encoded;write(encoded.clone());}
        void write(byte[] owned)throws Exception{envelope.save(owned,new StateEnvelope.AtomicTarget(){
            FileOutputStream out;public void begin()throws Exception{out=new FileOutputStream(next.toFile());}public void write(byte[] wire)throws Exception{out.write(wire);}
            public void commit()throws Exception{out.getFD().sync();out.close();Files.move(next,base,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}public void rollback(){try{if(out!=null)out.close();Files.deleteIfExists(next);}catch(IOException ignored){}}
        });}
    }
    static SyncState initial(){
        var state=new SyncState(new byte[32],local());
        for(int n=0;n<2400;n++){
            String uid=String.format(java.util.Locale.ROOT,"item-%04d",n);String start="<event uid=\""+uid+"\" stale=\""+Instant.ofEpochMilli(NOW+60000)+"\"><detail>",end="</detail></event>";
            byte[] xml=(start+"x".repeat(1100-start.length()-end.length())+end).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            state.put(CotRecord.record(uid,NOW,local(),NOW+60000,xml,0),NOW);
        }return state;
    }
    @Test public void baselineColdSaveOpensSpillForEveryBody()throws Exception{measure(false);}
    @Test public void encodedSaveOpensPrimaryOnceAndDoesNotOpenSpill()throws Exception{measure(true);}
    static void measure(boolean optimized)throws Exception{
        Path root=Files.createTempDirectory("distributak-save-reuse-");CotSync node=null;
        try{
            var cipher=new StateEnvelope(new StateEnvelopeTest.TestCipher());var primary=new Primary(root,cipher);var state=initial();byte[] original=state.encode();assertTrue(original.length+38<=4194304);primary.save(state);
            var time=new AtomicLong();var disk=new Disk(root.resolve("cache"),cipher);var cache=new SyncCache(disk,2*1024*1024,8192,time::get);
            node=new CotSync(local(),state,Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC),time::get,primary,(p,se,w)->true,r->{},new SecureRandom(),0,new ExternalMarks(new byte[32],local()),m->{},SyncLimits.forHeap(64L*1024*1024),cache);
            state=null;long[] runs=new long[3];int totalReads=0,totalOpens=0;
            for(int run=-1;run<3;run++){
                time.addAndGet(6_000_000_000L);node.poll();assertEquals(0,cache.hotBytes());disk.reads=0;primary.opens=0;long start=System.nanoTime();
                if(optimized){assertTrue(node.registerReceivedUid("registry-"+run));node.flush();}else primary.save(node.snapshot());
                long elapsed=System.nanoTime()-start;if(run>=0){runs[run]=elapsed;totalReads+=disk.reads;totalOpens+=primary.opens;}
                if(optimized){assertEquals(1,primary.opens);assertEquals(0,disk.reads);assertNotNull(primary.lastEncoded);assertArrayEquals(new byte[primary.lastEncoded.length],primary.lastEncoded);}
                else assertTrue(disk.reads>=2400);
            }
            byte[] plain=primary.loadEncoded();try{assertArrayEquals(node.snapshot().encode(),plain);assertEquals(2400,primary.load().records().size());}finally{Crypto.wipe(plain);}
            long[] sorted=runs.clone();Arrays.sort(sorted);Path output=Path.of("../../../../out/reviews/20261112-distributak-cot-sync-fix1/save-reuse-"+(optimized?"after":"before")+".txt").toAbsolutePath().normalize();Files.createDirectories(output.getParent());
            Files.write(output,("PC AES-GCM + fsync + atomic rename; records=2400, each XML=1100, XML total=2640000 > Hot=2097152, original envelope="+(original.length+38)+"\nruns_ns="+Arrays.toString(runs)+"\nmedian_ms="+sorted[1]/1e6+" spill_opens_total="+totalReads+" primary_opens_total="+totalOpens+" saves=3\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }finally{if(node!=null)node.close();try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
    }
}
