// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.security.SecureRandom;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

/** 本物のAES-GCM包みとfsyncを使うPC計測。輸送だけを同一workerのキューに置き換える。 */
public class OffloadCapacityTest {
    static final long NOW=10_000_000_000L;
    static byte[] id(int value){byte[] result=new byte[32];result[0]=(byte)value;return result;}
    static final class Primary implements CotSync.Store {
        final Path base,next;final byte[] local;final StateEnvelope envelope;
        int records,saves;long maxSaveNanos;
        Primary(Path dir,byte[] local,StateEnvelope envelope){base=dir.resolve("sync.bin");next=dir.resolve("sync.bin.new");this.local=local;this.envelope=envelope.withMaximum(StateEnvelope.SYNC_MAX_BYTES);}
        public boolean encoded(){return true;}
        public byte[] loadEncoded()throws Exception{return envelope.open(Files.readAllBytes(base));}
        public void save(SyncState state)throws Exception {write(state,state.encode());}
        public void saveEncoded(SyncState state,byte[] encoded)throws Exception{write(state,encoded.clone());}
        private void write(SyncState state,byte[] owned)throws Exception{
            long start=System.nanoTime();envelope.save(owned,new StateEnvelope.AtomicTarget(){
                FileOutputStream out;
                public void begin()throws Exception{out=new FileOutputStream(next.toFile());}
                public void write(byte[] wire)throws Exception{out.write(wire);}
                public void commit()throws Exception{out.getFD().sync();out.close();Files.move(next,base,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
                public void rollback(){try{if(out!=null)out.close();Files.deleteIfExists(next);}catch(IOException ignored){}}
            });records=state.records().size();saves++;maxSaveNanos=Math.max(maxSaveNanos,System.nanoTime()-start);
        }
        public SyncState load()throws Exception {byte[] plain=envelope.open(Files.readAllBytes(base));try{return SyncState.decode(plain,new byte[32],local);}finally{Crypto.wipe(plain);}}
    }
    static SyncState fixture(boolean xml)throws Exception {
        var base=new SyncState(new byte[32],id(1));
        for(int n=0;n<4096;n++){
            String uid=String.format(java.util.Locale.ROOT,"%04d",n)+"x".repeat(252);
            CotRecord item=xml?CotRecord.record(uid,NOW,id(1),NOW+60000,("<event uid=\""+uid+"\" stale=\""+Instant.ofEpochMilli(NOW+60000)+"\"/>").getBytes(StandardCharsets.UTF_8),0):CotRecord.tombstone(uid,NOW,id(1),0);
            base.put(item,NOW);
        }
        return base;
    }
    private record Message(int from,int to,byte[] session,byte[] wire){@Override public String toString(){return "Capacity fixture message";}}
    @Test public void encryptedDiskWorstAcceptedUidCatchupAndHeapReport()throws Exception {
        var report=new StringBuilder("PC; UID UTF8=256 bytes, 4096 records; real monotonic 30s deadline; AES-GCM+fsync+atomic rename primary and encrypted cache; no ATAK imports\n");
        for(boolean xml:new boolean[]{false,true}){
            Path root=Files.createTempDirectory("distributak-capacity-");var nodes=new CotSync[2];var caches=new SyncCache[2];var disks=new ColdFileStore[2];var primary=new Primary[2];
            var queue=new ArrayDeque<Message>();long start=0,initialize=System.nanoTime(),peakHeap=0,peakHot=0,peakDisk=0;int peakFiles=0,peakRefs=0;
            try{
                var envelope=new StateEnvelope(new StateEnvelopeTest.TestCipher());var clock=Clock.fixed(Instant.ofEpochMilli(NOW),ZoneOffset.UTC);
                for(int n=0;n<2;n++){
                    Path dir=Files.createDirectory(root.resolve("node-"+n));primary[n]=new Primary(dir,id(n+1),envelope);
                    primary[n].save(n==0?fixture(xml):new SyncState(new byte[32],id(2)));
                    disks[n]=new ColdFileStore(dir.resolve("sync-cache").toFile(),envelope,new byte[32],id(n+1),ColdFileStore.DEFAULT_BYTES,ColdFileStore.DEFAULT_FILES);
                    caches[n]=new SyncCache(disks[n],4*1024*1024,8192,System::nanoTime);int index=n;
                    nodes[n]=new CotSync(id(n+1),primary[n].load(),clock,System::nanoTime,primary[n],(peer,session,wire)->{queue.add(new Message(index,peer[0]-1,session.clone(),wire.clone()));return true;},r->{},new SecureRandom(),0,new ExternalMarks(new byte[32],id(n+1)),m->{},SyncLimits.DEFAULT,caches[n]);
                }
                initialize=System.nanoTime()-initialize;start=System.nanoTime();byte[] session=new byte[16];session[0]=1;
                nodes[0].connected(id(2),session);nodes[1].connected(id(1),session);
                System.gc();long retainedBefore=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
                long handled=0;
                while(System.nanoTime()-start<CotSync.CATCHUP_NANOS&&primary[1].records<4096){
                    for(var node:nodes)node.poll();
                    for(Message message;(message=queue.poll())!=null;){
                        assertTrue(++handled<200000);nodes[message.to].receive(id(message.from+1),message.session,message.wire);
                        if(handled%32==0){
                            peakHeap=Math.max(peakHeap,Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory());
                            for(int n=0;n<2;n++){peakHot=Math.max(peakHot,caches[n].hotBytes());peakDisk=Math.max(peakDisk,disks[n].bytes());peakFiles=Math.max(peakFiles,disks[n].files());peakRefs=Math.max(peakRefs,caches[n].references());}
                        }
                        if(System.nanoTime()-start>=CotSync.CATCHUP_NANOS)break;
                    }
                    if(queue.isEmpty()&&primary[1].records<4096)Thread.sleep(1);
                }
                double seconds=(System.nanoTime()-start)/1e9;
                System.gc();long retainedAfter=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
                report.append("xml=").append(xml).append(" records=").append(primary[1].records).append(" catchup_s=").append(seconds).append(" initialization_s=").append(initialize/1e9)
                    .append(" post_gc_jvm_before=").append(retainedBefore).append(" post_gc_jvm_after=").append(retainedAfter).append(" failed=").append(nodes[0].statistics().failed()).append('/').append(nodes[1].statistics().failed()).append(" primary_saves=").append(primary[1].saves)
                    .append(" max_save_ms=").append(primary[1].maxSaveNanos/1e6).append(" peak_sampled_jvm_used=").append(peakHeap).append(" peak_cache_hot_per_node=").append(peakHot)
                    .append(" peak_cache_disk_per_node=").append(peakDisk).append(" peak_cache_files_per_node=").append(peakFiles).append(" peak_cache_refs_per_node=").append(peakRefs).append('\n');
                Path output=Path.of("../../../../out/reviews/20261112-distributak-cot-sync/offload-capacity-fix2.txt").toAbsolutePath().normalize();Files.createDirectories(output.getParent());Files.write(output,report.toString().getBytes(StandardCharsets.UTF_8));
                assertEquals(report.toString(),4096,primary[1].records);assertTrue(report.toString(),seconds<30);
                for(var node:nodes)assertEquals(0,node.statistics().failed());assertEquals(4096,primary[1].load().records().size());
                assertTrue(peakHot<=4*1024*1024);assertTrue(peakDisk<=ColdFileStore.DEFAULT_BYTES);assertTrue(peakFiles<=ColdFileStore.DEFAULT_FILES);
            }finally{
                for(var node:nodes)if(node!=null)node.close();
                try(var paths=Files.walk(root)){for(Path path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
            }
        }
    }
}
