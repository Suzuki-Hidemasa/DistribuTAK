// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * 停止の印を固定領域へ書き、同期まで成功したときだけ確定する（04 §4.5）。
 * <p>
 * Writes stop markers in a fixed region and commits only after synchronization succeeds (04 §4.5).
 */
final class StopMarker {
    static final int BYTES=256,SLOT_BYTES=128,MAGIC=0x4454534d;
    static final int RECEIVED=1,RECOVERY=2;
    enum Status {CLEAR,ACTIVE,INVALID}
    interface Region {
        byte[] read()throws IOException;
        void allocate()throws IOException;
        void write(int offset,byte[] bytes)throws IOException;
        void sync()throws IOException;
    }
    interface Wait {void sleep(long millis)throws InterruptedException;}
    record Target(long saveSeq,long requiredVersion,byte[] stateDigest,byte[] revocationDigest,int reason){
        Target {
            if(saveSeq<0||requiredVersion<0||reason!=RECEIVED&&reason!=RECOVERY)throw new IllegalArgumentException("Invalid stop requirement");
            if(stateDigest==null||stateDigest.length!=32||revocationDigest==null||revocationDigest.length!=32)
                throw new IllegalArgumentException("Invalid stop requirement length");
            stateDigest=stateDigest.clone();revocationDigest=revocationDigest.clone();
        }
        @Override public byte[] stateDigest(){return stateDigest.clone();}
        @Override public byte[] revocationDigest(){return revocationDigest.clone();}
        boolean candidateLess(){return Arrays.equals(stateDigest,new byte[32])&&Arrays.equals(revocationDigest,new byte[32]);}
        boolean matches(Target other){return !candidateLess()&&sameRequirement(other);}
        boolean sameRequirement(Target other){return other!=null&&saveSeq==other.saveSeq&&requiredVersion==other.requiredVersion
                &&reason==other.reason&&Arrays.equals(stateDigest,other.stateDigest)&&Arrays.equals(revocationDigest,other.revocationDigest);}
        @Override public String toString(){return "Stop marker target";}
    }
    record Inspection(Status status,Target target,long sequence){
        @Override public String toString(){return "Stop marker inspection";}
    }
    private record Slot(boolean active,long sequence,Target target){}
    private final Region region;
    private final Wait wait;
    StopMarker(Region region,Wait wait){this.region=java.util.Objects.requireNonNull(region);this.wait=java.util.Objects.requireNonNull(wait);}
    synchronized void initialize(Target target)throws IOException{
        byte[] existing=region.read();
        if(existing!=null&&existing.length!=0){
            var current=inspect();
            if(current.status==Status.CLEAR&&target.matches(current.target))return;
            throw new IOException("Stop marker already exists");
        }
        retry(()->region.allocate());writePair(target,false,0,0);
    }
    /**
     * 検証済み旧形式の初期確保だけに使う。部分領域は根拠にせず、有効なactiveを上書きしない。
     * <p>
     * Used only for initial allocation from verified legacy state. Never trusts partial regions or overwrites valid active slots.
     */
    synchronized void initializeMigration(Target target)throws IOException{
        byte[] existing=region.read();long previous=0;
        if(!canInitializeMigration(existing,target.requiredVersion(),target.revocationDigest()))
            throw new IOException("Existing stop requirements must be retained");
        if(existing!=null&&existing.length==BYTES){
            Slot a=decode(Arrays.copyOfRange(existing,0,SLOT_BYTES)),b=decode(Arrays.copyOfRange(existing,SLOT_BYTES,BYTES));
            for(Slot slot:new Slot[]{a,b})if(slot!=null){
                previous=Math.max(previous,slot.sequence);
            }
            var current=inspect();if(current.status==Status.CLEAR&&target.matches(current.target))return;
        }
        retry(()->region.allocate());writePair(target,false,previous,0);
    }
    synchronized boolean canInitializeMigration(long requiredVersion,byte[] revocationDigest)throws IOException{
        return canInitializeMigration(region.read(),requiredVersion,revocationDigest);
    }
    private static boolean canInitializeMigration(byte[] existing,long requiredVersion,byte[] revocationDigest){
        // 初回確保の途中は未作成か全ゼロだけ。検証できたスロットがすべて clear で、版・R が合う場合は決定 B の規則を保つ。
        // Initial allocation permits only missing or all-zero regions; decision B's rules are retained when all verified slots are clear and their versions and R match.
        if(existing==null)return true;
        if(existing.length>BYTES)return false;
        if(Arrays.equals(existing,new byte[existing.length]))return true;
        if(existing.length!=BYTES)return false;
        Slot a=decode(Arrays.copyOfRange(existing,0,SLOT_BYTES)),b=decode(Arrays.copyOfRange(existing,SLOT_BYTES,BYTES));
        if(a==null&&b==null)return false;
        for(Slot slot:new Slot[]{a,b})if(slot!=null&&(slot.active||slot.target.requiredVersion()!=requiredVersion
                ||!Arrays.equals(slot.target.revocationDigest(),revocationDigest)))return false;
        return true;
    }
    synchronized void active(Target target)throws IOException{update(target,true);}
    synchronized void clear(Target target)throws IOException{update(target,false);}
    private void update(Target target,boolean active)throws IOException{
        var current=inspect();if(current.status==Status.INVALID)throw new IOException("Invalid stop marker");
        byte[] bytes=region.read();
        if(bytes==null||bytes.length!=BYTES)throw new IOException("Invalid stop marker");
        long firstSequence=ByteBuffer.wrap(bytes,8,8).getLong(),secondSequence=ByteBuffer.wrap(bytes,136,8).getLong();
        // 古いスロットから書き、片側だけのactiveをclearの途中で失わない。
        // Write the older slot first to retain a lone active marker during clear.
        writePair(target,active,current.sequence,firstSequence<secondSequence?0:SLOT_BYTES);
    }
    private void writePair(Target target,boolean active,long previous,int firstOffset)throws IOException{
        if(previous<0||previous>Long.MAX_VALUE-2)throw new IOException("Stop marker sequence exhausted");
        byte[] first=encode(new Slot(active,previous+1,target)),second=encode(new Slot(active,previous+2,target));
        retry(()->{region.write(firstOffset,first);region.sync();region.write(SLOT_BYTES-firstOffset,second);region.sync();});
    }
    private interface Attempt {void run()throws IOException;}
    private void retry(Attempt attempt)throws IOException{
        for(int i=0;;i++){
            try{attempt.run();return;}
            catch(IOException failure){
                if(i==2)throw failure;
                try{wait.sleep(100);}catch(InterruptedException interrupted){
                    Thread.currentThread().interrupt();throw new IOException("Stop marker retry interrupted",interrupted);
                }
            }
        }
    }
    synchronized Inspection inspect()throws IOException{
        byte[] bytes=region.read();if(bytes==null||bytes.length!=BYTES)return invalid();
        Slot a=decode(Arrays.copyOfRange(bytes,0,SLOT_BYTES)),b=decode(Arrays.copyOfRange(bytes,SLOT_BYTES,BYTES));
        if(a==null||b==null||a.sequence==b.sequence)return invalid();
        Slot latest=a.sequence>b.sequence?a:b,older=latest==a?b:a;
        if(latest.sequence-older.sequence!=1)return invalid();
        if(a.target.sameRequirement(b.target))return new Inspection(a.active||b.active?Status.ACTIVE:Status.CLEAR,latest.target,latest.sequence);
        if(latest.active)return new Inspection(Status.ACTIVE,latest.target,latest.sequence);
        return invalid();
    }
    private static Inspection invalid(){return new Inspection(Status.INVALID,null,0);}
    private static byte[] encode(Slot slot){
        var buffer=ByteBuffer.allocate(SLOT_BYTES);var t=slot.target;
        buffer.putInt(MAGIC).put((byte)1).put((byte)(slot.active?1:0)).put((byte)t.reason).put((byte)0)
                .putLong(slot.sequence).putLong(t.saveSeq).putLong(t.requiredVersion).put(t.stateDigest).put(t.revocationDigest);
        buffer.put(Crypto.blake2s(Arrays.copyOf(buffer.array(),96)));return buffer.array();
    }
    private static Slot decode(byte[] bytes){
        if(!Crypto.equal(Crypto.blake2s(Arrays.copyOf(bytes,96)),Arrays.copyOfRange(bytes,96,128)))return null;
        var in=ByteBuffer.wrap(bytes);
        if(in.getInt()!=MAGIC||in.get()!=1)return null;
        int flag=in.get(),reason=in.get();if(flag!=0&&flag!=1||reason!=RECEIVED&&reason!=RECOVERY||in.get()!=0)return null;
        long sequence=in.getLong(),seq=in.getLong(),version=in.getLong();if(sequence<=0||seq<0||version<0)return null;
        byte[] state=new byte[32],union=new byte[32];in.get(state);in.get(union);
        return new Slot(flag==1,sequence,new Target(seq,version,state,union,reason));
    }
    /**
     * 同じファイルの同じ領域を使う。確保では全256Bを書き、一時ファイルやrenameを使わない。
     * <p>
     * Uses the same region of the same file. Allocation writes all 256 bytes without temporary files or rename.
     */
    static final class FileRegion implements Region {
        interface DirectorySync {void sync()throws IOException;}
        private final File file;
        private final DirectorySync directorySync;
        FileRegion(File file,DirectorySync directorySync){this.file=java.util.Objects.requireNonNull(file);this.directorySync=java.util.Objects.requireNonNull(directorySync);}
        public byte[] read()throws IOException{
            if(!file.exists())return null;
            try(var input=new RandomAccessFile(file,"r")){
                if(input.length()>BYTES)return new byte[BYTES+1];
                byte[] result=new byte[(int)input.length()];input.readFully(result);return result;
            }
        }
        public void allocate()throws IOException{
            try(var output=new RandomAccessFile(file,"rw")){
                output.setLength(BYTES);output.seek(0);output.write(new byte[BYTES]);output.getFD().sync();
            }
            directorySync.sync();
        }
        public void write(int offset,byte[] bytes)throws IOException{
            if(offset!=0&&offset!=SLOT_BYTES||bytes.length!=SLOT_BYTES)throw new IOException("Invalid stop marker slot");
            try(var output=new RandomAccessFile(file,"rw")){
                if(output.length()!=BYTES)throw new IOException("Missing stop marker region");
                output.seek(offset);output.write(bytes);
            }
        }
        public void sync()throws IOException{try(var output=new RandomAccessFile(file,"rw")){output.getFD().sync();}}
    }
}
