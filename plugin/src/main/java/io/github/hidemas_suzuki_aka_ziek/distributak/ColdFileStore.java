// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** workerだけで使う、消して取り直せる暗号化キャッシュ。 */
final class ColdFileStore implements SyncSpill {
    static final long DEFAULT_BYTES=64L*1024*1024;
    static final int DEFAULT_FILES=8192,MAX_FILE_BYTES=256*1024;
    private static final byte[] PURPOSE="distributak-sync-cache-v1".getBytes(StandardCharsets.US_ASCII);
    private static final int MAGIC=0x44544b43,HEADER_BYTES=4+4+PURPOSE.length+32+32+32+4;
    private final File directory;
    private final StateEnvelope envelope;
    private final byte[] group,local;
    private final long maximum;
    private final int fileLimit;
    private final Thread owner=Thread.currentThread();
    private final Map<String,Long> sizes=new HashMap<>();
    private long total;private boolean writable=true;
    ColdFileStore(File directory,StateEnvelope envelope,byte[] group,byte[] local,long maximum,int fileLimit){
        length(group);length(local);if(maximum<=0||fileLimit<=0)throw new IllegalArgumentException("退避の上限が範囲外です");
        try{this.directory=checked(directory);if(!this.directory.isDirectory()&&!this.directory.mkdirs())throw new IOException();clearDirectory(this.directory);}
        catch(IOException e){throw new IllegalStateException("退避の置き場を開けません");}
        this.envelope=envelope.withMaximum(MAX_FILE_BYTES);this.group=group.clone();this.local=local.clone();this.maximum=maximum;this.fileLimit=fileLimit;
    }
    private static File checked(File directory)throws IOException {
        File absolute=directory.getAbsoluteFile(),parent=absolute.getParentFile().getCanonicalFile();File expected=new File(parent,absolute.getName());
        if(!absolute.getCanonicalFile().equals(expected))throw new IOException();return expected;
    }
    static void clearDirectory(File directory)throws IOException {
        File target=checked(directory);if(!target.exists())return;File[] files=target.listFiles();if(files==null)throw new IOException("退避を片付けられません");
        // 平らな専用領域だけを消す。シンボリックリンクや他の領域をたどらない。
        for(File file:files)if(!file.delete())throw new IOException("退避を片付けられません");
    }
    private void worker(){if(Thread.currentThread()!=owner)throw new IllegalStateException("退避の入出力は作業スレッドで行ってください");}
    private static void length(byte[] value){if(value==null||value.length!=32)throw new IllegalArgumentException("退避の識別子が範囲外です");}
    private static String name(byte[] key){length(key);var out=new StringBuilder(68);for(byte value:key){out.append(Character.forDigit((value>>>4)&15,16));out.append(Character.forDigit(value&15,16));}return out.append(".bin").toString();}
    private File file(String name){return new File(directory,name);}
    private void forget(String name){Long before=sizes.remove(name);if(before!=null)total-=before;}
    public boolean put(byte[] key,byte[] plaintext){
        worker();String name=name(key);if(plaintext==null)throw new IllegalArgumentException("退避する中身がありません");
        long needed=(long)HEADER_BYTES+plaintext.length+38;
        if(!writable||needed>MAX_FILE_BYTES||total+needed>maximum||sizes.size()+(sizes.containsKey(name)?1:2)>fileLimit)return false;
        File base=file(name),next=file(name+".new");byte[] plain=null,wire=null;
        try{
            if(!base.getCanonicalFile().equals(base)||!next.getCanonicalFile().equals(next))return false;
            if(next.exists()&&!next.delete()){writable=false;return false;}
            var out=ByteBuffer.allocate(HEADER_BYTES+plaintext.length);out.putInt(MAGIC).putInt(1).put(PURPOSE).put(group).put(local).put(key).putInt(plaintext.length).put(plaintext);plain=out.array();
            wire=envelope.seal(plain);
            try(var stream=new FileOutputStream(next)){stream.write(wire);stream.getFD().sync();}
            // 同じ内部領域で、暗号文の.newを原子的に取り替える。失敗時は前のbaseを残す。
            if(!next.renameTo(base))return false;
            forget(name);sizes.put(name,(long)wire.length);total+=wire.length;return true;
        }catch(Exception e){return false;}
        finally{Crypto.wipe(plain);Crypto.wipe(wire);if(next.exists()&&!next.delete()){writable=false;String abandoned=name+".new";forget(abandoned);sizes.put(abandoned,next.length());total+=next.length();}}
    }
    public byte[] get(byte[] key){
        worker();String name=name(key);File base=file(name);byte[] wire=null,plain=null;
        try{
            if(!base.exists()){forget(name);return null;}
            if(!base.getCanonicalFile().equals(base)||base.length()>MAX_FILE_BYTES)throw new IOException();
            try(var stream=new FileInputStream(base);var out=new ByteArrayOutputStream()){
                byte[] buffer=new byte[4096];for(int count;(count=stream.read(buffer))!=-1;){if(out.size()+count>MAX_FILE_BYTES)throw new IOException();out.write(buffer,0,count);}wire=out.toByteArray();
            }
            plain=envelope.open(wire);if(plain.length<HEADER_BYTES)throw new IOException();
            var input=ByteBuffer.wrap(plain);byte[] purpose=new byte[PURPOSE.length],storedGroup=new byte[32],storedLocal=new byte[32],storedKey=new byte[32];
            if(input.getInt()!=MAGIC||input.getInt()!=1)throw new IOException();input.get(purpose).get(storedGroup).get(storedLocal).get(storedKey);int length=input.getInt();
            if(!Arrays.equals(PURPOSE,purpose)||!Crypto.equal(group,storedGroup)||!Crypto.equal(local,storedLocal)||!Crypto.equal(key,storedKey)||length<0||length!=input.remaining())throw new IOException();
            if(!sizes.containsKey(name)){
                if(sizes.size()>=fileLimit||total+wire.length>maximum)throw new IOException();sizes.put(name,(long)wire.length);total+=wire.length;
            }
            return Arrays.copyOfRange(plain,HEADER_BYTES,plain.length);
        }catch(Exception e){remove(key);return null;}
        finally{Crypto.wipe(wire);Crypto.wipe(plain);}
    }
    public void remove(byte[] key){
        worker();String name=name(key);
        for(String suffix:new String[]{"",".bak",".new"}){
            File target=file(name+suffix);if(target.exists()&&!target.delete()){
                writable=false;forget(name+suffix);sizes.put(name+suffix,target.length());total+=target.length();
            }else forget(name+suffix);
        }
    }
    public void clear(){worker();try{clearDirectory(directory);}catch(IOException e){throw new IllegalStateException("退避を片付けられません");}sizes.clear();total=0;writable=true;}
    public long bytes(){worker();return total;}
    public int files(){worker();return sizes.size();}
}
