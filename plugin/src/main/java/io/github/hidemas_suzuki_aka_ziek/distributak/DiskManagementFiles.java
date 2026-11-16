// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.*;

/**
 * 孤立世代も採番には数えるが、復元には使わない。
 * <p>
 * Counts orphan generations when allocating numbers but never uses them for restoration.
 */
final class DiskManagementFiles implements ManagementFiles {
    interface DirectorySync {void sync()throws IOException;}
    private final File directory;
    private final DirectorySync sync;
    DiskManagementFiles(File directory,DirectorySync sync)throws IOException{
        this.directory=directory;this.sync=sync;
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("管理保存先を開けません");
    }
    private static Long generation(String name){
        if(!name.matches("management-[1-9][0-9]*\\.bin(?:\\.part)?"))return null;
        try{return Long.parseLong(name.substring(11,name.indexOf('.')));}catch(NumberFormatException e){return null;}
    }
    public synchronized long nextGeneration()throws IOException{
        File[] entries=directory.listFiles();if(entries==null)throw new IOException("管理世代を調べられません");long max=0;
        for(File entry:entries){Long n=generation(entry.getName());if(n!=null)max=Math.max(max,n);}
        if(max==Long.MAX_VALUE)throw new IOException("管理世代が上限です");return max+1;
    }
    private File file(long generation)throws IOException{if(generation<=0)throw new IOException("管理世代が違います");return new File(directory,"management-"+generation+".bin");}
    public synchronized void write(long generation,byte[] wire)throws IOException{
        if(wire.length>ManagementState.MAX_ENVELOPE_BYTES)throw new IOException("管理保存が上限です");
        File complete=file(generation),temporary=new File(complete+".part");
        if(complete.exists()||!temporary.createNewFile())throw new IOException("管理世代は変更できません");
        try(var output=new FileOutputStream(temporary)){output.write(wire);output.getFD().sync();}
        if(complete.exists()||!temporary.renameTo(complete))throw new IOException("管理世代を確定できません");sync.sync();
    }
    public byte[] read(long generation)throws IOException{
        File selected=file(generation);long size=selected.length();
        if(!selected.isFile()||size<38||size>ManagementState.MAX_ENVELOPE_BYTES)throw new IOException("管理ファイルの長さが違います");
        try(var input=new DataInputStream(new FileInputStream(selected))){byte[] result=new byte[(int)size];input.readFully(result);if(input.read()!=-1)throw new IOException("管理ファイルが変わっています");return result;}
    }
    public boolean hasSpace(long bytes){return bytes>=0&&directory.getUsableSpace()>=bytes;}
    public synchronized void cleanup(long retained)throws IOException{
        File[] entries=directory.listFiles();if(entries==null)throw new IOException("管理世代を調べられません");
        for(File entry:entries){Long n=generation(entry.getName());if(n!=null&&(n!=retained||entry.getName().endsWith(".part"))&&!entry.delete())throw new IOException("旧管理世代を消せません");}sync.sync();
    }
}
