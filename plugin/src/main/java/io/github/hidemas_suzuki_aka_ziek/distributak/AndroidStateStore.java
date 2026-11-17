// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.content.Context;
import android.security.keystore.*;
import android.util.AtomicFile;
import java.io.*;
import java.security.*;
import java.time.Clock;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.ExternalMarks;

/** ATAKのUIDの内部領域だけを使う。操作はControllerの作業スレッドと核のjoinスレッドから呼ぶ。
 * 同時には呼ばず、Controllerが口のcloseでjoinの終了を待ってから確定・取消・消去する。 */
final class AndroidStateStore implements LanRuntime.Storage {
    private static final String ALIAS="io.github.hidemas_suzuki_aka_ziek.distributak.wrap.v1";
    private final AtomicFile state,settings,completed,joining,sync,external;
    private final File directory;
    private final StateEnvelope envelope;
    private final GroupStateStorage groups;
    int port;
    boolean erased;
    AndroidStateStore(Context host)throws Exception {
        directory=directory(host);
        ColdFileStore.clearDirectory(new File(directory,"sync-cache"));
        StoreRecovery.resume(eraseTarget(directory,()->{},()->{}),initialTarget(directory));
        joining=new AtomicFile(new File(directory,"joining.bin"));delete(joining);
        state=new AtomicFile(new File(directory,"state.bin"));settings=new AtomicFile(new File(directory,"settings.bin"));
        completed=new AtomicFile(new File(directory,"erased.bin"));
        sync=new AtomicFile(new File(directory,"sync.bin"));
        external=new AtomicFile(new File(directory,"external.bin"));
        erased=exists(completed);
        envelope=new StateEnvelope(new StateEnvelope.CipherBox(){
            public StateEnvelope.Sealed seal(byte[] plain,byte[] aad)throws Exception {
                Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key(true));cipher.updateAAD(aad);
                return new StateEnvelope.Sealed(cipher.getIV(),cipher.doFinal(plain));
            }
            public byte[] open(byte[] iv,byte[] ciphertext,byte[] aad)throws Exception {
                Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(false),new GCMParameterSpec(128,iv));
                cipher.updateAAD(aad);return cipher.doFinal(ciphertext);
            }
        });
        groups=new GroupStateStorage(envelope,new Target(state),source(state,StateEnvelope.MAX_BYTES),new Target(settings),source(settings,StateSettings.MAX_BYTES),
                fixed->android.util.Log.i(LanController.TAG,fixed),new DiskManagementFiles(directory,()->{
                    try{var descriptor=android.system.Os.open(directory.getPath(),android.system.OsConstants.O_RDONLY,0);
                        try{android.system.Os.fsync(descriptor);}finally{android.system.Os.close(descriptor);}
                    }catch(android.system.ErrnoException e){throw new IOException("管理保存先を同期できません",e);}
                }),new StopMarker(new StopMarker.FileRegion(new File(directory,"stop-marker.bin"),()->{
                    try{var descriptor=android.system.Os.open(directory.getPath(),android.system.OsConstants.O_RDONLY,0);
                        try{android.system.Os.fsync(descriptor);}finally{android.system.Os.close(descriptor);}
                    }catch(android.system.ErrnoException e){throw new IOException("停止印の保存先を同期できません",e);}
                }),Thread::sleep));
        boolean valid=false,usableState=exists(state)&&!erased;
        if(exists(settings)) {
            try {
                byte[] config=read(settings,StateSettings.MAX_BYTES);
                try {
                    port=StateSettings.decode(config).port;valid=true;
                }finally{Crypto.wipe(config);}
            }catch(IOException|RuntimeException e){if(!usableState)throw e;}
        }else if(!usableState) {port=LanSupport.port(null,new SecureRandom());writeSettings(port,false);valid=true;}
        if(!valid&&!usableState)throw new SecurityException("設定がありません");
    }
    private static File directory(Context host)throws IOException {
        File directory=new File(host.getApplicationContext().getNoBackupFilesDir(),"distributak");
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("保存先を開けません");return directory;
    }
    private static void marker(AtomicFile file)throws IOException {
        FileOutputStream stream=file.startWrite();
        try{stream.write(1);file.finishWrite(stream);}
        catch(IOException|RuntimeException e){file.failWrite(stream);throw e;}
    }
    private static void delete(AtomicFile file)throws IOException {
        file.delete();StoreFiles.remove(file.getBaseFile());
    }
    private static StoreRecovery.EraseTarget eraseTarget(File directory,Runnable stop,Runnable wipe) {
        return recoveryTarget(directory,stop,wipe,false);
    }
    private static StoreRecovery.EraseTarget initialTarget(File directory) {
        return recoveryTarget(directory,()->{},()->{},true);
    }
    private static StoreRecovery.EraseTarget recoveryTarget(File directory,Runnable stop,Runnable wipe,boolean initial) {
        AtomicFile pending=new AtomicFile(new File(directory,initial?"initial.pending":"erase.pending"));
        return new StoreRecovery.EraseTarget(){
            public boolean pending(){return exists(pending);}
            public void markPending()throws Exception{marker(pending);}
            public void stop(){stop.run();}
            public void deleteKey()throws Exception{AndroidStateStore.deleteKey();}
            public void deleteRecords()throws Exception{
                StoreFiles.deleteRecords(directory,file->new AtomicFile(file).delete());
            }
            public void markComplete()throws Exception{if(!initial)marker(new AtomicFile(new File(directory,"erased.bin")));}
            public void wipeMemory(){wipe.run();}
            public void clearPending()throws Exception{delete(pending);}
        };
    }
    static AndroidStateStore erase(Context host,Runnable stop,Runnable wipe)throws Exception {
        StoreRecovery.erase(eraseTarget(directory(host),stop,wipe));return new AndroidStateStore(host);
    }
    private static boolean exists(AtomicFile file){return file.getBaseFile().exists()||new File(file.getBaseFile()+".bak").exists();}
    private SecretKey key(boolean create)throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        if(store.containsAlias(ALIAS))return (SecretKey)store.getKey(ALIAS,null);
        if(!create || exists(state)||exists(sync)||new File(sync.getBaseFile()+".new").exists()||exists(external)||new File(external.getBaseFile()+".new").exists())throw new SecurityException("保存用の鍵がありません");
        KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false).build());
        return generator.generateKey();
    }
    private static void deleteKey()throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);store.deleteEntry(ALIAS);
    }
    private static byte[] read(AtomicFile file,int maximum)throws IOException {
        try(var in=file.openRead();var out=new ByteArrayOutputStream()) {
            byte[] buffer=new byte[4096];
            for(int count;(count=in.read(buffer))!=-1;) {
                if(out.size()+count>maximum)throw new IOException("保存の上限を超えています");out.write(buffer,0,count);
            }
            return out.toByteArray();
        }
    }
    private static final class Target implements StateEnvelope.AtomicTarget {
        final AtomicFile file;FileOutputStream stream;
        Target(AtomicFile file){this.file=file;}
        public void begin()throws IOException {stream=file.startWrite();}
        public void write(byte[] bytes)throws IOException {stream.write(bytes);}
        public void commit(){file.finishWrite(stream);stream=null;}
        public void rollback(){file.failWrite(stream);stream=null;}
    }
    private static SyncStateStorage.Source source(AtomicFile file,int maximum) {
        return new SyncStateStorage.Source(){
            public boolean exists(){return AndroidStateStore.exists(file);}
            public byte[] read()throws Exception{return AndroidStateStore.read(file,maximum);}
        };
    }
    private void writeSettings(int port,boolean erased)throws Exception {
        if(erased)throw new SecurityException("設定の値が違います");
        StateEnvelope.writeAtomic(new StateSettings(port,0,0,0,0).encode(),new Target(settings));this.port=port;
    }
    public int port(){return port;}
    public boolean erased(){return erased;}
    public boolean erasing(){return exists(new AtomicFile(new File(directory,"erase.pending")))
            ||exists(new AtomicFile(new File(directory,"initial.pending")));}
    private StoreRecovery.EraseTarget newStateTarget(){return erased?eraseTarget(directory,()->{},()->{}):initialTarget(directory);}
    public void create(LanGroup group)throws Exception {
        if(!StoreRecovery.canCreate(exists(state)&&!erased,erasing()))throw new SecurityException("作成できません");
        try {
            StoreRecovery.create(newStateTarget(),()->save(group),()->delete(completed));
            erased=false;
        }catch(Exception e){erased=exists(completed);throw e;}
    }
    public LanGroup load(Clock clock)throws Exception {
        if(erased||!exists(state))return null;
        LanGroup group=groups.load(clock);
        if(group!=null){if(group.port!=port)android.util.Log.i(LanController.TAG,"LAN_PORT_RESTORED");port=group.port;}
        return group;
    }
    public void save(LanGroup group)throws Exception {
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");groups.save(group);
    }
    public io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.PersistenceHooks persistenceHooks(LanGroup group){return groups.persistenceHooks(group);}
    public void saveDirectory(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.MemberDirectory directory,java.util.Map<String,String> labels)throws Exception{
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");groups.saveDirectory(group,directory,labels);
    }
    public void prepareNetwork(LanGroup group)throws Exception{groups.prepareNetwork(group);}
    public void saveMembership(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordStore.Snapshot snapshot,byte[] secret)throws Exception{
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");groups.saveMembership(group,snapshot,secret);
    }
    public boolean largeState(){return groups.largeState();}
    public boolean saveIssuedRenewal(LanGroup group,byte[] peerId,byte[] certificate)throws Exception {
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");return groups.saveIssuedRenewal(group,peerId,certificate);
    }
    public boolean saveLocalRenewal(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record certificate)throws Exception {
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");return groups.saveLocalRenewal(group,certificate);
    }
    public boolean savePeer(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record certificate,java.net.InetSocketAddress address)throws Exception {
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");return groups.savePeer(group,certificate,address);
    }
    /** DHT の記録の次の版を予約して保存する（04 の 8.3）。呼ぶスレッドは save と同じ。この回は画面・DhtPublisher につながない。 */
    public long reserveDhtVersion(LanGroup group)throws Exception {
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");return groups.reserveDhtVersion(group);
    }
    private SyncStateStorage syncStorage() {
        return new SyncStateStorage(envelope,new Target(sync),new SyncStateStorage.Source(){
            public boolean exists(){return AndroidStateStore.exists(sync);}
            public byte[] read()throws Exception{return AndroidStateStore.read(sync,StateEnvelope.SYNC_MAX_BYTES);}
        },externalStorage());
    }
    private ExternalStateStorage externalStorage(){return new ExternalStateStorage(envelope,new Target(external),new SyncStateStorage.Source(){
        public boolean exists(){return AndroidStateStore.exists(external);}
        public byte[] read()throws Exception{return AndroidStateStore.read(external,ExternalMarks.MAX_ENVELOPE_BYTES);}
    });}
    public io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncSpill openSpill(LanGroup group){
        return new ColdFileStore(new File(directory,"sync-cache"),envelope,group.groupId,group.id(),ColdFileStore.DEFAULT_BYTES,ColdFileStore.DEFAULT_FILES);
    }
    public ExternalMarks loadExternal(LanGroup group)throws Exception{return externalStorage().load(group);}
    public void saveExternal(LanGroup group,ExternalMarks marks)throws Exception{externalStorage().save(group,marks);}
    public SyncState loadSync(LanGroup group)throws Exception{return syncStorage().load(group,()->save(group));}
    public void saveSync(LanGroup group,SyncState snapshot)throws Exception{syncStorage().save(group,snapshot);}
    public byte[] loadSyncEncoded(LanGroup group)throws Exception{return syncStorage().readEncoded(group);}
    public void saveSyncEncoded(LanGroup group,SyncState snapshot,byte[] encoded)throws Exception{syncStorage().saveEncoded(group,snapshot,encoded);}
    public LanRuntime.Pending stage(LanGroup group)throws Exception {
        if(group.port!=port)throw new SecurityException("ポートの記録が違います");
        return groups.stage(group,new Target(joining),()->read(joining,StateEnvelope.MAX_BYTES),()->delete(joining));
    }
    public void acceptJoined(java.util.concurrent.Future<?> future,LanRuntime.Pending staged)throws Exception {
        try {
            StoreRecovery.acceptJoined(future,newStateTarget(),()->{
                if(staged==null)throw new SecurityException("加入の保存がありません");staged.commit();
            },()->delete(completed));
            erased=false;
        }catch(Exception e){erased=exists(completed);throw e;}
    }
    public void acceptRejoined(java.util.concurrent.Future<?> future,LanGroup previous,LanGroup candidate,LanRuntime.Pending staged)throws Exception {
        if(erased||erasing()||!exists(state))throw new SecurityException("入り直しの保存がありません");
        groups.acceptRejoined(previous,candidate,future,staged);
    }
    public void setPort(int next,LanGroup group)throws Exception {
        LanSupport.port(next,new SecureRandom());
        int previous=port;
        if(group!=null) {
            group.port=next;
            try{groups.save(group);}catch(Exception e){group.port=previous;throw e;}
            port=next;
        }else writeSettings(next,false);
    }
}
