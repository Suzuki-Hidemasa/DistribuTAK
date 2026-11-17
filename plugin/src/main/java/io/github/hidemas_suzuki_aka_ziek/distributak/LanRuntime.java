// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.*;
import java.time.Clock;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Future;
import java.util.function.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.ExternalMarks;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncLimits;

/** 制御の順序をAndroidから切り離す保存・回線・待ち行列。 */
final class LanRuntime {
    interface Tasks extends AutoCloseable {
        void execute(Runnable task);
        void repeat(Runnable task);
        void repeatSync(Runnable task);
        void close();
    }
    interface Link {
        Inet4Address address();
        boolean same(Link other);
        UdpEndpoint.DatagramIo open(int port)throws Exception;
        /** この Wi-Fi の IPv4 のネットマスク長。分からないときは UNKNOWN_PREFIX（DHT は動かさない）。 */
        default int prefixLength(){return io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.LocalNetwork.UNKNOWN_PREFIX;}
    }
    static final class NetworkSnapshot {
        final Link link;final long revision;
        NetworkSnapshot(Link link,long revision){this.link=link;this.revision=revision;}
    }
    interface Network extends AutoCloseable {
        Link current();
        default NetworkSnapshot snapshot(){return new NetworkSnapshot(current(),0);}
        void close();
    }
    interface NetworkFactory {Network open(Runnable changed)throws Exception;}
    interface Pending {
        void commit()throws Exception;
        void abort()throws Exception;
    }
    interface Storage {
        int port();boolean erased();boolean erasing();
        void create(LanGroup group)throws Exception;
        LanGroup load(Clock clock)throws Exception;
        void save(LanGroup group)throws Exception;
        io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncSpill openSpill(LanGroup group)throws Exception;
        SyncState loadSync(LanGroup group)throws Exception;
        void saveSync(LanGroup group,SyncState snapshot)throws Exception;
        default byte[] loadSyncEncoded(LanGroup group)throws Exception{return loadSync(group).encode();}
        default void saveSyncEncoded(LanGroup group,SyncState snapshot,byte[] encoded)throws Exception{saveSync(group,snapshot);}
        ExternalMarks loadExternal(LanGroup group)throws Exception;
        void saveExternal(LanGroup group,ExternalMarks marks)throws Exception;
        Pending stage(LanGroup group)throws Exception;
        void acceptJoined(Future<?> joined,Pending pending)throws Exception;
        default io.github.hidemas_suzuki_aka_ziek.distributak.core.CorePersistenceCoordinator.PersistenceHooks persistenceHooks(LanGroup group){
            throw new UnsupportedOperationException("管理保存の口がありません");
        }
        default void saveDirectory(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.MemberDirectory directory,java.util.Map<String,String> labels)throws Exception{
            throw new UnsupportedOperationException("名簿保存の口がありません");
        }
        default void prepareNetwork(LanGroup group)throws Exception{}
        default void saveMembership(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecordStore.Snapshot snapshot,byte[] secret)throws Exception{
            throw new UnsupportedOperationException("付与の保存の口がありません");
        }
        default boolean largeState(){return false;}
        default boolean saveIssuedRenewal(LanGroup group,byte[] peerId,byte[] certificate)throws Exception {
            throw new UnsupportedOperationException("発行済み更新の保存の口がありません");
        }
        default boolean saveLocalRenewal(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record certificate)throws Exception {
            throw new UnsupportedOperationException("更新の保存の口がありません");
        }
        default boolean savePeer(LanGroup group,io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Record certificate,InetSocketAddress address)throws Exception {
            throw new UnsupportedOperationException("相手の保存の口がありません");
        }
        default void acceptRejoined(Future<?> future,LanGroup previous,LanGroup candidate,Pending pending)throws Exception {
            throw new UnsupportedOperationException("入り直しの保存の口がありません");
        }
        /** DHT に出す記録の次の版を予約して保存する（04 の 8.3）。失敗や上限では例外。 */
        default long reserveDhtVersion(LanGroup group)throws Exception {
            throw new UnsupportedOperationException("DHT の版の保存の口がありません");
        }
        void setPort(int port,LanGroup group)throws Exception;
    }
    interface Stores {
        Storage open()throws Exception;
        Storage erase(Runnable stop,Runnable wipe)throws Exception;
    }
    final Stores stores;
    final NetworkFactory network;
    final Tasks worker;
    final Consumer<Runnable> main;
    final Consumer<String> log;
    final Runnable selfCheck;
    final Clock clock;
    final LongSupplier nanos;
    final SecureRandom random;
    interface Qr {byte[] encode(io.github.hidemas_suzuki_aka_ziek.distributak.core.Invitation invitation,int size)throws Exception;}
    final Qr qr;
    final CotPort cot;
    final SyncLimits syncLimits;
    /** DHT の公開のばらつき（0〜5 分）を引く乱数。製品は random と同じものを渡す（試験だけが決まった値を渡す）。 */
    final Random dhtJitter;
    LanRuntime(Stores stores,NetworkFactory network,Tasks worker,Consumer<Runnable> main,Consumer<String> log,
               Runnable selfCheck,Clock clock,LongSupplier nanos,SecureRandom random){
        this(stores,network,worker,main,log,selfCheck,clock,nanos,random,InvitationQr::encode);
    }
    LanRuntime(Stores stores,NetworkFactory network,Tasks worker,Consumer<Runnable> main,Consumer<String> log,
               Runnable selfCheck,Clock clock,LongSupplier nanos,SecureRandom random,Qr qr){
        this(stores,network,worker,main,log,selfCheck,clock,nanos,random,qr,CotPort.NONE);
    }
    LanRuntime(Stores stores,NetworkFactory network,Tasks worker,Consumer<Runnable> main,Consumer<String> log,
               Runnable selfCheck,Clock clock,LongSupplier nanos,SecureRandom random,Qr qr,CotPort cot){
        this(stores,network,worker,main,log,selfCheck,clock,nanos,random,qr,cot,SyncLimits.DEFAULT);
    }
    LanRuntime(Stores stores,NetworkFactory network,Tasks worker,Consumer<Runnable> main,Consumer<String> log,
               Runnable selfCheck,Clock clock,LongSupplier nanos,SecureRandom random,Qr qr,CotPort cot,SyncLimits syncLimits){
        this(stores,network,worker,main,log,selfCheck,clock,nanos,random,qr,cot,syncLimits,random);
    }
    LanRuntime(Stores stores,NetworkFactory network,Tasks worker,Consumer<Runnable> main,Consumer<String> log,
               Runnable selfCheck,Clock clock,LongSupplier nanos,SecureRandom random,Qr qr,CotPort cot,SyncLimits syncLimits,Random dhtJitter){
        this.dhtJitter=Objects.requireNonNull(dhtJitter);
        this.syncLimits=syncLimits;
        this.cot=cot;
        this.qr=qr;this.stores=stores;this.network=network;this.worker=worker;this.main=main;this.log=log;
        this.selfCheck=selfCheck;this.clock=clock;this.nanos=nanos;this.random=random;
    }
    long millis(){return nanos.getAsLong()/1_000_000L;}
}
