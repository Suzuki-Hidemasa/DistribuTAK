// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.*;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.RevocationUnion;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.AdminStateTrust;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtWire;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DiscoveryRecord;

/** 状態と秘密は作業スレッドで所有し、UIには公開情報だけを渡す。 */
final class LanController implements AutoCloseable {
    static final String TAG="DistribuTAK";
    // 診断と更新間隔の測定後に値を決める（ADR0030答え168(9)）。
    static final long MINIMUM_COT_INTERVAL_NANOS=10_000_000_000L;
    interface Ui {
        void render(Status status);void qr(byte[] pixels);void hideSensitive();
        long screenEpoch();boolean foreground();
        default void confirmUnknown(Object token,int count){}
        default void hideManagementConfirmation(){}
    }
    static final class Ticket {
        final long screen,network,revision;final LanRuntime.Link link;
        Ticket(long screen,long network,LanRuntime.NetworkSnapshot snapshot){this.screen=screen;this.network=network;this.link=snapshot.link;this.revision=snapshot.revision;}
    }
    private static final class Unavailable extends Exception {Unavailable(String fixed){super(fixed);}}
    private static final class Abandoned extends RuntimeException {}
    private static final class RenewalSaveFailure extends Exception {}
    static final class Status {
        final String text;final boolean ready,wifi,member,admin,busy,running,erased,erasing;final int port;
        final boolean rejoin,reinvite;
        int unknown;
        boolean operationsReady=true;
        /** 画面の「DHTを探し直す」ボタンを押せるか（DHT が動いているとき）。 */
        final boolean dht;
        Status(String text,boolean ready,boolean wifi,boolean member,boolean admin,boolean busy,boolean running,boolean erased,boolean erasing,int port,boolean rejoin,boolean reinvite){
            this(text,ready,wifi,member,admin,busy,running,erased,erasing,port,rejoin,reinvite,false);
        }
        Status(String text,boolean ready,boolean wifi,boolean member,boolean admin,boolean busy,boolean running,boolean erased,boolean erasing,int port,boolean rejoin,boolean reinvite,boolean dht){
            this.text=text;this.ready=ready;this.wifi=wifi;this.member=member;this.admin=admin;this.busy=busy;this.running=running;this.erased=erased;this.erasing=erasing;this.port=port;this.rejoin=rejoin;this.reinvite=reinvite;this.dht=dht;
        }
    }
    private final LanRuntime runtime;
    private final Ui ui;
    private final LanRuntime.Tasks worker;
    private final java.util.function.Consumer<Runnable> main;
    private final Clock clock;
    private final SecureRandom random;
    private final AtomicLong networkGeneration=new AtomicLong();
    private volatile LanRuntime.Link observed;
    private long observedRevision;
    private final AtomicLong generation=new AtomicLong();
    private volatile boolean stopped;
    private final AtomicBoolean mainFailed=new AtomicBoolean();
    private boolean mainFailurePublished;
    private LanRuntime.Storage store;
    private LanRuntime.Network wifi;
    private LanRuntime.Link bound;
    private LanGroup group;
    private UdpEndpoint endpoint;
    /** 同じ Wi-Fi の IPv4 の LAN にいる同じグループの相手だけを見つける DHT。端点と同じ寿命（作業の列でだけ触る）。 */
    private LanDht dht;
    private CotSync sync;
    private final SyncInbox inbox=new SyncInbox();
    private final AtomicBoolean draining=new AtomicBoolean();
    private final CotSourceBuffer source=new CotSourceBuffer();
    private final CotImportStatus importStatus=new CotImportStatus();
    private final CotCaptureBaseline captureBaseline=new CotCaptureBaseline();
    private String captureStatus="";
    private volatile Set<String> syncReceived=Set.of();
    private boolean syncUidLimitReached;
    private boolean externalLimitReached;
    private ExternalMarks loadedExternal;
    private volatile ExternalMarks importExternal;
    private UdpEndpoint.InvitationRegistration invitation;
    private String message="初期化中",selfCheck="自己確認: 未実行";
    private boolean ready,busy,joining,selfCheckPassed;
    private boolean savedMember,savedAdmin,administrator;
    private String publicGroup="";
    private long tx,rx,reject,joinBegan,connectBegan;
    private boolean established;
    private final ReconnectSupervisor reconnect=new ReconnectSupervisor();
    private final ProofRequests proofRequests;
    private final java.util.Map<String,byte[]> deliverySessions=new java.util.HashMap<>();
    private long lastOwnRenewalCheck,lastRenewalAttempt;



    private boolean ownRenewalChecked,renewalAttempted;
    private boolean certificateExpired,keyMissed,revokedPeerForgotten;
    private boolean storageStopped;
    private String storageWarning="";
    private boolean invalidStopMarker;
    private long recoveryBegan;
    private boolean committedNotApplied;
    private boolean recoveryUnavailable;
    private static final String RECOVERY_UNAVAILABLE="保存がいっぱい。取り直せないため通信を止めています。消去して新しい招待で入り直せます";
    private AdministrationPreparation preparation;
    private Ticket preparationTicket;
    private long preparationGeneration;
    private byte[] preparationBasis;
    private boolean preparingInvitation;
    private int invitationSide;
    private Object confirmation;
    private boolean managementBusy;
    private GroupAdministration incomingAdministration;
    private LanGroup unknownOwner;
    private AdminRecords.Record unknownList,unknownLocal;
    private byte[] unknownSecret;
    private int unknowns;

    private long publicExpiry;private int publicRenewals;
    private static final String JOIN_FAILED="加入できませんでした。管理者側の状態も確認してください。管理者が招待を出せる場合は、新しい招待でやり直してください";
    private static final String RENEW_FAILED="証明書の更新に失敗しました。接続するを押してください";
    private static final String EXPIRED="証明書の期限が切れました。管理者の新しい招待を読んでください";
    private static final String CLOCK="端末の時計がずれています。時計を合わせてからATAKを起動し直してください";
    private static final String INTERNAL="内部の異常で通信を止めました。記録は消していません";
    private static final String RETRY_STOPPED="続けて3回失敗したため、自動のつなぎ直しを止めました。原因を直してから接続するを押してください";
    interface Action {void run()throws Exception;}
    LanController(Ui ui,LanRuntime runtime) {
        this.ui=ui;this.runtime=runtime;worker=runtime.worker;main=action->runtime.main.accept(()->runMain(action));clock=runtime.clock;random=runtime.random;proofRequests=new ProofRequests(random,runtime.nanos);
        submit(()->{
            if(clock.millis()<0){message=CLOCK;return;}
            runtime.selfCheck.run();CoreSelfCheck.run(clock,runtime.nanos);
            selfCheckPassed=true;selfCheck="自己確認: 成功";log("Self-check PASS: Noise_IKpsk2 handshake, transport, TOTP; clock=elapsedRealtimeNanos");
            store=runtime.stores.open();
            try{group=store.load(clock);}
            catch(StateSettings.Rollback e){ready=false;message="保存が古い状態に戻っています";return;}
            catch(StoredCertificateFailure e){
                if(e.reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID){eraseInternal();message="自分の証明書が無効です。消去しました";}
                else {ready=false;message=e.reason==UdpEndpoint.CloseReason.CLOCK_FAILURE?CLOCK:INTERNAL;}
                return;
            }catch(SecurityException e){ready=false;message=INTERNAL;return;}
            if(group!=null&&!group.storageBlocked)loadSync();
            wifi=runtime.network.open(()->enqueue(this::networkChanged));var initial=wifi.snapshot();observed=initial.link;observedRevision=initial.revision;ready=true;savedMember=group!=null;
            message=group==null?(store.erased()?"消去済み。グループを作るか、新しい招待を読んでください":"未所属"):"保存した所属を復元しました";
            log(group==null?"LAN_READY":"LAN_RESTORED");
            if(group!=null){
                certificateExpired=group.localCertificateReason()==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED&&!group.isAdministrator();
                if(certificateExpired)message=EXPIRED;
                else if(selection()!=null){
                    reconnect.enable(runtime.nanos.getAsLong());
                    try{openMember();startPeer();}
                    catch(RenewalSaveFailure e){reconnect.stop();message=RENEW_FAILED;}
                }
            }
            if(endpoint==null)releaseGroup();
        });
        worker.repeat(()->{if(!stopped)try{poll();}catch(Exception e){fail("状態を確かめられません。通信を停止しました");}});
        worker.repeatSync(()->{if(!stopped)try{pollSync();}catch(CotSync.ExternalCapacityException e){externalLimitReached=true;fail("外来の印の上限に達したため同期を止めました。消去して作成か加入をやり直してください");}catch(RuntimeException e){fail("同期を保存できません。消去して作成か加入をやり直してください");}});
    }
    private void log(String fixed){runtime.log.accept(fixed);}
    Ticket ticket(){return new Ticket(ui.screenEpoch(),networkGeneration.get(),networkSnapshot());}
    private LanRuntime.NetworkSnapshot networkSnapshot(){return wifi==null?new LanRuntime.NetworkSnapshot(null,0):wifi.snapshot();}
    boolean accepts(Ticket ticket){return ticket!=null&&!stopped&&!mainFailed.get()&&ticket.screen==ui.screenEpoch()
            &&ticket.network==networkGeneration.get()&&ticket.revision==networkSnapshot().revision&&ui.foreground();}
    private boolean acceptsEpoch(Ticket ticket){return ticket.screen==ui.screenEpoch()&&ticket.network==networkGeneration.get()
            &&ticket.revision==networkSnapshot().revision;}
    private void requireTicket(Ticket ticket)throws Unavailable {
        if(ticket==null||ticket.screen!=ui.screenEpoch()||ticket.network!=networkGeneration.get()
                ||ticket.revision!=networkSnapshot().revision||!same(ticket.link,selection()))throw new Unavailable("画面かWi-Fiが変わりました。もう一度押してください");
    }
    private static boolean same(LanRuntime.Link a,LanRuntime.Link b){return a==null?b==null:a.same(b);}
    /** mainのコールバックも同じ口で実行し、失敗通知自身の例外では再通知しない。 */
    void runMain(Runnable action){
        try{action.run();}
        catch(RuntimeException e){
            SensitiveImage.attempt(ui::hideSensitive);
            if(mainFailed.compareAndSet(false,true))enqueue(()->fail("処理できません。通信を停止しました"));
        }
    }
    private void enqueue(Runnable action){enqueue(action,()->{});}
    private void enqueue(Runnable action,Runnable discarded){
        if(stopped){discarded.run();return;}
        try{worker.execute(()->{
            if(stopped){discarded.run();return;}
            try{action.run();}catch(Exception|LinkageError e){fail("処理できません。通信を停止しました");}
        });}catch(RejectedExecutionException ignored){discarded.run();}
    }
    private void submit(Action action){submit(action,()->{});}
    private void submit(Action action,Runnable discarded){enqueue(()->{
        busy=true;publish();
        try{action.run();}catch(Unavailable e){message=e.getMessage();if(endpoint==null)releaseGroup();}
        catch(Exception|LinkageError e){fail("処理できません。通信を停止しました");}
        finally{busy=false;publish();}
    },discarded);}
    private void fail(String fixed) {
        if(storageStopped||group!=null&&group.storageBlocked)fixed="保存がいっぱい";
        reconnect.stop();
        generation.incrementAndGet();try{stopNetwork();}catch(Exception ignored){}releaseGroup();
        ready=false;joining=false;message=fixed;main.accept(()->{if(!stopped)ui.hideSensitive();});log("LAN_STOPPED");publish(true);
    }
    private LanRuntime.Link selection(){return wifi==null?null:wifi.current();}
    private LanRuntime.Link requireWifi()throws Unavailable {
        LanRuntime.Link selected=selection();if(selected==null)throw new Unavailable("Wi-FiのIPv4がありません。接続してから押してください");return selected;
    }
    private void requireReady()throws Unavailable {
        if(storageStopped||group!=null&&group.storageBlocked||persistence!=null&&!persistence.statusText().isEmpty())throw new Unavailable("保存がいっぱい");
        if(!ready||joining||releasePending||mainFailed.get()||persistence!=null&&persistence.state()!=CorePersistenceCoordinator.State.RUNNING)throw new Unavailable("今は操作できません");
    }
    private void requireGroup()throws Exception {
        if(group==null&&savedMember)group=store.load(clock);
        if(group!=null&&group.storageBlocked)throw new Unavailable("保存がいっぱい");
    }
    private void rememberPublicGroup() {
        if(group==null||releasePending)return;administrator=group.isAdministrator();savedMember=true;savedAdmin=group.isAdministrator()&&group.peerCertificate==null;
        storageStopped|=group.storageBlocked;invalidStopMarker|=group.invalidStopMarker;
        publicGroup="\nグループ: "+LanSupport.shortId(group.groupId)+" 自分: "+LanSupport.shortId(group.id())
                +"\n相手: "+(group.peerCertificate==null?"未登録":LanSupport.shortId(Crypto.blake2s(group.peerCertificate.field(0))));
        publicExpiry=group.certificate.expiresAt();publicRenewals=group.renewalCount;
        revokedPeerForgotten|=group.revokedPeerForgotten;
        if(group.pendingRenewalReason()==UdpEndpoint.CloseReason.INTERNAL_FAILURE)storageWarning="保存した証明書の更新を1件捨てました。次の更新で作り直します";
    }
    private boolean releasePending;
    private void releaseGroup(){
        rememberPublicGroup();
        unknownOwner=null;unknownList=unknownLocal=null;unknownSecret=null;
        if(group!=null){releasePending=!group.tryClose();if(!releasePending)group=null;}
    }
    private void retryRelease(){if(releasePending)releaseGroup();}
    void create(){submit(()->{
        requireReady();requireWifi();if(!StoreRecovery.canCreate(savedMember||group!=null,store.erasing()))throw new Unavailable("作成できません");
        LanGroup created=LanGroup.create(store.port(),clock,random);
        try{store.create(created);group=created;created=null;}finally{if(created!=null)created.close();}
        reconnect.enable(Long.MAX_VALUE);openMember();message="グループを作成しました";log("LAN_GROUP_CREATED");
    });}
    private UdpEndpoint.Receiver receiver(long epoch) {return new UdpEndpoint.Receiver(){
        public void receive(byte[] peer,byte[] plain){}
        public void receive(byte[] peer,byte[] session,byte[] plain){
            if(stopped||epoch!=generation.get()||plain.length==0)return;
            var coordinator=persistence;var receivedClock=managementClock;
            if(coordinator!=null){
                var state=coordinator.state();
                if(state==CorePersistenceCoordinator.State.STORAGE_FAILED)return;
                if(state==CorePersistenceCoordinator.State.PERSISTING){
                    try{ManagementPage.decodeEnvelope(plain);}
                    catch(IllegalArgumentException invalid){return;}
                }
            }
            if(inbox.offer(epoch,peer,session,plain,receivedClock==null?0:receivedClock.millis()))scheduleDrain();
        }
    };}
    private void scheduleDrain(){
        if(!draining.compareAndSet(false,true))return;
        enqueue(this::drainInbox,()->{draining.set(false);inbox.clear();});
    }
    private void drainInbox(){
        try {
            for(int i=0;i<32;i++) {
                if(persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.PERSISTING)break;
                SyncInbox.Packet packet=inbox.take();if(packet==null)break;
                try(packet) {
                    if(packet.epoch!=generation.get()||endpoint==null)continue;
                    byte[] current=endpoint.sessionId(packet.peer);
                    try{if(current==null||!Crypto.equal(current,packet.session))continue;}
                    finally{Crypto.wipe(current);}
                    if(roster!=null&&roster.receive(packet.peer,packet.session,packet.wire,packet.receivedAt)){
                        if(persistence.state()==CorePersistenceCoordinator.State.STORAGE_FAILED){
                            storageStopped=true;reconnect.stop();message="保存がいっぱい";stopNetwork();
                        }
                        continue;
                    }
                    if(dht!=null&&dht.receiveAnnouncement(packet.peer,packet.session,packet.wire,packet.receivedAt,recovery))continue;
                    if(recovery!=null&&recovery.receive(packet.peer,packet.session,packet.wire,packet.receivedAt)){
                        if(persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.STORAGE_FAILED){
                            storageStopped=true;reconnect.stop();message="保存がいっぱい";stopNetwork();
                        }else finishRecovery();
                        continue;
                    }
                    if(persistence!=null&&!persistence.permits(CorePersistenceCoordinator.Operation.COT_RECEIVE))continue;
                    if(LanSupport.isTestData(packet.wire)){rx++;log(LanSupport.receipt(rx,packet.peer));}
                    else if(DhtWire.isDht(packet.wire)){
                        if(dht==null||!dht.receive(packet.peer,packet.session,packet.wire))reject++;
                        if(persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.STORAGE_FAILED){
                            storageStopped=true;reconnect.stop();message="保存がいっぱい";stopNetwork();
                        }
                    }
                    else if(AdminControl.isEnvelope(packet.wire)){}
                    else if(RenewalMessage.isManagement(packet.wire)){receiveProofRenewal(packet.peer,packet.session,packet.wire);}
                    else if(receiveRenewal(packet.wire)){}
                    else if(sync!=null){
                        // mainですでに見た外来を保存し、受信処理の期限判定より先に計時を止める。
                        pollSync();
                        if(sync!=null&&permits(CorePersistenceCoordinator.Operation.CATCH_UP)){
                            sync.connected(packet.peer,packet.session);
                            if(permits(CorePersistenceCoordinator.Operation.COT_RECEIVE))sync.receive(packet.peer,packet.session,packet.wire);
                            if(permits(CorePersistenceCoordinator.Operation.CATCH_UP))sync.poll();
                        }
                    }
                    else reject++;
                }
            }
        } finally {
            draining.set(false);if(inbox.size()!=0&&(persistence==null||persistence.state()!=CorePersistenceCoordinator.State.PERSISTING))scheduleDrain();
        }
        publish();
    }
    private void opened(UdpEndpoint next,LanRuntime.Link selected){endpoint=next;bound=selected;established=false;}
    private void closed(long epoch,UdpEndpoint.CloseReason reason){enqueue(()->{
        if(epoch!=generation.get())return;
        if(joiningOperation!=null){failedJoin();log("LAN_ENDPOINT_CLOSED reason="+reason.name());publish();return;}
        if(reason==UdpEndpoint.CloseReason.CLOSED_BY_CALLER)return;
        if(recoveringNetwork||group!=null&&group.storageBlocked){
            storageStopped=true;reconnect.stop();stopNetwork();message="保存がいっぱい";publish();return;
        }
        boolean expiredAdministrator=reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED&&group!=null&&group.isAdministrator();
        stopNetwork();if(!expiredAdministrator)releaseGroup();joining=false;
        if(expiredAdministrator){openExpiredAdministrator();}
        else if(reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID){
            reconnect.stop();try{eraseInternal();message="自分の証明書が無効です。消去しました";}catch(Exception e){fail("消去を完了できません。通信を停止しました");return;}
        }else if(reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED){reconnect.stop();certificateExpired=true;message=EXPIRED;}
        else if(reason==UdpEndpoint.CloseReason.CLOCK_FAILURE||reason==UdpEndpoint.CloseReason.RANDOM_FAILURE||reason==UdpEndpoint.CloseReason.RECEIVE_FAILURE){
            reconnect.failed(runtime.nanos.getAsLong());
            message=reconnect.active()?(reason==UdpEndpoint.CloseReason.CLOCK_FAILURE?"時計の確認に失敗しました。つなぎ直します":reason==UdpEndpoint.CloseReason.RANDOM_FAILURE?"乱数の取得に失敗しました。つなぎ直します":"受信に失敗しました。つなぎ直します"):RETRY_STOPPED;
        }else{reconnect.stop();message=INTERNAL;}
        log("LAN_ENDPOINT_CLOSED reason="+reason.name());
        main.accept(()->{if(!stopped)ui.hideSensitive();});publish();
    });}

    private void openExpiredAdministrator(){
        reconnect.stop();certificateExpired=false;
        try{openMember();reconnect.enable(runtime.nanos.getAsLong());startPeer();message="握手中";}
        catch(Unavailable e){reconnect.stop();releaseGroup();if(ready)message=e.getMessage();}
        catch(Exception e){reconnect.stop();releaseGroup();if(ready)message=RENEW_FAILED;}
    }
    private volatile CorePersistenceCoordinator persistence;
    private RevocationUnion managementUnion;
    private volatile Clock managementClock;
    private RevocationRecovery recovery;
    private RosterExchange roster;
    private SessionManager managedSessions;
    private boolean recoveringNetwork;
    private interface SavedAction<T>{T run()throws Exception;}
    private <T> T saving(SavedAction<T> action)throws Exception{
        if(persistence==null)return action.run();
        Object[] result={null};Exception[] failure={null};
        try{persistence.saveUnchanged(()->{try{result[0]=action.run();}catch(Exception e){failure[0]=e;}});}
        finally{retryRelease();}
        if(failure[0]!=null)throw failure[0];
        @SuppressWarnings("unchecked") T value=(T)result[0];return value;
    }
    private void openMember()throws Exception {
        boolean limited=group.recoveryRequirement!=null;
        if(group.storageBlocked&&!limited)throw new Unavailable("保存がいっぱい");
        if(!limited)store.prepareNetwork(group);
        stopNetwork();
        recoveringNetwork=limited;recoveryUnavailable=false;if(limited)recoveryBegan=runtime.nanos.getAsLong();
        if(group.isAdministrator()&&!limited){
            var renewed=group.state.renewOwnCertificate(group.certificate,group.handshakeSecret,group.identitySecret,group.administratorSecret);
            if(renewed!=null)try{saving(()->store.saveLocalRenewal(group,renewed));}
            catch(RuntimeException e){throw e;}catch(Exception e){throw new RenewalSaveFailure();}
        }
        LanRuntime.Link selected=requireWifi();long epoch=generation.incrementAndGet();
        if(!limited)startSync();
        UdpEndpoint.DatagramIo socket;
        try{socket=selected.open(store.port());}catch(Exception e){stopNetwork();throw new Unavailable("待ち受けを開けません。ポートを確かめてください");}
        SessionManager sessions=null;
        try {
            sessions=group.sessions(clock,runtime.nanos);
            managementClock=new MonotonicClock(runtime.nanos);
            managementUnion=new RevocationUnion(group.groupId,new AdminStateTrust(group.state));
            persistence=new CorePersistenceCoordinator(group.state,sessions,managementUnion,
                    clock,managementClock,group.recoveryRequirement);
            UdpEndpoint next=new UdpEndpoint(sessions,group.state,socket,receiver(epoch),
                    UdpEndpoint.DEFAULT_INTERVAL,runtime.nanos,reason->closed(epoch,reason));
            SessionManager managed=sessions;sessions=null;
            opened(next,selected);
            managedSessions=managed;
            recovery=new RevocationRecovery(group,managed,persistence,managementClock,random,()->store.persistenceHooks(group),new RevocationRecovery.Transport(){
                public boolean send(byte[] peer,byte[] session,byte[] wire){return next.sendIfSession(peer,session,wire);}
                public void start(byte[] peer){next.start(peer);}
                public void rejected(ManagementPageSender.Offer result){reject++;}
            });
            roster=new RosterExchange(group,managed,persistence,managementClock,store,recovery);
            if(!limited)startDht(next,managed,selected,epoch);
            else message="保存がいっぱい";
            if(group.peerCertificate!=null){next.expectPeerCertificate(group.peerCertificate);next.setPeerAddress(Crypto.blake2s(group.peerCertificate.field(0)),group.peerAddress);}
            else if(group.pendingHandshake!=null)next.pinPeerAddress(group.pendingHandshake,group.pendingAddress);
        }catch(Exception e){socket.close();if(sessions!=null)sessions.close();stopNetwork();throw e;}
    }
    private void finishRecovery()throws RuntimeException {
        if(!recoveringNetwork||persistence==null||persistence.state()!=CorePersistenceCoordinator.State.RUNNING)return;
        if(group.storageBlocked||group.recoveryRequirement!=null||group.localCertificateReason()!=UdpEndpoint.CloseReason.RUNNING){
            storageStopped=true;message="保存がいっぱい";stopNetwork();return;
        }
        try{
            recoveringNetwork=false;recoveryUnavailable=false;storageStopped=false;inbox.clear();startSync();
            startDht(endpoint,managedSessions,bound,generation.get());message="保存した所属を復元しました";
        }catch(Exception failure){message="保存がいっぱい";stopNetwork();}
    }
    private SyncState loadSync()throws Exception {
        try{SyncState state=store.loadSync(group);loadedExternal=store.loadExternal(group);
            boolean migrated=loadedExternal.migrateLegacy();
            if(migrated)store.saveExternal(group,loadedExternal);
            externalLimitReached=loadedExternal.full();syncUidLimitReached=state.uidCount()>=SyncState.MAX_UIDS;return state;}
        catch(Exception e){fail("同期の記録を開けません。消去して作成か加入をやり直してください");throw new Unavailable("同期の記録を開けません。消去して作成か加入をやり直してください");}
    }
    private void startSync()throws Exception {
        SyncState initial=loadSync();
        importStatus.start(loadedExternal.size());
        captureBaseline.restore(initial);
        long epoch=generation.get();syncReceived=initial.receivedUids();importExternal=loadedExternal;
        var imports=new CotImportGate(main,()->!stopped&&epoch==generation.get(),()->importExternal,source,CotPort.REAL_IMPORT_ENABLED,runtime.cot::accept,importStatus::gateSkipped,importStatus::invalidInput);
        var cache=new SyncCache(store.openSpill(group),Math.max(1,Math.min(4*1024*1024,runtime.syncLimits.totalBytes()/4)),8192,runtime.nanos,random);
        try{sync=new CotSync(group.id(),initial,clock,runtime.nanos,new CotSync.Store(){
            private void saved(SyncState snapshot){syncUidLimitReached=snapshot.uidCount()>=SyncState.MAX_UIDS;syncReceived=snapshot.receivedUids();runtime.cot.saved(syncReceived);runtime.cot.captureSaved(snapshot);}
            public void save(SyncState snapshot)throws Exception{store.saveSync(group,snapshot);saved(snapshot);}
            public SyncState load()throws Exception{return store.loadSync(group);}
            public boolean encoded(){return true;}
            public byte[] loadEncoded()throws Exception{return store.loadSyncEncoded(group);}
            public void saveEncoded(SyncState snapshot,byte[] encoded)throws Exception{store.saveSyncEncoded(group,snapshot,encoded);saved(snapshot);}
        },
                (peer,session,plain)->endpoint!=null&&endpoint.sendIfSession(peer,session,plain,CorePersistenceCoordinator.Operation.COT_SEND),
                imports::notice,random,MINIMUM_COT_INTERVAL_NANOS,loadedExternal,
                marks->{store.saveExternal(group,marks);importExternal=marks;externalLimitReached=marks.full();importStatus.savedMarks(marks.size());},runtime.syncLimits,cache);}
        catch(RuntimeException e){cache.close();throw e;}
        loadedExternal=null;
        String selfUid=runtime.cot.selfUid();
        if(runtime.cot!=CotPort.NONE&&(selfUid==null||!sync.protectPosition(selfUid)))throw new IllegalStateException("自分の位置を識別できません");
        main.accept(()->{
            if(stopped||epoch!=generation.get())return;
            runtime.cot.captureSaved(initial);
            runtime.cot.saved(syncReceived);
            runtime.cot.start(new CotPort.Listener(){
                public void captureStarted(){enqueue(()->{if(!stopped&&epoch==generation.get()&&sync!=null&&permits(CorePersistenceCoordinator.Operation.CATCH_UP))sync.beginCreatedCapture();});}
                public void position(String uid,byte[] xml){if(!stopped&&epoch==generation.get()&&Objects.equals(uid,selfUid))source.position(uid,xml);}
                public void external(String uid){if(!stopped&&epoch==generation.get()&&!Objects.equals(uid,selfUid))source.external(uid);}
                public boolean externalMarked(String uid){return !stopped&&epoch==generation.get()&&source.externalMarked(uid,()->importExternal);}
            },this::runMain);
        });
    }
    private void pollSync(){
        if(sync==null||!permits(CorePersistenceCoordinator.Operation.CATCH_UP))return;
        boolean previousLimit=syncUidLimitReached,previousExternalLimit=externalLimitReached;
        runtime.cot.poll(runtime.nanos.getAsLong());
        if(runtime.cot.failed()){fail("柵を登録できなかったため同期を止めました。ATAK を起動し直してください");return;}
        try(var batch=source.take()){
            for(var fingerprint:batch.external)if(permits(CorePersistenceCoordinator.Operation.COT_SEND))sync.externalFingerprint(fingerprint);
            if(batch.xml!=null)try(var candidate=captureBaseline.candidate(batch.uid,batch.xml,true)){
                if(candidate!=null&&permits(CorePersistenceCoordinator.Operation.COT_SEND)&&sync.publish(candidate.uid,candidate.xml,SyncState.Origin.LOCAL_POSITION)){
                    sync.flush();captureBaseline.saved(sync.snapshot().get(candidate.uid));
                }
            }
            if(batch.overflow){sync.flush();throw new CotSync.ExternalCapacityException();}
            sync.flush();batch.committed();
        }
        if(permits(CorePersistenceCoordinator.Operation.CATCH_UP))sync.expireExternal();
        if(permits(CorePersistenceCoordinator.Operation.CATCH_UP))sync.poll();
        String nextStatus=runtime.cot.captureStatus();boolean captureChanged=!captureStatus.equals(nextStatus);captureStatus=nextStatus;
        if(previousLimit!=syncUidLimitReached||previousExternalLimit!=externalLimitReached||captureChanged)publish();
    }
    private boolean permits(CorePersistenceCoordinator.Operation operation){
        return !stopped&&(persistence==null||persistence.permits(operation));
    }
    private void coordinated(CorePersistenceCoordinator.Operation operation,Runnable action){
        if(stopped)return;
        var coordinator=persistence;if(coordinator==null)action.run();else coordinator.execute(operation,action);
    }
    void debugFence(){debugFence(false);}
    void debugFenceOnly(){debugFence(true);}
    private void debugFence(boolean only){submit(()->{
        requireReady();
        if(!BuildConfig.DEBUG||sync==null||!runtime.cot.ready())throw new Unavailable("柵を登録できません。登録の状態を確かめてください");
        if(!sync.registerReceivedUid(CotPort.FIXTURE_UID))throw new Unavailable("試験の記録を保存できません");
        sync.flush();long epoch=generation.get();
        main.accept(()->{if(!stopped&&epoch==generation.get()){if(only)runtime.cot.debugFenceOnly();else runtime.cot.debug();}});
    });}
    void debugFenceSend(CotPort.Send method){submit(()->{
        long epoch=generation.get();main.accept(()->{if(!stopped&&epoch==generation.get())runtime.cot.debugSend(method);});
    });}
    void connect(){submit(()->{
        requireReady();requireWifi();requireGroup();
        if(certificateExpired){message=EXPIRED;releaseGroup();return;}
        if(group==null){message="先にグループに入ってください";return;}
        if(endpoint==null&&group.isAdministrator()&&group.localCertificateReason()==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED){openExpiredAdministrator();return;}
        reconnect.enable(runtime.nanos.getAsLong());
        if(endpoint==null)try{openMember();}catch(RenewalSaveFailure e){reconnect.stop();releaseGroup();message=RENEW_FAILED;return;}
        if(group.peerCertificate==null){message=group.pendingHandshake==null?"相手の加入を待っています":"管理者からの接続を待っています";return;}
        byte[] peer=Crypto.blake2s(group.peerCertificate.field(0));
        if(!endpoint.isEstablished(peer)){startPeer();message="握手中";log("LAN_HANDSHAKE_STARTED");}
    });}
    void showInvitation(Ticket ticket){showInvitation(ticket,512);}
    void showInvitation(Ticket ticket,int imageSide){showInvitation(ticket,imageSide,false);}
    void showRejoinInvitation(Ticket ticket,int imageSide){showInvitation(ticket,imageSide,true);}
    private void showInvitation(Ticket ticket,int imageSide,boolean explicitRejoin){submit(()->{
        requireTicket(ticket);
        requireReady();requireWifi();requireGroup();if(group==null||!group.isAdministrator()||group.peerCertificate!=null&&!explicitRejoin
                &&group.state.localCertificateReason(group.peerCertificate,group.peerCertificate.field(1))!=UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_EXPIRED)throw new Unavailable("招待を作れません");
        if(endpoint==null)openMember();
        if(invitation!=null){
            // 登録を取り替える前にjoinの作業も止め、古いproviderの秘密を消す。
            openMember();
        }
        if(preparation!=null)throw new Unavailable("確認中の操作を終えてください");
        beginPreparation(ticket,imageSide,true);
    });}
    private void displayPreparedInvitation(Ticket ticket,int imageSide)throws Exception {
        requireTicket(ticket);requireReady();
        byte[] totp=LanGroup.random(random);byte[] pixels=null;
        try(var value=new Invitation(bound.address().getAddress(),store.port(),Crypto.x25519Public(group.handshakeSecret),Crypto.ed25519Public(group.administratorSecret),totp,group.groupId)) {
            long epoch=generation.get();
            register(value,epoch);
            pixels=runtime.qr.encode(value,imageSide);byte[] transferred=pixels;pixels=null;
            main.accept(()->{
                try {
                    if(stopped||epoch!=generation.get()||!accepts(ticket))return;
                    ui.qr(transferred);log("LAN_INVITATION_SHOWN");
                    enqueue(()->{if(epoch==generation.get()&&acceptsEpoch(ticket)){message="招待QRを表示しました";publish();}});
                }finally{Crypto.wipe(transferred);}
            });
            message="招待QRを準備しました";
        }finally{Crypto.wipe(totp);Crypto.wipe(pixels);}
    }
    private GroupAdministration administration(){
        boolean legacyMember=group.certificate.format()==1&&!group.state.administrators().hasAdminBindings()
                &&group.state.administrators().entries().size()==1&&!group.isAdministrator()&&group.peerCertificate!=null;
        var value=legacyMember?GroupAdministration.fromSaved(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                group.administratorSecret,clock,runtime.nanos,random,group.peerCertificate)
                :new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                group.administratorSecret,clock,runtime.nanos,random);
        try{
            if(group.management!=null){
                if(!legacyMember||!group.management.legacyAdministratorBasis.isEmpty())value.restoreLegacyAdministratorBasis(group.management.legacyAdministratorBasis);
                if(value.isAdministrator())value.directory().restoreSnapshot(group.management.roster);
            }
            if(value.isAdministrator()){
                value.directory().saved(group.certificate);
                if(group.peerCertificate!=null)value.directory().saved(group.peerCertificate);
                if(endpoint!=null)for(var peer:endpoint.knownPeers())value.directory().saved(peer.certificate());
            }
            return value;
        }catch(RuntimeException failure){value.close();throw failure;}
    }
    private int unknownCount(){
        if(group==null||!group.isAdministrator()||group.state.administrators().bindings().stream().noneMatch(b->b.state()==AdminBinding.State.UNKNOWN))return 0;
        var list=group.state.administrators();
        // 対応の入力が同じ間は件数を再利用し、表示のたびに署名検査を繰り返さない。
        // Reuse the count while binding inputs are unchanged, avoiding signature checks on every render.
        if(unknownOwner==group&&unknownList==list&&unknownLocal==group.certificate&&unknownSecret==group.administratorSecret)return unknowns;
        try(var value=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                group.administratorSecret,clock,runtime.nanos,random)){
            int count=(int)value.bindings().stream().filter(b->b.state()==AdminBinding.State.UNKNOWN).count();
            unknownOwner=group;unknownList=list;unknownLocal=group.certificate;unknownSecret=group.administratorSecret;unknowns=count;
            return count;
        }
        catch(RuntimeException unavailable){return 0;}
    }
    void removeUnknown(Ticket ticket){submit(()->{
        requireTicket(ticket);requireReady();requireGroup();
        if(endpoint==null||managedSessions==null||preparation!=null)throw new Unavailable("今は操作できません");
        beginPreparation(ticket,0,false);
        var token=confirmation;int count=unknownCount();
        main.accept(()->{if(accepts(ticket)&&confirmation==token)ui.confirmUnknown(token,count);});
    });}
    void confirmUnknown(Object token){submit(()->{
        // 古い確認は無視し、進行中の操作と成功の表示を保つ。
        // Ignore stale confirmations, preserving active work and its success message.
        if(token==null||token!=confirmation||preparation==null)return;
        if(!preparationCurrent()){
            cancelPreparation();throw new Unavailable("確認の条件が変わりました。操作を取り消しました");
        }
        confirmation=null;
        try{preparation.begin();}
        catch(RuntimeException failure){cancelPreparation();message="操作を取り消しました。切り替えを始められません";return;}
        managementBusy=true;pollPreparation();
    });}
    void cancelManagement(){enqueue(()->{cancelPreparation();message="操作を取り消しました";publish();});}
    private void beginPreparation(Ticket ticket,int side,boolean invitation)throws Exception {
        var value=administration();
        try{
            var removed=new ArrayList<byte[]>();
            if(!invitation)for(var binding:value.bindings())if(binding.state()==AdminBinding.State.UNKNOWN)removed.add(binding.administratorKey());
            preparation=new AdministrationPreparation(value,managedSessions,removed,invitation,new AdministrationPreparation.Port(){
                public void own(AdminRecords.Record certificate){
                    boolean[] saved={false};
                    try{
                        saving(()->{boolean changed=store.saveLocalRenewal(group,certificate);saved[0]=changed;return changed;});
                        endpoint.updateLocalCertificate(certificate);
                    }catch(Exception failure){
                        if(saved[0])stopCommittedPreparation();
                        throw new IllegalStateException("証明書を保存できません");
                    }
                }
                public void issued(AdminRecords.Record certificate){
                    try{
                        var directory=new MemberDirectory(group.state);
                        if(group.management!=null)directory.restoreSnapshot(group.management.roster);
                        directory.saved(group.certificate);directory.saved(certificate);
                        saving(()->{store.saveDirectory(group,directory,group.management==null?Map.of():group.management.aliases);return null;});
                    }catch(Exception failure){throw new IllegalStateException("証明書を保存できません");}
                }
                public void send(byte[] peer,RenewalMessage message){
                    byte[] session=endpoint.sessionId(peer),wire=message.encode();
                    try{if(session!=null)endpoint.sendIfSession(peer,session,wire,CorePersistenceCoordinator.Operation.RENEWAL);}
                    finally{Crypto.wipe(session);Crypto.wipe(wire);}
                }
                public void commit(GroupAdministration.Preparation prepared,GroupAdministration.Candidate candidate){
                    boolean[] saved={false};var sessions=managedSessions;
                    try{
                        // sessions → 管理操作 → AdminState の順を守り、端点の定期処理との逆順を防ぐ。
                        // Lock sessions, then administration, then AdminState to avoid inversion with endpoint polling.
                        synchronized(sessions){saving(()->{
                            prepared.publish(candidate,snapshot->{store.persistenceHooks(group).save(snapshot);saved[0]=true;},c->{});
                            return null;
                        });}
                    }catch(Exception failure){
                        if(saved[0])stopCommittedPreparation();
                        throw new IllegalStateException("管理者の一覧を保存できません");
                    }
                }
            });
        }catch(RuntimeException failure){value.close();throw new Unavailable("最後の管理者を外すか、切り替えの条件を満たさない操作はできません");}
        preparationTicket=ticket;preparationGeneration=generation.get();preparationBasis=group.state.administrators().encode();
        preparingInvitation=invitation;invitationSide=side;confirmation=invitation?null:new Object();
        if(invitation){
            managementBusy=true;
            try{preparation.begin();message="形式の切り替えを待っています";pollPreparation();}
            catch(RuntimeException failure){cancelPreparation();throw new Unavailable("招待を止めました。形式の切り替えを確かめてください");}
        }
    }
    private boolean preparationCurrent(){
        return preparation!=null&&group!=null&&endpoint!=null&&preparationGeneration==generation.get()
                &&accepts(preparationTicket)&&Arrays.equals(preparationBasis,group.state.administrators().encode())
                &&group.isAdministrator()&&group.state.administrators().hasEntry(Crypto.ed25519Public(group.administratorSecret))
                &&permits(CorePersistenceCoordinator.Operation.ADMINISTRATION);
    }
    private void pollPreparation()throws Exception {
        if(preparation==null)return;
        boolean invitation=preparingInvitation;
        if(!preparationCurrent()){
            cancelPreparation();message=invitation?"招待を止めました。確認の条件が変わりました":"確認の条件が変わりました。操作を取り消しました";publish();return;
        }
        if(!preparation.begun())return;
        try{
            if(!preparation.poll())return;
            var ticket=preparationTicket;int side=invitationSide;
            cancelPreparation();
            if(invitation)displayPreparedInvitation(ticket,side);
            else message="対応のない管理者をすべて外しました";
            publish();
        }catch(RuntimeException failure){
            cancelPreparation();message=invitation?"招待を止めました。形式の切り替えを確かめてください":"操作を取り消しました。切り替えを完了できません";publish();
        }
    }
    private void cancelPreparation(){
        if(preparation!=null){preparation.close();preparation=null;}
        confirmation=null;managementBusy=false;preparationTicket=null;Crypto.wipe(preparationBasis);preparationBasis=null;
        main.accept(ui::hideManagementConfirmation);
    }
    private void stopCommittedPreparation(){
        committedNotApplied=true;storageStopped=true;reconnect.stop();stopNetwork();
    }
    private void receivePreparationMessage(byte[] peer,byte[] session,RenewalMessage message)throws Exception {
        if(message.operation()==RenewalMessage.Operation.PROOF_REPLY){
            if(preparation!=null&&preparationCurrent())preparation.reply(peer,session,message);
            return;
        }
        if(incomingAdministration!=null&&!Arrays.equals(incomingAdministration.certificate().encode(),group.certificate.encode())){
            incomingAdministration.close();incomingAdministration=null;
        }
        if(incomingAdministration==null)incomingAdministration=administration();
        if(message.operation()==RenewalMessage.Operation.PROOF_REQUEST){
            var reply=incomingAdministration.receiveProofRequest(managedSessions,peer,session,message);
            if(!renewalCandidate(()->proofRequests.remember(peer,session,message)))return;
            endpoint.sendIfSession(peer,session,reply.encode(),CorePersistenceCoordinator.Operation.RENEWAL);
        }else{
            var certificate=incomingAdministration.receiveCertificateDelivery(managedSessions,peer,session,message,next->{
                try{saving(()->store.saveLocalRenewal(group,next));}
                catch(Exception failure){throw new IllegalStateException("証明書を保存できません");}
            });
            proofRequests.forget(peer);endpoint.updateLocalCertificate(certificate);endpoint.startIfPermitted(peer,CorePersistenceCoordinator.Operation.RECONNECT);
        }
    }
    private boolean recoveryCannotContinue(){
        long now=runtime.nanos.getAsLong();
        return now<recoveryBegan||now-recoveryBegan>=240_000_000_000L||recovery!=null&&recovery.exhausted();
    }
    private String managementStopText(){
        if(invalidStopMarker||group!=null&&group.invalidStopMarker)return "保存した停止の記録を確かめられません。通信を止めています";
        if(committedNotApplied||persistence!=null&&persistence.stopReason()==CorePersistenceCoordinator.StopReason.COMMITTED_NOT_APPLIED)
            return "保存した変更を適用できません。通信を止めています";
        if(recoveryUnavailable)return RECOVERY_UNAVAILABLE;
        if(persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.PERSISTING)
            return recoveringNetwork?"保存がいっぱい。通信を止め、取り消しの一覧を保存しています":"保存中です。通信と操作を一時的に止めています";
        if(persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.RECOVERING_REVOCATIONS){
            if(recoveryCannotContinue())return RECOVERY_UNAVAILABLE;
            return "保存がいっぱい。通信を止め、取り消しの一覧を取り直しています";
        }
        if(storageStopped||group!=null&&group.storageBlocked||persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.STORAGE_FAILED)
            return "保存がいっぱい。通信を止めています";
        return "";
    }
    private void register(Invitation value,long epoch) {
        // provider は核の join スレッドで動く。告知を保存してから、公開記録と秘密の写しを固定する。
        // The provider runs on the core join thread. Persist the announcement before fixing public records and secret copies.
        byte[] expected=group.peerCertificate==null?null:group.peerCertificate.field(0);
        try(var administration=new GroupAdministration(group.state,group.certificate,group.identitySecret,group.handshakeSecret,
                group.administratorSecret,clock,runtime.nanos,random);
            var materials=administration.invitationMaterials(group.groupKey,group.keyVersion,expected)){
            Objects.requireNonNull(materials);
        }
        var materialState=LanGroup.restore(group.groupId,group.urlAdmin,group.state.snapshot(),clock);
        var issuer=new JoinHandshake.Admin(value,materialState.administrators(),materialState.snapshot().anchorSignature(),clock,runtime.nanos);
        byte[] handshake=group.handshakeSecret.clone(),admin=group.administratorSecret.clone(),psk=group.groupKey.clone();
        var chain=List.of(materialState.administrators());long version=group.keyVersion;
        try {
            invitation=endpoint.registerInvitation(issuer,()->new UdpEndpoint.JoinMaterials(handshake.clone(),admin.clone(),
                    (expected==null?JoinHandshake.Materials.verified(materialState,chain,version,psk):JoinHandshake.Materials.verified(materialState,chain,version,psk,expected))),joined->enqueue(()->{
                if(epoch!=generation.get()||group==null||!permits(CorePersistenceCoordinator.Operation.INVITATION))return;
                try{
                    group.state.verifyCertificate(joined.certificate(),joined.handshakeKey());
                    if(expected!=null){
                        // 入り直しの返事だけでは、相手の保存した証明書を進めない。
                        message="相手の加入を認めました。接続するを押してください";
                        log("LAN_MEMBER_ISSUED");main.accept(()->{if(!stopped)ui.hideSensitive();});publish();return;
                    }
                    savePeer(joined.certificate(),joined.address());
                    endpoint.rememberPeer(group.peerCertificate);endpoint.setPeerAddress(Crypto.blake2s(group.peerCertificate.field(0)),group.peerAddress);
                    message="相手の加入を認めました。接続するを押してください";log("LAN_MEMBER_ISSUED");
                    main.accept(()->{if(!stopped)ui.hideSensitive();});publish();
                }catch(Exception e){fail("相手の記録を保存できません。通信を停止しました");}
            }));
            // 登録のcloseより前に秘密を消さない。stopNetworkで核を閉じたあとに片付ける。
            invitationSecrets=new byte[][]{handshake,admin,psk};
        }catch(RuntimeException e){issuer.close();Crypto.wipe(handshake);Crypto.wipe(admin);Crypto.wipe(psk);throw e;}
    }
    private static final class JoinOperation implements AutoCloseable {
        final byte[] identity,handshake;final long epoch;
        LanGroup previous;ReconnectSupervisor priorReconnect;
        final AtomicReference<LanGroup> candidate=new AtomicReference<>();
        final AtomicReference<LanRuntime.Pending> staged=new AtomicReference<>();
        volatile boolean fatal;
        volatile SessionManager sessions;
        Future<AdminRecords.Record> future;
        JoinOperation(byte[] identity,byte[] handshake,long epoch){this.identity=identity.clone();this.handshake=handshake.clone();this.epoch=epoch;}
        public void close(){Crypto.wipe(identity);Crypto.wipe(handshake);LanGroup value=candidate.getAndSet(null);if(value!=null)value.close();}
    }
    private JoinOperation joiningOperation;
    private byte[][] invitationSecrets;
    void join(Invitation value,Ticket ticket){submit(()->{
        try(value) {
            requireReady();requireTicket(ticket);LanRuntime.Link selected=requireWifi();requireGroup();
            boolean rejoin=savedMember&&(certificateExpired||keyMissed);
            if(!StoreRecovery.canJoin(group!=null||savedMember)&&!rejoin)throw new Unavailable("所属済みです");
            if(rejoin&&!group.state.administrators().hasEntry(value.adminPublicKey()))throw new Unavailable("加入できませんでした。管理者側の状態も確認してください。管理者が招待を出せる場合は、新しい招待でやり直してください");
            LanGroup previous=rejoin?group:null;ReconnectSupervisor prior=reconnect.snapshot();
            byte[] identity=rejoin?group.identitySecret.clone():LanGroup.random(random),handshake=LanGroup.random(random);
            byte[] administrator=value.adminPublicKey(),remoteKey=value.handshakePublicKey();
            InetSocketAddress address=new InetSocketAddress(InetAddress.getByAddress(value.adminAddress()),value.udpPort());
            UdpEndpoint.DatagramIo socket=null;JoinHandshake.Joiner joiner=null;boolean socketOwned=false;
            try {
                // 未所有の口と鍵を片付けてから、前のグループで開き直す。
                try{
                    reconnect.stop();stopNetwork();long epoch=generation.incrementAndGet();
                    try{socket=selected.open(store.port());}catch(java.io.IOException e){throw new Unavailable("加入の口を開けません。ポートを確かめてください");}joiner=rejoin?JoinHandshake.Joiner.rejoin(value,identity,handshake,clock,previous.state,previous.certificate,previous.keyVersion,
                            previous.groupKey,previous.state.announcement(),previous.state.revokedSubjects()):new JoinHandshake.Joiner(value,identity,handshake,clock);
                    UdpEndpoint next=new UdpEndpoint(socket,receiver(epoch),runtime.nanos,reason->closed(epoch,reason));
                    opened(next,selected);socketOwned=true;next.pinPeerAddress(remoteKey,address);joining=true;joinBegan=runtime.millis();
                    JoinOperation operation=new JoinOperation(identity,handshake,epoch);operation.previous=previous;operation.priorReconnect=prior;
                    joiningOperation=operation;
                    operation.future=next.join(value,joiner,joined->{
                        LanGroup candidate=null;SessionManager manager=null;
                        try {
                            if(stopped||epoch!=generation.get())throw new Abandoned();
                            candidate=rejoin?LanGroup.rejoined(previous,operation.handshake,administrator,joined,clock):LanGroup.joined(store.port(),operation.identity,operation.handshake,administrator,joined,clock);
                            if(!rejoin)candidate.pendingPeer(remoteKey,address);
                            operation.staged.set(store.stage(candidate));
                            if(stopped||epoch!=generation.get())throw new Abandoned();
                            manager=new SessionManager(joined.state(),joined.certificate(),operation.handshake,candidate.groupKey,candidate.keyVersion,clock,runtime.nanos,LanGroup.coreGroupSize());
                            operation.candidate.set(candidate);candidate=null;SessionManager result=manager;operation.sessions=result;manager=null;return result;
                        }catch(Exception e){if(!(e instanceof Abandoned)&&!rejoin)operation.fatal=true;throw new IllegalStateException("加入結果を保存できません");}
                        finally{if(candidate!=null)candidate.close();if(manager!=null)manager.close();}
                    });
                    joiner=null;
                    message="加入中";log("LAN_JOIN_STARTED");
                }finally{Crypto.wipe(identity);Crypto.wipe(handshake);if(joiner!=null)joiner.close();if(!socketOwned&&socket!=null)socket.close();}
            }catch(Exception e){
                if(!rejoin)throw e;
                restoreFailedJoin(previous,prior,e instanceof AdminState.ClockFailure);
            }
        }
    },value::close);}
    /** 「DHTを探し直す」ボタン。作業の列で押しを処理し、結果は状態テキストの固定文で見せる。 */
    void rescanDht(){enqueue(()->{if(dht!=null)dht.press();publish();});}
    private void startDht(UdpEndpoint next,SessionManager managed,LanRuntime.Link selected,long epoch){
        stopDht();
        try{
            LanRuntime.Link link=selected;int prefix=link.prefixLength();
            byte[] ipv4=link.address().getAddress();
            LanDht.Config cfg=new LanDht.Config();
            cfg.groupId=group.groupId.clone();cfg.self=new DhtId(group.id());cfg.ipv4=ipv4;cfg.prefix=prefix;
            cfg.coordinator=persistence;
            cfg.wire=new LanDht.EndpointWire(next,managed);cfg.nanos=runtime.nanos;cfg.wall=clock;cfg.jitter=runtime.dhtJitter;
            LanGroup owner=group;int port=store.port();
            cfg.reserve=()->{
                if(!permits(CorePersistenceCoordinator.Operation.DHT_WRITE))throw new IllegalStateException("Discovery publication is suspended");
                return saving(()->store.reserveDhtVersion(owner));
            };
            cfg.issuer=(version,signedAt)->{
                DiscoveryRecord[] record={null};coordinated(CorePersistenceCoordinator.Operation.DHT_WRITE,
                    ()->record[0]=DiscoveryRecord.issue(owner.groupId,owner.identitySecret,Crypto.x25519Public(owner.handshakeSecret),ipv4,port,version,signedAt));
                return record[0];
            };
            cfg.rejoining=()->joiningOperation!=null;
            cfg.pinWaiting=()->owner.peerCertificate==null&&owner.pendingHandshake!=null;
            cfg.revoked=id->owner.state.revocations().hasEntry(id.bytes());
            cfg.storedPeer=()->owner.peerCertificate==null?null:Crypto.blake2s(owner.peerCertificate.field(0));
            cfg.storedContact=id->{
                if(owner.peerCertificate==null||owner.peerAddress==null)return null;
                byte[] stored=Crypto.blake2s(owner.peerCertificate.field(0));
                try{
                    if(!Arrays.equals(stored,id.bytes()))return null;
                    return new DhtWire.NodeContact(id,owner.peerCertificate.field(1),owner.peerAddress.getAddress().getAddress(),owner.peerAddress.getPort());
                }finally{Crypto.wipe(stored);}
            };
            cfg.log=this::log;
            if(persistence!=null)cfg.management=new ManagedDhtExchange(owner,managed,persistence,managementUnion,clock,managementClock,runtime.nanos,random,store);
            if(cfg.management!=null)cfg.management.transport(recovery);
            final LanDht created;
            try{created=new LanDht(cfg);}catch(RuntimeException|LinkageError failure){if(cfg.management!=null)cfg.management.close();throw failure;}
            dht=created;
            next.allowDiscoveredReplies(created::allowsReply);
            next.onVolatilePeerForgotten(peer->enqueue(()->{if(epoch==generation.get()&&dht==created)created.peerForgotten(peer);}));
        }catch(RuntimeException|LinkageError e){
            // DHT だけ止める。端点や CoT の同期は止めない。例外の文面は記録しない。
            dht=null;log("DHT_START_FAILED");
        }
    }
    private void stopDht(){
        LanDht current=dht;dht=null;
        if(current!=null)current.close();
    }
    void sendTest(){submit(()->{
        requireReady();if(endpoint==null||group==null||group.peerCertificate==null){message="相手と接続してください";return;}
        byte[] peer=Crypto.blake2s(group.peerCertificate.field(0)),plain=LanSupport.testData();
        try{if(endpoint.send(peer,plain)){tx++;message="試験DATAを送信しました";log("LAN_TEST_TX count="+tx);}else message="送信できません。セッションの確立を待ってください";}
        finally{Crypto.wipe(plain);}
    });}
    void setPort(int port){submit(()->{requireReady();if(port<49152||port>65535)throw new Unavailable("49152〜65535の番号を入れてください");if(endpoint!=null)throw new Unavailable("通信中です");requireGroup();store.setPort(port,group);releaseGroup();message="ポートを保存しました";});}
    void disconnect(){submit(()->{reconnect.stop();stopNetwork();releaseGroup();message="通信を停止しました";main.accept(()->{if(!stopped)ui.hideSensitive();});});}
    void erase(){submit(this::eraseInternal);}
    private void eraseInternal()throws Exception {
        reconnect.stop();
        generation.incrementAndGet();
        try{store=runtime.stores.erase(this::stopNetwork,this::releaseGroup);}
        finally{stopNetwork();releaseGroup();}
        if(wifi==null)wifi=runtime.network.open(()->enqueue(this::networkChanged));
        savedMember=false;savedAdmin=false;administrator=false;publicGroup="";certificateExpired=keyMissed=revokedPeerForgotten=false;storageWarning="";syncUidLimitReached=false;externalLimitReached=false;loadedExternal=null;
        ready=selfCheckPassed;storageStopped=false;invalidStopMarker=false;committedNotApplied=false;recoveryUnavailable=false;joining=false;tx=rx=reject=0;message="消去しました。グループを作るか、新しい招待を読んでください";
        main.accept(()->{if(!stopped)ui.hideSensitive();});log("LAN_ERASED");
    }
    private void networkChanged(){
        if(stopped)return;var snapshot=networkSnapshot();LanRuntime.Link current=snapshot.link;
        if(observedRevision!=snapshot.revision||!same(observed,current)) {
            reconnect.stop();observed=current;observedRevision=snapshot.revision;networkGeneration.incrementAndGet();
            long began=runtime.millis();generation.incrementAndGet();stopNetwork();releaseGroup();
            message="Wi-Fiが変わりました。戻ったら接続するを押してください";
            main.accept(()->{if(!stopped)ui.hideSensitive();});log("LAN_WIFI_STOP elapsedMs="+(runtime.millis()-began));
        }publish();
    }
    private void poll()throws Exception {
        retryRelease();
        networkChanged();
        if(inbox.size()!=0&&(persistence==null||persistence.state()!=CorePersistenceCoordinator.State.PERSISTING))scheduleDrain();
        if(endpoint==null&&!releasePending&&ready&&savedMember&&selection()!=null&&!certificateExpired&&reconnect.due(runtime.nanos.getAsLong())){
            try{requireGroup();openMember();startPeer();}
            catch(StoredCertificateFailure e){
                reconnect.stop();
                if(e.reason==UdpEndpoint.CloseReason.LOCAL_CERTIFICATE_INVALID){eraseInternal();message="自分の証明書が無効です。消去しました";}
                else{message=e.reason==UdpEndpoint.CloseReason.CLOCK_FAILURE?CLOCK:INTERNAL;releaseGroup();}
            }
            catch(Exception e){reconnect.failed(runtime.nanos.getAsLong());if(!reconnect.active())message=RETRY_STOPPED;}
        }
        if(joiningOperation!=null&&joiningOperation.future!=null&&joiningOperation.future.isDone()) {
            JoinOperation operation=joiningOperation;
            try{operation.future.get();}
            catch(ExecutionException|CancellationException e){failedJoin();publish();return;}
            if(stopped||operation.epoch!=generation.get()){failedJoin();publish();return;}
            LanGroup candidate=operation.candidate.getAndSet(null);
            if(candidate==null)throw new IllegalStateException("加入の結果がありません");
            try{
                if(operation.previous!=null)store.acceptRejoined(operation.future,operation.previous,candidate,operation.staged.get());
                else store.acceptJoined(operation.future,operation.staged.get());
                operation.staged.set(null);
            }catch(Exception e){candidate.close();if(operation.previous!=null){failedJoin();publish();return;}throw e;}
            boolean rejoined=operation.previous!=null;
            joiningOperation=null;operation.close();if(rejoined&&group!=null)group.close();group=candidate;joining=false;
            certificateExpired=keyMissed=false;reconnect.enable(rejoined?runtime.nanos.getAsLong():Long.MAX_VALUE);
            if(rejoined){
                try{openMember();startPeer();message="握手中";}
                catch(Unavailable e){reconnect.stop();releaseGroup();message=e.getMessage();}
            }else{
                // 保存した所属から共通の調整層を作り、加入用の口の世代を終える。
                // Build shared coordination from the saved membership and end the join endpoint's generation.
                try{openMember();message="加入が完了しました。管理者からの接続を待っています";}
                catch(Unavailable e){reconnect.stop();releaseGroup();message=e.getMessage();}
            }
            log("LAN_JOINED elapsedMs="+(runtime.millis()-joinBegan));
        }
        if(endpoint!=null&&group!=null&&!joining) {
            if(recovery!=null){
                var candidates=new ArrayList<byte[]>();
                if(group.peerCertificate!=null)candidates.add(Crypto.blake2s(group.peerCertificate.field(0)));
                for(var known:endpoint.knownPeers()){
                    byte[] id=Crypto.blake2s(known.certificate().field(0));
                    if(candidates.stream().noneMatch(value->Arrays.equals(value,id)))candidates.add(id);
                }
                if(roster!=null&&persistence.permits(CorePersistenceCoordinator.Operation.ROSTER)){
                    for(var candidate:candidates)roster.registerFirst(candidate);
                    if(persistence.state()==CorePersistenceCoordinator.State.STORAGE_FAILED){
                        storageStopped=true;reconnect.stop();message="保存がいっぱい";stopNetwork();publish();return;
                    }
                    roster.poll(candidates);
                }
                recovery.poll(candidates);finishRecovery();
                if(endpoint==null)return;
            }
            if(persistence!=null&&!persistence.permits(CorePersistenceCoordinator.Operation.CATCH_UP)){
                pollPreparation();
                message="保存がいっぱい";publish();return;
            }
            var peers=endpoint.knownPeers();
            if(sync!=null&&permits(CorePersistenceCoordinator.Operation.CATCH_UP))for(var peer:peers){
                byte[] id=Crypto.blake2s(peer.certificate().field(0)),session=endpoint.sessionId(id);
                try{if(permits(CorePersistenceCoordinator.Operation.CATCH_UP)){if(session==null)sync.disconnected(id);else sync.connected(id,session);}}
                finally{Crypto.wipe(id);Crypto.wipe(session);}
            }
            if(!peers.isEmpty()) {
                var peer=peers.get(0);
                byte[] id=Crypto.blake2s(peer.certificate().field(0)),pending=group.pendingRenewal(id);
                try {
                    var first=endpoint.authenticatedFirstCertificate(id);
                    boolean maySave=pending==null||first!=null&&java.util.Arrays.equals(first.encode(),peer.certificate().encode());
                    if(maySave&&(group.peerCertificate==null||peer.certificate().issuedAt()>group.peerCertificate.issuedAt()))savePeer(peer.certificate(),peer.address());
                    else if(pending!=null&&pending[0]==10&&AdminRecords.decode(pending).format()==1&&first!=null
                            &&java.util.Arrays.equals(first.encode(),group.peerCertificate.encode())) {
                        byte[] previous=group.removeRenewal(id);
                        try{saving(()->{store.save(group);return null;});group.retainPeerCertificatePermission();Crypto.wipe(previous);}
                        catch(Exception failure){group.restoreRenewal(id,previous);throw failure;}
                    }
                }finally{Crypto.wipe(id);Crypto.wipe(pending);}
            }
            if(group.peerCertificate!=null&&group.state.revocations().hasEntry(Crypto.blake2s(group.peerCertificate.field(0)))){
                endpoint.forgetPeer(Crypto.blake2s(group.peerCertificate.field(0)));group.forgetRevokedPeer();
                try{saving(()->{store.save(group);return null;});}catch(Exception e){log("LAN_REVOKED_PEER_SAVE_FAILED");}
                message="相手は失効しました";
            }
            keyMissed|=endpoint.sawNewerKeyVersion();if(preparation==null||!preparation.begun())renewPeer();showMemberFirst();
            if(group.peerCertificate!=null) {
                boolean current=endpoint.isEstablished(Crypto.blake2s(group.peerCertificate.field(0)));
                if(current&&!established){
                    long epoch=generation.get();main.accept(()->{if(!stopped&&epoch==generation.get())runtime.cot.reconnected();});
                    message="セッションが確立しました";log("LAN_ESTABLISHED elapsedMs="+(connectBegan==0?0:runtime.millis()-connectBegan));
                }
                if(current){reconnect.established();keyMissed=false;}
                else if(established)reconnect.retry(runtime.nanos.getAsLong());
                if(!current&&reconnect.due(runtime.nanos.getAsLong()))startPeer();
                established=current;
            }
        }
        if(dht!=null)dht.step();
        pollPreparation();
        if(persistence!=null&&persistence.state()==CorePersistenceCoordinator.State.STORAGE_FAILED){
            storageStopped=true;reconnect.stop();message="保存がいっぱい";stopNetwork();
        }
        publish();
    }
    private void savePeer(AdminRecords.Record certificate,InetSocketAddress address)throws Exception {
        saving(()->store.savePeer(group,certificate,address));
        if(endpoint!=null)endpoint.expectPeerCertificate(group.peerCertificate);
    }
    private boolean receiveRenewal(byte[] wire){
        // 旧項目8は消費して捨てる。形式2の更新には専用の入口だけを使う。
        try{return SyncWire.renewalCertificate(wire)!=null;}catch(RuntimeException malformed){return false;}
    }
    private <T> T renewalCandidate(java.util.function.Supplier<T> action){
        if(persistence==null)return action.get();
        Object[] value={null};persistence.execute(CorePersistenceCoordinator.Operation.RENEWAL,()->value[0]=action.get());
        @SuppressWarnings("unchecked") T result=(T)value[0];return result;
    }
    private boolean applyRenewal(AdminRecords.Record certificate) {
        try {
            var validation=endpoint.renewalValidationIfPermitted(certificate);
            if(validation==UdpEndpoint.RenewalValidation.DENIED)return false;
            if(validation==UdpEndpoint.RenewalValidation.UPDATE){
                saving(()->store.saveLocalRenewal(group,certificate));
                return endpoint!=null&&endpoint.updateRenewalIfPermitted(certificate);
            }
            return true;
        }catch(Exception failure){log("LAN_RENEWAL_REJECTED");return false;}
    }
    private static String renewalPeer(byte[] peer){return java.util.Base64.getEncoder().encodeToString(peer);}
    private void receiveProofRenewal(byte[] peer,byte[] session,byte[] wire) {
        if(persistence!=null&&!persistence.permits(CorePersistenceCoordinator.Operation.RENEWAL))return;
        try {
            var message=RenewalMessage.decode(wire);
            if(message.reason()!=RenewalMessage.Reason.AUTO_RENEWAL){
                receivePreparationMessage(peer,session,message);return;
            }
            if(message.operation()==RenewalMessage.Operation.PROOF_REPLY){receiveProofReply(peer,session,message);return;}
            if(group.peerCertificate==null||!Crypto.equal(peer,Crypto.blake2s(group.peerCertificate.field(0)))
                    ||!Crypto.equal(message.administrator(),group.urlAdmin)||!group.state.administrators().hasEntry(message.administrator())
                    ||!Crypto.equal(message.memberId(),group.id())||!Crypto.equal(message.group(),group.groupId))
                throw new SecurityException("更新を出した管理者が違います");
            group.state.verifyCertificate(group.peerCertificate,group.peerCertificate.field(1));
            if(message.operation()==RenewalMessage.Operation.CERTIFICATE_DELIVERY
                    &&java.util.Arrays.equals(message.certificate(),group.certificate.encode())) {
                // 最初の FIRST が5秒制限で送れなかった場合も、同じ配送で再試行する。保存と回数は変えない。
                endpoint.startIfPermitted(peer,CorePersistenceCoordinator.Operation.RECONNECT);return;
            }
            if(!message.matchesBase(group.certificate))throw new SecurityException("更新の基準が違います");
            if(message.reason()==RenewalMessage.Reason.INVITATION_PREPARE&&group.certificate.format()!=1)
                throw new SecurityException("招待の更新は形式1だけです");
            if(message.reason()==RenewalMessage.Reason.AUTO_RENEWAL&&!ProofRequests.due(group.certificate,clock.millis()))
                throw new SecurityException("更新の時期ではありません");
            if(message.operation()==RenewalMessage.Operation.PROOF_REQUEST) {
                if(message.reason()==RenewalMessage.Reason.AUTO_RENEWAL&&group.certificate.identityProofFormat()==2)
                    throw new SecurityException("本人証明はすでに形式2です");
                if(!renewalCandidate(()->proofRequests.remember(peer,session,message)))return;
                endpoint.sendIfSession(peer,session,RenewalMessage.reply(message,group.identitySecret).encode(),CorePersistenceCoordinator.Operation.RENEWAL);return;
            }
            if(group.certificate.identityProofFormat()!=2&&proofRequests.match(peer,session,message)==null)
                throw new SecurityException("未要求の証明書です");
            var certificate=AdminRecords.decode(message.certificate());
            if(certificate.format()!=2||certificate.identityProofFormat()!=2||!Crypto.equal(certificate.signer(),message.administrator()))
                throw new SecurityException("更新の形式か署名者が違います");
            if(!applyRenewal(certificate))return;proofRequests.forget(peer);
            // 保存済みの証明書を、管理者へ新しいFIRSTで示す。
            endpoint.startIfPermitted(peer,CorePersistenceCoordinator.Operation.RECONNECT);
        }catch(Exception failure){log("LAN_RENEWAL_REJECTED");}
    }
    private void receiveProofReply(byte[] peer,byte[] session,RenewalMessage reply)throws Exception {
        if(!group.isAdministrator()||group.peerCertificate==null||!Crypto.equal(peer,Crypto.blake2s(group.peerCertificate.field(0))))
            throw new SecurityException("求めた相手が違います");
        var request=renewalCandidate(()->proofRequests.match(peer,session,reply));
        if(request==null||!request.matchesBase(group.peerCertificate)||!Crypto.equal(reply.identity(),group.peerCertificate.field(0))
                ||!SignaturePurpose.verifyIdentity(group.groupId,reply.identity(),reply.handshake(),reply.proof()))
            throw new SecurityException("未完の証明要求と違います");
        byte[] pending=group.pendingRenewal(peer);
        try {
            AdminRecords.Record certificate;
            if(pending!=null) {
                certificate=AdminRecords.decode(LanGroup.renewalCertificate(pending));
                if(certificate.format()!=2||!Crypto.equal(certificate.field(2),reply.proof()))throw new SecurityException("保存した本人証明が違います");
                group.state.verifyCertificate(certificate,group.peerCertificate.field(1));
            }else certificate=renewalCandidate(()->group.state.issueCertificateRenewal(group.peerCertificate,reply.proof(),group.administratorSecret,reply.reason(),reply.managementOperation()));
            publishDelivery(peer,session,RenewalMessage.delivery(request,certificate.encode()));
        }finally{Crypto.wipe(pending);}
    }
    private void publishDelivery(byte[] peer,byte[] session,RenewalMessage delivery)throws Exception {
        byte[] wire=delivery.encode(),pending=delivery.pendingValue();
        try {
            saving(()->store.saveIssuedRenewal(group,peer,pending));
            renewalCandidate(()->{
                byte[] previous=deliverySessions.put(renewalPeer(peer),session.clone());Crypto.wipe(previous);
                return null;
            });
            if(endpoint!=null)endpoint.sendIfSession(peer,session,wire,CorePersistenceCoordinator.Operation.RENEWAL);
        }finally{Crypto.wipe(wire);Crypto.wipe(pending);}
    }
    private void renewPeer() {
        if(persistence!=null&&!persistence.permits(CorePersistenceCoordinator.Operation.RENEWAL))return;
        long now=runtime.nanos.getAsLong();
        if(!group.isAdministrator())return;
        if(!ownRenewalChecked||now>=lastOwnRenewalCheck&&now-lastOwnRenewalCheck>=3_600_000_000_000L){
            ownRenewalChecked=true;lastOwnRenewalCheck=now;
            try{
                var renewed=group.state.renewOwnCertificate(group.certificate,group.handshakeSecret,group.identitySecret,group.administratorSecret);
                if(renewed!=null){saving(()->store.saveLocalRenewal(group,renewed));endpoint.updateLocalCertificate(renewed);}
            }catch(Exception e){log("LAN_RENEWAL_REJECTED");}
        }
        if(group.peerCertificate==null||renewalAttempted&&(now<lastRenewalAttempt||now-lastRenewalAttempt<5_000_000_000L))return;
        byte[] peer=Crypto.blake2s(group.peerCertificate.field(0)),session=endpoint.sessionId(peer),pending=group.pendingRenewal(peer);
        try {
            if(session==null)return;
            if(pending==null&&!ProofRequests.due(group.peerCertificate,clock.millis()))return;
            renewalAttempted=true;lastRenewalAttempt=now;
            if(pending!=null&&pending[0]==10&&AdminRecords.decode(pending).format()==1)return;
            if(pending!=null&&Crypto.equal(session,deliverySessions.get(renewalPeer(peer)))) {
                endpoint.sendIfSession(peer,session,RenewalMessage.pendingValue(pending).encode(),CorePersistenceCoordinator.Operation.RENEWAL);return;
            }
            var request=renewalCandidate(()->proofRequests.begin(peer,session,group.peerCertificate,Crypto.ed25519Public(group.administratorSecret),RenewalMessage.Reason.AUTO_RENEWAL,null));
            if(request==null)return;
            if(group.peerCertificate.identityProofFormat()!=2){endpoint.sendIfSession(peer,session,request.encode(),CorePersistenceCoordinator.Operation.RENEWAL);return;}
            var certificate=pending==null?group.state.issueCertificateRenewal(group.peerCertificate,group.peerCertificate.field(2),group.administratorSecret,
                    RenewalMessage.Reason.AUTO_RENEWAL,null):AdminRecords.decode(LanGroup.renewalCertificate(pending));
            publishDelivery(peer,session,RenewalMessage.delivery(request,certificate.encode()));
        }catch(Exception failure){log("LAN_RENEWAL_REJECTED");}
        finally{Crypto.wipe(peer);Crypto.wipe(session);Crypto.wipe(pending);}
    }
    /** 答え212。管理者が始めたセッションごとに1回、自分の証明書をFIRSTで示す。 */
    static List<byte[]> memberFirstTargets(LanGroup group,List<AdminRecords.Record> peers) {
        var result=new ArrayList<byte[]>();var list=group.state.administrators();
        if(!list.hasAdminBindings()&&list.entries().size()==1) {
            if(group.peerCertificate!=null&&list.hasEntry(group.urlAdmin))result.add(Crypto.blake2s(group.peerCertificate.field(0)));
            return result;
        }
        for(var cert:peers) {
            byte[] member=Crypto.blake2s(cert.field(0));
            try{group.state.verifyCertificate(cert,cert.field(1));}catch(SecurityException invalid){continue;}
            for(var binding:list.bindings())if(binding.state()==AdminBinding.State.BOUND&&Crypto.equal(binding.memberId(),member)
                    &&Crypto.equal(binding.identityKey(),cert.field(0))){result.add(member);break;}
        }return result;
    }
    private static final class MemberFirst {
        byte[] session;long observed;boolean started;
        MemberFirst(byte[] session,long observed){this.session=session.clone();this.observed=observed;}
    }
    private final Map<String,MemberFirst> memberFirst=new HashMap<>();
    private void showMemberFirst() {
        if(group.isAdministrator()||!permits(CorePersistenceCoordinator.Operation.RECONNECT))return;
        var certificates=new ArrayList<AdminRecords.Record>();for(var peer:endpoint.knownPeers())certificates.add(peer.certificate());
        var targets=memberFirstTargets(group,certificates);var retained=new HashSet<String>();
        for(byte[] peer:targets) {
            byte[] session=endpoint.sessionId(peer);String key=renewalPeer(peer);
            try {
                if(session==null||!endpoint.isPeerInitiatedSession(peer,session))continue;
                retained.add(key);long now=runtime.nanos.getAsLong();var entry=memberFirst.get(key);
                if(entry==null||!java.util.Arrays.equals(entry.session,session)) {
                    if(entry!=null)Crypto.wipe(entry.session);entry=new MemberFirst(session,now);memberFirst.put(key,entry);
                }
                if(entry.started||now<entry.observed||now-entry.observed<ProofRequests.RETRY_NANOS)continue;
                try{entry.started=endpoint.startIfPermitted(peer,session);}
                catch(IllegalStateException waiting){/* 次のpollで核の制限を確かめる。 */}
            }finally{Crypto.wipe(peer);Crypto.wipe(session);}
        }
        memberFirst.entrySet().removeIf(entry->{if(retained.contains(entry.getKey()))return false;Crypto.wipe(entry.getValue().session);return true;});
    }
    private void startPeer(){
        if(group==null||endpoint==null||group.peerCertificate==null||!permits(CorePersistenceCoordinator.Operation.RECONNECT))return;
        byte[] peer=Crypto.blake2s(group.peerCertificate.field(0));
        if(group.state.localCertificateReason(group.peerCertificate,group.peerCertificate.field(1))!=UdpEndpoint.CloseReason.RUNNING)return;
        try{if(!endpoint.isEstablished(peer)){connectBegan=runtime.millis();endpoint.startIfPermitted(peer,CorePersistenceCoordinator.Operation.RECONNECT);reconnect.retry(runtime.nanos.getAsLong());}}
        catch(RuntimeException e){reconnect.retry(runtime.nanos.getAsLong());}
    }

    private void discard(JoinOperation operation){
        try{var stage=operation.staged.getAndSet(null);if(stage!=null)stage.abort();}
        catch(Exception e){throw new IllegalStateException("仮の保存を消せません");}
        finally{operation.close();}
    }
    /** futureとcloseのどちらが先でも、この処理で加入を片付ける。 */
    private void failedJoin(){
        JoinOperation operation=joiningOperation;
        restoreFailedJoin(operation==null?null:operation.previous,operation==null?null:operation.priorReconnect,false);
    }
    private void restoreFailedJoin(LanGroup previous,ReconnectSupervisor prior,boolean clockFailure){
        stopNetwork();
        if(previous!=null){
            group=previous;reconnect.restore(prior);
            if(!certificateExpired)try{openMember();}catch(Exception e){reconnect.stop();releaseGroup();}
        }else releaseGroup();
        if(ready)message=clockFailure?CLOCK:previous!=null&&certificateExpired?EXPIRED:JOIN_FAILED;
        main.accept(()->{if(!stopped)ui.hideSensitive();});
    }
    private void stopNetwork(){
        if(recoveringNetwork&&recoveryCannotContinue())recoveryUnavailable=true;
        if(persistence!=null&&persistence.stopReason()==CorePersistenceCoordinator.StopReason.COMMITTED_NOT_APPLIED)committedNotApplied=true;
        cancelPreparation();
        if(incomingAdministration!=null){incomingAdministration.close();incomingAdministration=null;}
        if(recovery!=null){recovery.close();recovery=null;}
        if(roster!=null){roster.close();roster=null;}managedSessions=null;recoveringNetwork=false;
        persistence=null;managementUnion=null;managementClock=null;joining=false;proofRequests.close();
        for(var entry:memberFirst.values())Crypto.wipe(entry.session);memberFirst.clear();
        for(byte[] session:deliverySessions.values())Crypto.wipe(session);deliverySessions.clear();
        // callbackは同じworkerへキューを置くだけなので、ここからcloseを待てる。
        generation.incrementAndGet();
        if(sync!=null){sync.close();sync=null;}
        inbox.clear();
        source.clear();captureBaseline.clear();importExternal=null;syncReceived=Set.of();importStatus.clear();main.accept(runtime.cot::stop);
        if(endpoint!=null){endpoint.close();endpoint=null;}else if(invitation!=null)invitation.close();
        // 順序: 端点（ポート）を止める → DHT のメモリを捨てる → 保存の消去は呼び出し側が最後に行う（答え 196 (9)）。
        stopDht();
        boolean fatal=false;
        if(joiningOperation!=null){JoinOperation operation=joiningOperation;joiningOperation=null;fatal=operation.fatal;discard(operation);}
        invitation=null;bound=null;established=false;connectBegan=0;
        if(invitationSecrets!=null){for(byte[] secret:invitationSecrets)Crypto.wipe(secret);invitationSecrets=null;}
        if(fatal)throw new IllegalStateException("加入結果を保存・検査できません");
    }
    private void publish(){publish(false);}
    private void publish(boolean failure){
        if(stopped||(mainFailed.get()&&(!failure||mainFailurePublished)))return;
        if(mainFailed.get())mainFailurePublished=true;
        rememberPublicGroup();boolean hasWifi=selection()!=null,member=savedMember;
        String stop=managementStopText();String shownMessage=stop.isEmpty()?message:stop;
        String text="DistribuTAK "+BuildConfig.VERSION_NAME+"\n"+selfCheck+"\nWi-Fi IPv4: "+(hasWifi?"利用可能":"なし／選べません")+"\n"+shownMessage;
        if(member){
            if(stop.isEmpty())text+=publicGroup;
            if(stop.isEmpty()&&(!administrator||publicExpiry>clock.millis()))text+="\n"+CertificateStatus.text(publicExpiry,clock.millis(),publicRenewals);
            text+="\nセッション: "+(established?"確立":endpoint==null?"停止":"待機／握手中");
        }
        int unknown=unknownCount();
        if(unknown>0&&stop.isEmpty())text+="\n対応のない管理者: "+unknown+" 件";
        if(revokedPeerForgotten)text+="\n相手は失効しました";
        if(keyMissed)text+="\n新しいグループの鍵があるようです。管理者の新しい招待を読んでください";
        if(!storageWarning.isEmpty())text+="\n"+storageWarning;
        if(store!=null&&store.largeState())text+="\n保存の大きさが512KiBを超えています";
        text+="\n試験DATA 送信: "+tx+" 受信: "+rx+" 拒否: "+reject;
        if(sync!=null)importStatus.expired(sync.externalExpired());
        importStatus.attempts(runtime.cot.importAttempts());
        text+=runtime.cot.diagnostics()+importStatus.text(sync==null?-1:sync.externalImportsSkipped());
        String mapStatus=runtime.cot.captureStatus();if(!mapStatus.isEmpty())text+="\n"+mapStatus;
        if(syncUidLimitReached)text+="\nCoT の識別子が4096件の上限に達しました。新しい識別子は同期できません。";
        if(externalLimitReached)text+="\n外来の印が65536件の上限に達しました。新しい識別子は同期できません。";
        if(sync!=null){var counts=sync.statistics();text+="\n同期 送信: "+counts.sent()+" 受信: "+counts.received()+" 拒否: "+counts.rejected()+" 不明: "+counts.unknown()+" 上限: "+counts.capacity()+"\n時計待ち: "+counts.clockBlocked()+" 再送: "+counts.retries()+" 失敗: "+counts.failed();}
        boolean dhtOn=dht!=null&&dht.active();
        if(dhtOn){
            text+="\nDHT 経路表: "+dht.routingSize()+" 預かり: "+dht.storedRecords()+" 検証で拒否: "+dht.refusedRecords();
            String result=dht.result();if(result!=null)text+="\n"+result;
        }
        Status status=new Status(text,ready,hasWifi,member,savedAdmin,busy||joining||managementBusy,endpoint!=null,store!=null&&store.erased(),store!=null&&store.erasing(),store==null?0:store.port(),certificateExpired||keyMissed,administrator&&savedMember&&!savedAdmin,dhtOn);
        status.unknown=unknown;status.operationsReady=stop.isEmpty();
        main.accept(()->{if(!stopped)ui.render(status);});
    }
    @Override public synchronized void close(){
        if(stopped)return;
        stopped=true;generation.incrementAndGet();
        worker.execute(()->{
            try{stopNetwork();}catch(RuntimeException e){log("LAN_STOPPED");}
            finally{try{if(wifi!=null)wifi.close();}finally{releaseGroup();}}
        });worker.close();
    }
}
