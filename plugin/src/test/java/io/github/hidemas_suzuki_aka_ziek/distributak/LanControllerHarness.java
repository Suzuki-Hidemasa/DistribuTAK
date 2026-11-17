// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.net.*;
import java.time.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import static org.junit.Assert.*;

/** Controllerと核は本物。順序の試験はメモリ内の輸送、実UDPの確認は専用モード。 */
final class LanControllerHarness implements AutoCloseable {
    static final AtomicInteger NEXT=new AtomicInteger();
    static final Set<Integer> RESERVED=ConcurrentHashMap.newKeySet();
    static final Map<Integer,Inet4Address> SOURCES=new ConcurrentHashMap<>();
    static final Clock CLOCK=Clock.fixed(Instant.ofEpochMilli(10_000_000_000L),ZoneOffset.UTC);
    static final class Queue implements LanRuntime.Tasks {
        final java.util.Queue<Runnable> tasks=new ConcurrentLinkedQueue<>();Runnable repeated,syncRepeated;boolean closed;
        public void execute(Runnable action){if(closed)throw new RejectedExecutionException();tasks.add(action);}
        public void repeat(Runnable action){repeated=action;}
        public void repeatSync(Runnable action){syncRepeated=action;}
        public void close(){closed=true;}
        void drain(){for(Runnable action;(action=tasks.poll())!=null;)action.run();}
        void tick(){if(!closed){if(repeated!=null)tasks.add(repeated);if(syncRepeated!=null)tasks.add(syncRepeated);}}
    }
    static final class Ui implements LanController.Ui {
        volatile long epoch;boolean front=true,sensitive;int qrs;byte[] pixels;LanController.Status last;
        boolean failQr,failRender,failHide;int renders,hides;byte[] transferred;
        final List<String> managementTexts=new ArrayList<>(),choiceLabels=new ArrayList<>(),statusTexts=new ArrayList<>();
        Object confirmation;int confirmationCount,confirmations;
        public void confirmUnknown(Object token,int count){confirmation=token;confirmationCount=count;confirmations++;}
        public void confirmManagement(Object token,String title,String text){confirmation=token;confirmations++;managementTexts.add(title);managementTexts.add(text);}
        Object naming,input;
        public void namingWait(Object token){naming=token;}
        public void inputLabel(Object token){input=token;}
        Object choiceToken;java.util.List<LanController.NamedChoice> choices;
        public void chooseManagement(Object token,String title,java.util.List<LanController.NamedChoice> values){
            choiceToken=token;choices=values;managementTexts.add(title);for(var value:values)choiceLabels.add(value.label);
        }
        public void hideManagementConfirmation(){confirmation=null;}
        public void render(LanController.Status status){renders++;if(failRender)throw new IllegalStateException("private UI detail");last=status;statusTexts.add(status.text);}
        public void qr(byte[] image){transferred=image;if(failQr)throw new IllegalStateException("private QR detail");qrs++;sensitive=true;Crypto.wipe(pixels);pixels=image.clone();Crypto.wipe(image);}
        public void hideSensitive(){hides++;epoch++;sensitive=false;Crypto.wipe(pixels);pixels=null;if(failHide)throw new IllegalStateException("private cleanup detail");}
        public long screenEpoch(){return epoch;}
        public boolean foreground(){return front;}
        void hide(){front=false;hideSensitive();}
        void show(){front=true;}
    }
    static final class Disk implements LanRuntime.Storage,LanRuntime.Stores {
        final StateEnvelope envelope=new StateEnvelope(new StateEnvelopeTest.TestCipher());
        final StateEnvelopeTest.MemoryTarget state=new StateEnvelopeTest.MemoryTarget(),temporary=new StateEnvelopeTest.MemoryTarget(),sync=new StateEnvelopeTest.MemoryTarget(),external=new StateEnvelopeTest.MemoryTarget();
        final GroupStateStorageTest.File settings=new GroupStateStorageTest.File();
        ColdFileStore spill;int spillOpens;java.io.File spillDirectory;
        public SyncSpill openSpill(LanGroup group)throws Exception{
            if(spillDirectory==null)spillDirectory=java.nio.file.Files.createTempDirectory("distributak-controller-cache-").toFile();
            spillOpens++;return spill=new ColdFileStore(spillDirectory,envelope,group.groupId,group.id(),ColdFileStore.DEFAULT_BYTES,ColdFileStore.DEFAULT_FILES);
        }
        Inet4Address networkAddress;final int initialPort;int port;boolean erased,erasing,initialPending,failSave,failStage;LanGroup creating;int portDraws;volatile int staged;
        volatile Runnable beforeStage=()->{},afterStage=()->{};
        Disk(int port){this.port=port;initialPort=port;}
        public int port(){return port;}
        public boolean erased(){return erased;}
        public boolean erasing(){return erasing;}
        private StoreRecovery.EraseTarget target(){return target(false);}
        private StoreRecovery.EraseTarget target(boolean initial){return new StoreRecovery.EraseTarget(){
            public boolean pending(){return erasing&&initialPending==initial;}
            public void markPending(){erasing=true;initialPending=initial;}
            public void stop(){}
            public void deleteKey(){}
            public void deleteRecords(){state.value=null;temporary.value=null;sync.value=null;external.value=null;settings.value=null;}
            public void markComplete(){if(!initial)erased=true;}
            public void wipeMemory(){}
            public void clearPending(){if(initialPending==initial)erasing=false;}
        };}
        public void create(LanGroup group)throws Exception {
            creating=group;
            StoreRecovery.create(target(!erased),()->save(group),()->erased=false);
        }
        public LanRuntime.Storage open()throws Exception{StoreRecovery.resume(target(false),target(true));temporary.value=null;return this;}
        Runnable afterStop=()->{};
        public LanRuntime.Storage erase(Runnable stop,Runnable wipe)throws Exception{stop.run();afterStop.run();StoreRecovery.erase(target());wipe.run();port=freePort();portDraws++;return this;}
        private SyncStateStorage.Source source(StateEnvelopeTest.MemoryTarget file){return new SyncStateStorage.Source(){
            public boolean exists(){return file.value!=null;}
            public byte[] read(){return file.value.clone();}
        };}
        GroupStateStorage groupStorage(){state.fail=failSave;return new GroupStateStorage(envelope,state,source(state),settings,settings,v->{});}
        Clock loadClock;RuntimeException loadFailure;
        VersionSixStorageTest.Files managementFiles;
        StopMarkerTest.Disk stopMarker;
        void enableSix(){managementFiles=new VersionSixStorageTest.Files();stopMarker=new StopMarkerTest.Disk();}
        GroupStateStorage managedStorage(){state.fail=failSave;return managementFiles==null?groupStorage():new GroupStateStorage(envelope,state,source(state),settings,settings,v->{},managementFiles,stopMarker.marker());}
        public void prepareNetwork(LanGroup group)throws Exception{managedStorage().prepareNetwork(group);}
        Runnable afterMembership=()->{};
        public void saveMembership(LanGroup group,AdminRecordStore.Snapshot snapshot,byte[] secret)throws Exception{
            managedStorage().saveMembership(group,snapshot,secret);afterMembership.run();
        }
        Runnable beforeCandidateSave;
        java.util.function.Consumer<AdminRecordStore.Snapshot> afterCandidateSave;
        int candidateSaves;
        public CorePersistenceCoordinator.PersistenceHooks persistenceHooks(LanGroup group){
            var delegate=managedStorage().persistenceHooks(group);
            if(beforeCandidateSave==null&&afterCandidateSave==null)return delegate;
            return new CorePersistenceCoordinator.PersistenceHooks(){
                public void save(AdminRecordStore.Snapshot snapshot){
                    if(beforeCandidateSave!=null)beforeCandidateSave.run();
                    delegate.save(snapshot);candidateSaves++;
                    if(afterCandidateSave!=null)afterCandidateSave.accept(snapshot);
                }
                public void stopped(CorePersistenceCoordinator.StopReason reason){delegate.stopped(reason);}
            };
        }
        public LanGroup load(Clock clock)throws Exception {if(loadFailure!=null)throw loadFailure;return erased?null:managedStorage().load(loadClock==null?clock:loadClock);}
        public void save(LanGroup group)throws Exception {managedStorage().save(group);}
        int directorySaves;Runnable afterDirectory=()->{};
        public void saveDirectory(LanGroup group,MemberDirectory directory,Map<String,String> labels)throws Exception{
            if(managementFiles==null)enableSix();directorySaves++;managedStorage().saveDirectory(group,directory,labels);afterDirectory.run();
        }
        public boolean largeState(){return state.value!=null&&state.value.length>512*1024;}
        boolean failLocalRenewal,failIssuedRenewal;
        Runnable afterLocalRenewal=()->{};
        public boolean saveLocalRenewal(LanGroup group,AdminRecords.Record certificate)throws Exception{if(failLocalRenewal)throw new java.io.IOException("test save failure");boolean saved=managedStorage().saveLocalRenewal(group,certificate);afterLocalRenewal.run();return saved;}
        public boolean saveIssuedRenewal(LanGroup group,byte[] id,byte[] certificate)throws Exception{if(failIssuedRenewal)throw new java.io.IOException("test save failure");return managedStorage().saveIssuedRenewal(group,id,certificate);}
        public boolean savePeer(LanGroup group,AdminRecords.Record certificate,InetSocketAddress address)throws Exception{return managedStorage().savePeer(group,certificate,address);}
        java.util.function.Consumer<LanGroup> beforeAcceptRejoined=previous->{};
        public void acceptRejoined(Future<?> future,LanGroup previous,LanGroup candidate,LanRuntime.Pending pending)throws Exception{beforeAcceptRejoined.accept(previous);groupStorage().acceptRejoined(previous,candidate,future,pending);}
        private SyncStateStorage syncStorage(){return new SyncStateStorage(envelope,sync,new SyncStateStorage.Source(){
            public boolean exists(){return sync.value!=null;}
            public byte[] read(){return sync.value.clone();}
        },externalStorage());}
        private ExternalStateStorage externalStorage(){return new ExternalStateStorage(envelope,external,new SyncStateStorage.Source(){
            public boolean exists(){return external.value!=null;}
            public byte[] read(){return external.value.clone();}
        });}
        public ExternalMarks loadExternal(LanGroup group)throws Exception{return externalStorage().load(group);}
        public void saveExternal(LanGroup group,ExternalMarks marks)throws Exception{external.fail=failSave;externalStorage().save(group,marks);}
        public SyncState loadSync(LanGroup group)throws Exception{return syncStorage().load(group,()->save(group));}
        public void saveSync(LanGroup group,SyncState snapshot)throws Exception{sync.fail=failSave;syncStorage().save(group,snapshot);}
        public byte[] loadSyncEncoded(LanGroup group)throws Exception{return syncStorage().readEncoded(group);}
        public void saveSyncEncoded(LanGroup group,SyncState snapshot,byte[] encoded)throws Exception{sync.fail=failSave;syncStorage().saveEncoded(group,snapshot,encoded);}
        public LanRuntime.Pending stage(LanGroup group)throws Exception {
            beforeStage.run();temporary.fail=failStage;
            var pending=groupStorage().stage(group,temporary,()->temporary.value.clone(),()->temporary.value=null);
            staged++;afterStage.run();return pending;
        }
        public void acceptJoined(Future<?> done,LanRuntime.Pending pending)throws Exception {
            StoreRecovery.acceptJoined(done,target(!erased),pending::commit,()->erased=false);
        }
        int reserves;boolean failReserve;Runnable beforeReserve=()->{};
        public long reserveDhtVersion(LanGroup group)throws Exception{
            beforeReserve.run();reserves++;var storage=groupStorage();state.fail=failReserve||failSave;return storage.reserveDhtVersion(group);
        }
        public void setPort(int value,LanGroup group)throws Exception{if(group!=null){group.port=value;save(group);}port=value;}
    }
    private static final Map<Integer,MemoryIo> ROUTES=new ConcurrentHashMap<>();
    static final class MemoryIo implements UdpEndpoint.DatagramIo {
        private static final UdpEndpoint.Datagram STOP=new UdpEndpoint.Datagram(new byte[0],new InetSocketAddress("127.0.0.1",1));
        final int port;final Inet4Address address;final AtomicInteger received;
        // 受信の待ちとcloseの順序を試験で確かめるための合図。製品には入らない。
        final CountDownLatch receiveEntered=new CountDownLatch(1);
        private final BlockingQueue<UdpEndpoint.Datagram> queue=new LinkedBlockingQueue<>();private volatile boolean closed;
        MemoryIo(int port,Inet4Address address,AtomicInteger received)throws java.io.IOException {
            this.port=port;this.address=address;this.received=received;
            if(ROUTES.putIfAbsent(port,this)!=null)throw new BindException("test port already bound");
        }
        public UdpEndpoint.Datagram receive()throws java.io.IOException {
            if(closed)throw new SocketException("test transport closed");
            try{receiveEntered.countDown();var packet=queue.take();if(packet==STOP)throw new SocketException("test transport closed");received.incrementAndGet();return packet;}
            catch(InterruptedException e){Thread.currentThread().interrupt();throw new java.io.IOException("test receive interrupted");}
        }
        public void send(byte[] wire,InetSocketAddress target)throws java.io.IOException {
            if(closed)throw new SocketException("test transport closed");var peer=ROUTES.get(target.getPort());
            if(peer!=null&&peer.address.equals(target.getAddress()))peer.deliver(new UdpEndpoint.Datagram(wire.clone(),new InetSocketAddress(address,port)));
        }
        private synchronized void deliver(UdpEndpoint.Datagram packet){if(closed)Crypto.wipe(packet.wire());else queue.add(packet);}
        public synchronized void close(){if(closed)return;closed=true;ROUTES.remove(port,this);for(UdpEndpoint.Datagram packet;(packet=queue.poll())!=null;)Crypto.wipe(packet.wire());queue.offer(STOP);}
    }
    final class Link implements LanRuntime.Link {
        final String id;final Inet4Address address;int opens,failOpens;Runnable beforeOpen=()->{},afterIoClose=()->{};UdpEndpoint.DatagramIo lastIo;final AtomicInteger received=new AtomicInteger();
        Link(String id,Inet4Address address){this.id=id;this.address=address;}
        public Inet4Address address(){return address;}
        int prefix=24;
        public int prefixLength(){return prefix;}
        public boolean same(LanRuntime.Link other){return other instanceof LanControllerHarness.Link
                &&id.equals(((Link)other).id)&&address.equals(other.address());}
        public UdpEndpoint.DatagramIo open(int port)throws Exception {
            opens++;beforeOpen.run();if(failOpens>0){failOpens--;throw new java.io.IOException("test open failure");}
            if(!realUdp){var io=new MemoryIo(port,address,received);return lastIo=new UdpEndpoint.DatagramIo(){
                public UdpEndpoint.Datagram receive()throws java.io.IOException{return io.receive();}
                public void send(byte[] wire,InetSocketAddress target)throws java.io.IOException{io.send(wire,target);}
                public void close(){io.close();afterIoClose.run();}
            };}
            DatagramSocket socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",port));
            SOURCES.put(port,address);var io=new UdpEndpoint.SocketIo(socket);
            return new UdpEndpoint.DatagramIo(){
                public UdpEndpoint.Datagram receive()throws java.io.IOException {
                    var packet=io.receive();received.incrementAndGet();Inet4Address source=SOURCES.get(packet.source().getPort());
                    if(source==null)throw new java.io.IOException("unknown test socket");
                    return new UdpEndpoint.Datagram(packet.wire(),new InetSocketAddress(source,packet.source().getPort()));
                }
                public void send(byte[] wire,InetSocketAddress target)throws java.io.IOException {
                    // 試験のパケットは例外なく127.0.0.1にだけ送る。
                    io.send(wire,new InetSocketAddress(InetAddress.getByName("127.0.0.1"),target.getPort()));
                }
                public void close(){io.close();SOURCES.remove(port,address);}
            };
        }
    }
    static final class Network implements LanRuntime.Network {
        volatile LanRuntime.Link current;Runnable changed;private LanRuntime.Link last;private long revision;
        synchronized void signal(Runnable notify){if(last==null?current!=null:!last.same(current)){revision++;last=current;}notify.run();}
        public synchronized LanRuntime.NetworkSnapshot snapshot(){return new LanRuntime.NetworkSnapshot(current,revision);}
        public LanRuntime.Link current(){return current;}
        public void close(){}
    }
    private final boolean realUdp;
    final Queue work=new Queue(),main=new Queue();final Ui ui=new Ui();
    final Network network=new Network();final AtomicLong offset=new AtomicLong();
    /** DHT の公開のばらつきの値（ミリ秒。上限は LanDht.JITTER_MILLIS）。既定は上限で、5 分は自分から公開し直さない。DHT の試験だけが create の前に 0 などへ変える。 */
    volatile int jitterValue=LanDht.JITTER_MILLIS;
    private Invitation recordedInvitation;
    final List<String> logs=new CopyOnWriteArrayList<>();final Link link;final Disk disk;final LanController controller;
    LanControllerHarness()throws Exception {this(null);}
    LanControllerHarness(Disk existing)throws Exception {this(existing,CotPort.NONE);}
    LanControllerHarness(Disk existing,CotPort cot)throws Exception {this(existing,cot,System::nanoTime);}
    LanControllerHarness(Disk existing,CotPort cot,Clock clock)throws Exception {this(existing,cot,System::nanoTime,false,clock);}
    LanControllerHarness(Disk existing,CotPort cot,java.util.function.LongSupplier nanos,Clock clock)throws Exception {this(existing,cot,nanos,false,clock);}
    LanControllerHarness(Disk existing,CotPort cot,java.util.function.LongSupplier nanos)throws Exception {this(existing,cot,nanos,false);}
    static LanControllerHarness realUdp()throws Exception{return new LanControllerHarness(null,CotPort.NONE,System::nanoTime,true);}
    private LanControllerHarness(Disk existing,CotPort cot,java.util.function.LongSupplier nanos,boolean realUdp)throws Exception {
        this(existing,cot,nanos,realUdp,CLOCK);
    }
    static LanControllerHarness unreadable(Disk disk,Clock clock)throws Exception{return new LanControllerHarness(disk,CotPort.NONE,System::nanoTime,false,clock,false);}
    private LanControllerHarness(Disk existing,CotPort cot,java.util.function.LongSupplier nanos,boolean realUdp,Clock clock)throws Exception {
        this(existing,cot,nanos,realUdp,clock,true);
    }
    private LanControllerHarness(Disk existing,CotPort cot,java.util.function.LongSupplier nanos,boolean realUdp,Clock clock,boolean expectReady)throws Exception {
        this.realUdp=realUdp;
        int number=NEXT.incrementAndGet();disk=existing==null?new Disk(freePort()):existing;
        if(disk.networkAddress==null)disk.networkAddress=(Inet4Address)InetAddress.getByAddress(new byte[]{(byte)192,0,2,(byte)number});
        link=new Link("A",disk.networkAddress);network.current=link;
        var runtime=new LanRuntime(disk,changed->{network.last=network.current;network.changed=()->network.signal(changed);return network;},work,main::execute,logs::add,
                ()->{},clock,()->nanos.getAsLong()+offset.get(),new SecureRandom(),(value,size)->{
                    if(recordedInvitation!=null)recordedInvitation.close();byte[] secret=value.totpSecret();
                    try{recordedInvitation=new Invitation(value.adminAddress(),value.udpPort(),value.handshakePublicKey(),value.adminPublicKey(),secret, value.groupId());}
                    finally{Crypto.wipe(secret);}
                    return InvitationQr.encode(value,size);
                },cot,io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncLimits.DEFAULT,new java.util.Random(){
                    @Override public int nextInt(int bound){return Math.min(jitterValue,bound-1);}
                });
        controller=new LanController(ui,runtime);drain();assertEquals(expectReady,ui.last.ready);
    }
    static int freePort()throws Exception {
        for(int i=0;i<1000;i++) {
            int port=49152+new SecureRandom().nextInt(16384);
            if(!RESERVED.add(port))continue;
            try(var socket=new DatagramSocket(new InetSocketAddress("127.0.0.1",port))){return port;}
            catch(java.net.BindException ignored){}
        }throw new AssertionError("no test port");
    }
    void drain(){work.drain();main.drain();}
    void tick(){work.tick();drain();}
    void create(){controller.create();drain();assertTrue(ui.last.member);}
    Invitation invitation()throws Exception {return invitation(false);}
    Invitation rejoinInvitation()throws Exception {return invitation(true);}
    private Invitation invitation(boolean rejoin)throws Exception {
        if(rejoin)controller.showRejoinInvitation(controller.ticket(),512);else controller.showInvitation(controller.ticket());
        drain();assertNotNull(ui.pixels);
        assertNotNull(recordedInvitation);byte[] secret=recordedInvitation.totpSecret();
        try{return new Invitation(recordedInvitation.adminAddress(),recordedInvitation.udpPort(),recordedInvitation.handshakePublicKey(),recordedInvitation.adminPublicKey(),secret, recordedInvitation.groupId());}
        finally{Crypto.wipe(secret);}
    }
    void beginJoin(LanControllerHarness admin)throws Exception {
        var value=admin.invitation();controller.join(value,controller.ticket());drain();
    }
    static Object field(Object target,String name)throws Exception {
        var field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);
    }
    UdpEndpoint endpoint()throws Exception{return (UdpEndpoint)field(controller,"endpoint");}
    Future<?> joinFuture()throws Exception{return (Future<?>)field(field(controller,"joiningOperation"),"future");}
    Invitation unreachable()throws Exception {
        var random=new SecureRandom();byte[] x=LanGroup.random(random),a=LanGroup.random(random),t=LanGroup.random(random);
        try{return new Invitation(new byte[]{(byte)198,51,100,1},freePort(),Crypto.x25519Public(x),Crypto.ed25519Public(a),t, new byte[32]);}
        finally{Crypto.wipe(x);Crypto.wipe(a);Crypto.wipe(t);}
    }
    interface Check {boolean ok()throws Exception;}
    static void until(Check check,LanControllerHarness... nodes)throws Exception {until("controller condition",check,nodes);}
    static void until(String branch,Check check,LanControllerHarness... nodes)throws Exception {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!check.ok()) {
            for(var node:nodes)node.tick();
            if(System.nanoTime()>end)throw new AssertionError(diagnostics(branch,nodes));Thread.sleep(5);
        }
        for(var node:nodes)node.drain();
    }
    static String diagnostics(String branch,LanControllerHarness... nodes){
        StringBuilder out=new StringBuilder("branch=").append(branch);
        for(int i=0;i<nodes.length;i++) {
            var node=nodes[i];var status=node.ui.last;
            out.append(" node=").append(i).append(" staged=").append(node.disk.staged)
                .append(" statePresent=").append(node.disk.state.value!=null).append(" temporaryPresent=").append(node.disk.temporary.value!=null)
                .append(" ready=").append(status==null?false:status.ready).append(" busy=").append(status==null?false:status.busy)
                .append(" member=").append(status==null?false:status.member).append(" erased=").append(node.disk.erased)
                .append(" publicStatus=").append(status==null?"none":status.text.replace('\n',' ')).append(" logs=").append(node.logs)
                .append(" workQueued=").append(node.work.tasks.size()).append(" mainQueued=").append(node.main.tasks.size());
            try {
                var endpoint=node.endpoint();out.append(" endpointReason=").append(endpoint==null?"none":endpoint.closeReason());
                Object operation=field(node.controller,"joiningOperation");
                Future<?> future=operation==null?null:(Future<?>)field(operation,"future");
                out.append(" joinFutureDone=").append(future!=null&&future.isDone());
            }catch(Exception ignored){out.append(" endpointInspection=unavailable");}
        }return out.toString();
    }
    public void close(){if(recordedInvitation!=null)recordedInvitation.close();controller.close();work.drain();main.drain();ui.hideSensitive();if(disk.spillDirectory!=null)disk.spillDirectory.delete();}
}
