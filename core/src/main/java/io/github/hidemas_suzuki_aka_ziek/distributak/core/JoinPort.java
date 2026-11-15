// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.IOException;
import java.net.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import org.bouncycastle.util.encoders.Hex;

/** UDPに載せる部分だけを受け持つ。暗号の核の規則を変えない。 */
final class JoinPort {
    static final long SECOND=1_000_000_000L,LIFETIME=10*SECOND;
    private final UdpEndpoint owner;
    private final UdpEndpoint.DatagramIo io;
    private final LongSupplier clock;
    private final ScheduledThreadPoolExecutor worker;
    private volatile Thread workerThread;
    private final Map<String,Registration> registrations=new HashMap<>();
    private final Map<InetAddress,Budget> responseRates=new HashMap<>();
    private final Budget sent=new Budget(8192),requested=new Budget(8192),peerRequests=new Budget(4096);
    private boolean closed;
    private Registration active;
    private Pending pending;
    private int adminJobs;
    private long lastTime=Long.MIN_VALUE;
    private boolean clockRead;

    JoinPort(UdpEndpoint owner,UdpEndpoint.DatagramIo io,LongSupplier clock) {
        this.owner=owner;this.io=io;this.clock=clock;
        worker=new ScheduledThreadPoolExecutor(1,task->{
            Thread thread=new Thread(task,"distributak-join");thread.setDaemon(true);workerThread=thread;return thread;
        });
        worker.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        worker.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        worker.scheduleWithFixedDelay(this::tick,10,10,TimeUnit.MILLISECONDS);
    }
    private static String key(byte[] id) { return Hex.toHexString(id); }
    private void open() { if(closed) throw new IllegalStateException("入るための口は閉じています"); }
    final class Registration implements UdpEndpoint.InvitationRegistration {
        final JoinHandshake.Admin admin;
        final UdpEndpoint.MaterialsProvider provider;
        final Consumer<UdpEndpoint.AdminJoined> callback;
        final byte[] id;
        byte[] transfer,request,reply;
        InetSocketAddress address;
        long started;
        boolean busy,ended,removed;
        UdpEndpoint.AdminJoined last;
        Registration(JoinHandshake.Admin admin,UdpEndpoint.MaterialsProvider provider,Consumer<UdpEndpoint.AdminJoined> callback) {
            this.admin=admin;this.provider=Objects.requireNonNull(provider);this.callback=Objects.requireNonNull(callback);id=admin.invitationId();
        }
        public UdpEndpoint.AdminJoined lastJoined() { synchronized(JoinPort.this) { return last; } }
        public void close() {
            synchronized(JoinPort.this) {
                if(removed) return;removed=true;registrations.remove(key(id));clear();last=null;
            }
            admin.close();
        }
        void clear() {
            Crypto.wipe(transfer);Crypto.wipe(request);Crypto.wipe(reply);transfer=null;request=null;reply=null;address=null;
            if(active==this) active=null;
        }
        @Override public String toString() { return "InvitationRegistration"; }
    }
    synchronized UdpEndpoint.InvitationRegistration register(JoinHandshake.Admin admin,UdpEndpoint.MaterialsProvider provider,Consumer<UdpEndpoint.AdminJoined> callback) {
        open();Objects.requireNonNull(admin);String id=key(admin.invitationId());
        if(registrations.size()>=8||registrations.containsKey(id)) throw new IllegalArgumentException("招待の登録の上限か重複です");
        var registration=new Registration(admin,provider,callback);registrations.put(id,registration);return registration;
    }
    /** 完了する操作は核の中だけに置く。API23でも利用できるFuture。 */
    static final class Completion<T> extends FutureTask<T> {
        Completion(){super(()->null);}
        @Override public void run(){} // 実行する仕事ではなく、加入の完了通知だけを保持する。
        @Override public boolean cancel(boolean interrupt){return super.cancel(interrupt)||isCancelled();}
        void complete(T value){set(value);}
        void fail(Throwable failure){
            if(failure instanceof CancellationException)cancel(false);else setException(failure);
        }
    }
    static final class Pending {
        final JoinHandshake.Joiner joiner;
        final UdpEndpoint.JoinedFactory factory;
        final InetSocketAddress address;
        final byte[] id,transfer=new byte[16],request;
        final Completion<AdminRecords.Record> future=new Completion<>();
        final Map<Integer,Long> flying=new LinkedHashMap<>();
        final long started;
        long lastRequest;
        int retries,next,restarts;
        boolean verifying,proofSent;
        JoinWire.Assembly assembly;
        Pending(Invitation invitation,JoinHandshake.Joiner joiner,UdpEndpoint.JoinedFactory factory,long now) {
            this.joiner=Objects.requireNonNull(joiner);this.factory=Objects.requireNonNull(factory);
            try { address=EndpointAddress.normalize(new InetSocketAddress(InetAddress.getByAddress(invitation.adminAddress()),invitation.udpPort())); }
            catch(UnknownHostException e) { throw new IllegalArgumentException("招待の番地が違います"); }
            request=joiner.request();
            try(var packet=JoinMessages.packet(request,false)) { id=packet.invitation.clone(); }
            if(request.length>CookieWire.MAX_FIRST-JoinWire.HEADER) { Crypto.wipe(request);joiner.close();throw new IllegalArgumentException("求めが大きすぎます"); }
            new SecureRandom().nextBytes(transfer);started=now;lastRequest=now;
        }
        void clear() {
            joiner.close();Crypto.wipe(request);Crypto.wipe(id);Crypto.wipe(transfer);
            if(assembly!=null) assembly.close();assembly=null;flying.clear();
        }
        @Override public String toString() { return "PendingJoin"; }
    }
    synchronized Future<AdminRecords.Record> join(Invitation invitation,JoinHandshake.Joiner joiner,UdpEndpoint.JoinedFactory factory) {
        open();if(pending!=null) throw new IllegalStateException("入る試みは1件だけです");
        Pending p=new Pending(invitation,joiner,factory,readTime());pending=p;
        send(JoinWire.request(p.id,p.transfer,p.request),p.address);return p.future;
    }
    /** 招待のIDの登録だけを確かめる。暗号のAdminロックやproviderには触らない。 */
    synchronized boolean acceptsCookieRequest(byte[] wire) {
        if(closed)return false;
        try(var frame=JoinWire.decode(wire)) {
            Registration r=registrations.get(key(frame.invitation()));
            return frame.kind()==JoinWire.REQUEST&&r!=null&&!r.removed&&!r.ended;
        }
    }
    synchronized boolean answerChallenge(CookieWire.Frame challenge,InetSocketAddress source) {
        Pending p=pending;
        if(closed||p==null||p.proofSent||p.verifying||p.assembly!=null||!EndpointAddress.same(p.address,source)
                ||elapsed(readTime(),p.started)>=LIFETIME)return false;
        byte[] first=JoinWire.request(p.id,p.transfer,p.request),hash=null;
        try {
            hash=Crypto.blake2s(first);if(!Crypto.equal(hash,challenge.hash()))return false;
            p.proofSent=true;send(CookieWire.proof(challenge.cookie(),first),source);return true;
        } finally { Crypto.wipe(first);Crypto.wipe(hash); }
    }
    /** 安い枠の検査は受信スレッド。providerと暗号は必ずworkerで呼ぶ。 */
    void receive(byte[] wire,InetSocketAddress source) {
        source=EndpointAddress.normalize(source);
        try(var frame=JoinWire.decode(wire)) {
            synchronized(this) {
                open();long now=readTime();
                if(frame.kind()==JoinWire.REQUEST||frame.kind()==JoinWire.FETCH) {
                    Registration r=registrations.get(key(frame.invitation()));
                    if(r==null||r.removed||r.ended) throw rejected();
                    if(frame.kind()==JoinWire.FETCH) {
                        if(r.reply==null||elapsed(now,r.started)>=LIFETIME||!matches(r,frame,source)||frame.total()!=r.reply.length) throw rejected();
                        if(!responseAllowed(source,now)) throw rejected();
                        send(JoinWire.data(r.id,r.transfer,r.reply,frame.index()),source);return;
                    }
                    // 開いているIDであることを確認するまでprotobufもproviderも呼ばない。
                    try(var packet=JoinMessages.packet(frame.body(),false)) {
                        if(!Arrays.equals(packet.invitation,r.id)) throw rejected();
                    }
                    if(r.busy) throw rejected();
                    if(r.reply!=null) {
                        if(elapsed(now,r.started)>=LIFETIME||!matches(r,frame,source)||!Arrays.equals(r.request,frame.body())) throw rejected();
                        if(!responseAllowed(source,now)) throw rejected();
                        send(JoinWire.ready(r.id,r.transfer,r.reply.length),source);return;
                    }
                    if(active!=null||adminJobs>=8) throw rejected();
                    active=r;r.busy=true;r.started=now;r.address=source;r.transfer=frame.transfer().clone();r.request=frame.body().clone();
                    byte[] request=r.request.clone();adminJobs++;worker.execute(()->respond(r,request));return;
                }
                Pending p=pending;
                if(p==null||p.verifying||elapsed(now,p.started)>=LIFETIME||!EndpointAddress.same(p.address,source)
                        ||!Arrays.equals(p.id,frame.invitation())||!Arrays.equals(p.transfer,frame.transfer())) throw rejected();
                if(frame.kind()==JoinWire.READY) {
                    if(p.assembly==null) p.assembly=new JoinWire.Assembly(frame.total());
                    else if(p.assembly.bytes().length!=frame.total()) throw rejected();
                } else {
                    if(p.assembly==null||!p.flying.containsKey(frame.index())) throw rejected();
                    if(p.assembly.add(frame)) p.flying.remove(frame.index());
                    if(p.assembly.complete()) { p.verifying=true;worker.execute(()->finish(p)); }
                }
            }
        }
    }
    private static boolean matches(Registration r,JoinWire.Frame frame,InetSocketAddress source) {
        return EndpointAddress.same(source,r.address)&&Arrays.equals(r.transfer,frame.transfer());
    }
    private static SecurityException rejected() { return new SecurityException("入るためのパケットを受けられません"); }
    /** 時計だけの失敗を包んで外へ渡す。ownerのロックはここでは取らない。 */
    private synchronized long readTime() {
        try {
            long now=clock.getAsLong();
            if(clockRead&&now<lastTime)throw new AddressCookies.ClockFailure();
            clockRead=true;lastTime=now;return now;
        } catch(RuntimeException e) { throw new AddressCookies.ClockFailure(); }
    }
    private static long elapsed(long now,long then) { long value=now-then;return value<0 ? Long.MAX_VALUE : value; }
    private void respond(Registration r,byte[] request) {
        byte[] reply=null;UdpEndpoint.AdminJoined result=null;
        try {
            synchronized(this) { if(closed||r.removed) return; }
            // Adminのロックは暗号の処理中にも保持される。受信スレッドからは触らない。
            r.admin.expire();if(r.admin.isClosed())throw rejected();
            try(var materials=Objects.requireNonNull(r.provider.get())) {
                reply=r.admin.respond(request,materials.handshakeSecret(),materials.administratorSecret(),materials.materials());
            }
            var certificate=r.admin.issuedCertificate();
            if(certificate==null) throw rejected();
            synchronized(this) {
                // 発行の通知は輸送の期限と分ける。返事を送れなくても発行済みの結果は知らせる。
                if(closed||r.removed) return;
                result=new UdpEndpoint.AdminJoined(certificate,r.address);r.last=result;
            }
            try { r.callback.accept(result); } catch(RuntimeException e) { owner.joinCallbackFailure(); }
            synchronized(this) {
                if(closed||r.removed||elapsed(readTime(),r.started)>=LIFETIME) return;
                r.reply=reply;reply=null;
                if(responseAllowed(r.address,readTime())) send(JoinWire.ready(r.id,r.transfer,r.reply.length),r.address);
            }
        } catch(AddressCookies.ClockFailure e) { owner.joinClockFailure(); }
        catch(RuntimeException e) { owner.joinRejected(); }
        finally {
            Crypto.wipe(request);Crypto.wipe(reply);
            synchronized(this) {
                adminJobs--;r.busy=false;
                if(r.reply==null) { if(r.admin.isConsumed()) r.ended=true;r.clear(); }
            }
        }
    }
    private void finish(Pending p) {
        JoinHandshake.Joined joined=null;SessionManager sessions=null;boolean installed=false;
        try {
            synchronized(this) { if(closed||pending!=p) return; }
            joined=p.joiner.receive(p.assembly.bytes());
            sessions=p.factory.create(joined);
            if(sessions==null) throw new IllegalStateException("加入後のセッションがありません");
            synchronized(this) { if(closed||pending!=p||elapsed(readTime(),p.started)>=LIFETIME) throw rejected(); }
            owner.installJoined(sessions,joined);installed=true;
            var certificate=joined.certificate();joined=null;sessions=null;
            synchronized(this) { if(pending==p) pending=null;p.clear(); }
            p.future.complete(certificate);
        } catch(AddressCookies.ClockFailure e) { owner.joinClockFailure(); }
        catch(RuntimeException e) {
            owner.joinRejected();boolean retry;
            try {
                synchronized(this) {
                    retry=!closed&&pending==p&&!p.joiner.isClosed()&&p.restarts<2&&elapsed(readTime(),p.started)<LIFETIME;
                    if(retry) { p.restarts++;p.assembly.close();p.assembly=new JoinWire.Assembly(p.assembly.bytes().length);p.flying.clear();p.next=0;p.verifying=false; }
                }
            } catch(AddressCookies.ClockFailure clockFailure) { owner.joinClockFailure();return; }
            if(!retry) { p.future.fail(new SecurityException("加入を完了できません"));owner.failJoining(); }
        } finally {
            if(!installed) { if(sessions!=null)sessions.close();if(joined!=null)joined.close(); }
        }
    }
    private void tick() {
        Pending failed=null;
        try {
            synchronized(this) {
                if(closed) return;long now=readTime();
                for(var r:registrations.values()) {
                    r.admin.expire();
                    if(!r.busy&&(r.admin.isClosed()||r.address!=null&&elapsed(now,r.started)>=LIFETIME)) { r.ended=true;r.clear(); }
                }
                Pending p=pending;
                if(p==null) return;
                if(elapsed(now,p.started)>=LIFETIME) { pending=null;p.clear();failed=p; }
                else if(!p.verifying) {
                    if(p.assembly==null) {
                        if(elapsed(now,p.lastRequest)>=SECOND&&p.retries<JoinHandshake.MAX_RETRIES) {
                            byte[] packet=p.joiner.retry();
                            try { send(JoinWire.request(p.id,p.transfer,packet),p.address); } finally { Crypto.wipe(packet); }
                            p.retries++;p.lastRequest=now;
                        }
                    } else {
                        for(var entry:p.flying.entrySet()) if(elapsed(now,entry.getValue())>=SECOND&&peerRequests.take(now)&&requested.take(now)) {
                            send(JoinWire.fetch(p.id,p.transfer,p.assembly.bytes().length,entry.getKey()),p.address);entry.setValue(now);
                        }
                        while(p.flying.size()<32&&p.next<p.assembly.count()&&peerRequests.take(now)&&requested.take(now)) {
                            int index=p.next++;p.flying.put(index,now);send(JoinWire.fetch(p.id,p.transfer,p.assembly.bytes().length,index),p.address);
                        }
                    }
                }
            }
            // 口のロックを取る処理は、JoinPortのモニタを離してから呼ぶ。
            if(failed!=null) { failed.future.fail(new TimeoutException("加入の期限です"));owner.failJoining(); }
        } catch(RuntimeException e) { owner.joinRejected();owner.joinClockFailure(); }
    }
    private void send(byte[] bytes,InetSocketAddress address) {
        if(pending!=null&&JoinWire.isJoin(bytes)&&bytes[4]==JoinWire.REQUEST)pending.proofSent=false;
        try { io.send(bytes,address); } catch(IOException e) { owner.joinSendFailure(); } finally { Crypto.wipe(bytes); }
    }
    private boolean responseAllowed(InetSocketAddress source,long now) {
        Budget rate=responseRates.get(source.getAddress());
        if(rate==null) {
            responseRates.values().removeIf(value->elapsed(now,value.began)>=SECOND);
            if(responseRates.size()>=8)return false;
            rate=new Budget(4096);responseRates.put(source.getAddress(),rate);
        }
        return rate.take(now)&&sent.take(now);
    }
    void stop() {
        synchronized(this) {
            if(closed) return;closed=true;Pending p=pending;pending=null;
            if(p!=null) {
                p.clear();
                // futureの利用者の処理を、口やjoinのロックの中から呼ばない。
                worker.execute(()->p.future.fail(new CancellationException("加入の口を閉じました")));
            }
            worker.shutdown();
            for(var r:registrations.values()) { r.removed=true;r.clear();r.last=null;r.admin.close(); }
            registrations.clear();responseRates.clear();
        }
    }
    boolean isWorkerThread() { return Thread.currentThread()==workerThread; }
    void await() {
        // 閉鎖通知のスレッドは、秘密を消すfinallyまで待つ。自分のworkerだけは待たない。
        if(isWorkerThread()) return;
        boolean interrupted=false;
        while(!worker.isTerminated()) try { worker.awaitTermination(1,TimeUnit.SECONDS); } catch(InterruptedException e) { interrupted=true; }
        if(interrupted)Thread.currentThread().interrupt();
    }
    boolean terminated() { return worker.isTerminated(); }
    static final class Budget {
        final int max;long began;int count;
        Budget(int max) { this.max=max; }
        boolean take(long now) {
            if(elapsed(now,began)>=SECOND) { began=now;count=0; }
            if(count>=max)return false;count++;return true;
        }
    }
}
