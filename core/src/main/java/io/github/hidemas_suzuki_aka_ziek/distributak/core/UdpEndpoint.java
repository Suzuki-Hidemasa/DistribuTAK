// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.IOException;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongConsumer;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import org.bouncycastle.util.encoders.Hex;

/**
 * 入る握手とメンバーセッションの UDP の口。渡した管理・ソケットはこの部品が所有する。
 * AdminState は SessionManager を作ったときと同じインスタンスを渡す。
 * 作成後は SessionManager と AdminState を直接操作せず、この口を通す。
 * 平文は受け口の呼び出し中だけ有効。残す場合は呼び出し元が写しを作って管理する。
 * 受け口は受信スレッドでロックの外から呼ぶ。待ち続ける処理を置かないこと。
 * 外からのcloseはソケットを閉じて鍵を消し、実行中の受け口を含むスレッドの終了を待つ。
 * 待ち時間に上限はない。受け口が戻らなければ、外部からのcloseも戻らない。
 * 閉鎖の通知は受信・時計・join作業が終了したあと、専用スレッドから理由だけを1回渡す。呼び出し元のcloseでも通知する。
 * 通知が例外を投げたときはcallbackFailuresに数える。通知が戻らなければ外のcloseも戻らない。
 * 受信・時計・join作業・閉鎖通知スレッドからのcloseは停止を要求するだけで、ほかのスレッドを待たない。
 */
public final class UdpEndpoint implements AutoCloseable {
    public enum CloseReason { RUNNING,CLOSED_BY_CALLER,LOCAL_CERTIFICATE_INVALID,RECEIVE_FAILURE,CLOCK_FAILURE,JOIN_FAILURE,LOCAL_CERTIFICATE_EXPIRED,RANDOM_FAILURE,INTERNAL_FAILURE }
    public static final Duration DEFAULT_INTERVAL=Duration.ofMillis(250);
    public interface Receiver {
        void receive(byte[] peerId,byte[] plaintext);
        /** sessionIdとplaintextは呼び出し中だけ有効。残す場合は写しを作る。 */
        default void receive(byte[] peerId,byte[] sessionId,byte[] plaintext){receive(peerId,plaintext);}
    }
    @FunctionalInterface public interface MaterialsProvider { JoinMaterials get(); }
    @FunctionalInterface public interface JoinedFactory { SessionManager create(JoinHandshake.Joined joined); }
    public interface InvitationRegistration extends AutoCloseable {
        AdminJoined lastJoined();
        @Override void close();
    }
    /** 引数の秘密の配列とMaterialsの所有を渡す。providerの元の鍵は別に持つこと。 */
    public static final class JoinMaterials implements AutoCloseable {
        private final byte[] handshakeSecret,administratorSecret;
        private final JoinHandshake.Materials materials;
        public JoinMaterials(byte[] handshakeSecret,byte[] administratorSecret,JoinHandshake.Materials materials) {
            this.handshakeSecret=handshakeSecret;this.administratorSecret=administratorSecret;
            this.materials=materials;
            try { Crypto.length(handshakeSecret,32);Crypto.length(administratorSecret,32);Objects.requireNonNull(materials); }
            catch(RuntimeException e) { close();throw e; }
        }
        byte[] handshakeSecret() { return handshakeSecret; }
        byte[] administratorSecret() { return administratorSecret; }
        JoinHandshake.Materials materials() { return materials; }
        @Override public void close() { Crypto.wipe(handshakeSecret);Crypto.wipe(administratorSecret);if(materials!=null)materials.close(); }
        @Override public String toString() { return "JoinMaterials"; }
    }
    /** 公開の発行結果。秘密鍵・グループの鍵は含まない。 */
    public static final class AdminJoined {
        private final AdminRecords.Record certificate;
        private final InetSocketAddress address;
        AdminJoined(AdminRecords.Record certificate,InetSocketAddress address) { this.certificate=AdminRecords.decode(certificate.encode());this.address=EndpointAddress.normalize(address); }
        public AdminRecords.Record certificate() { return AdminRecords.decode(certificate.encode()); }
        public byte[] identityKey() { return certificate.field(0); }
        public byte[] handshakeKey() { return certificate.field(1); }
        public InetSocketAddress address() { return address; }
        @Override public String toString() { return "AdminJoined"; }
    }
    /** receive は UDP データグラム全体を返す。切り詰めたものを返してはならない。 */
    public interface DatagramIo extends AutoCloseable {
        Datagram receive() throws IOException;
        void send(byte[] wire,InetSocketAddress target) throws IOException;
        @Override void close();
    }
    public record Datagram(byte[] wire,InetSocketAddress source) {
        @Override public String toString() { return "Datagram"; }
    }
    /** Network.bindSocket 済みの、未接続で bind 済みのソケットも受け取れる。 */
    public static class SocketIo implements DatagramIo {
        private final DatagramSocket socket;
        private final byte[] buffer=new byte[65535];
        public SocketIo(DatagramSocket socket) {
            this.socket=Objects.requireNonNull(socket);
            if(socket.isClosed() || !socket.isBound() || socket.isConnected())
                throw new IllegalArgumentException("未接続で bind 済みのソケットが必要です");
        }
        @Override public Datagram receive() throws IOException {
            // 最大 UDP 長より大きいバッファで受け、1232 の有効な頭だけに切り詰めない。
            DatagramPacket packet=new DatagramPacket(buffer,buffer.length);socket.receive(packet);
            return new Datagram(Arrays.copyOf(buffer,packet.getLength()),(InetSocketAddress)packet.getSocketAddress());
        }
        @Override public void send(byte[] wire,InetSocketAddress target) throws IOException {
            socket.send(new DatagramPacket(wire,wire.length,target));
        }
        @Override public void close() { socket.close(); }
    }
    private final Object lock=new Object();
    private SessionManager sessions;
    private AdminState admin;
    private JoinHandshake.Joined joinedOwner;
    private final JoinPort joins;
    private final FirstPacketGate firstPackets;
    private final Map<String,CookieAttempt> cookieAttempts=new HashMap<>();
    private static final class CookieAttempt {
        final byte[] first,hash;final InetSocketAddress address;boolean proved;
        CookieAttempt(byte[] first,InetSocketAddress address) { this.first=first.clone();hash=Crypto.blake2s(first);this.address=address; }
        void clear() { Crypto.wipe(first);Crypto.wipe(hash); }
    }
    private final DatagramIo io;
    private final Receiver receiver;
    private final Map<String,InetSocketAddress> addresses=new HashMap<>();
    private byte[] pinnedHandshake;
    private InetSocketAddress pinnedAddress;
    /** 同じグループの DHT で出会った（登録のない）相手の 1 通目の送り元を許す条件。null なら許さない。ロックの中で呼ぶ。 */
    private Predicate<InetSocketAddress> discoveredPolicy;
    /** addresses のうち、1 通目で揮発の相手として入った相手の鍵。保存した相手・予約した相手は入れない。 */
    private final Set<String> volatileKeys=new HashSet<>();
    /**
     * 発見で見つけた、まだ検査が通っていない宛先（核 C1 必修 3）。addresses・knownPeers には出さない。
     * 2 通目の検査が全部通ったときだけ addresses へ移す。
     */
    private final Map<String,InetSocketAddress> unconfirmed=new HashMap<>();
    private Consumer<byte[]> volatileForgotten;
    private final ScheduledExecutorService timer;
    private final ExecutorService notifications;
    private final Consumer<CloseReason> closedListener;
    private volatile Thread clockThread,notificationThread;
    private final Thread receiving;
    private final AtomicLong rejected=new AtomicLong(),sendFailures=new AtomicLong(),callbackFailures=new AtomicLong();
    /** 定期処理が 1 回終わるたびに増える。試験が「少なくとも N 回まわった」まで待つための数（動作には使わない）。 */
    private final AtomicLong completedTicks=new AtomicLong();
    long completedTicks() { return completedTicks.get(); }
    private volatile boolean closed;
    private volatile CloseReason closeReason=CloseReason.RUNNING;

    public UdpEndpoint(SessionManager sessions,AdminState admin,DatagramSocket socket,Receiver receiver) {
        this(sessions,admin,new SocketIo(socket),receiver,DEFAULT_INTERVAL);
    }
    public UdpEndpoint(SessionManager sessions,AdminState admin,DatagramSocket socket,Receiver receiver,Consumer<CloseReason> closedListener) {
        this(sessions,admin,new SocketIo(socket),receiver,DEFAULT_INTERVAL,closedListener);
    }
    public UdpEndpoint(SessionManager sessions,AdminState admin,DatagramIo io,Receiver receiver,Duration interval) {
        this(Objects.requireNonNull(sessions),Objects.requireNonNull(admin),io,receiver,interval,System::nanoTime);
    }
    public UdpEndpoint(SessionManager sessions,AdminState admin,DatagramIo io,Receiver receiver,Duration interval,Consumer<CloseReason> closedListener) {
        this(Objects.requireNonNull(sessions),Objects.requireNonNull(admin),io,receiver,interval,System::nanoTime,closedListener);
    }
    /** 招待から入る前の口。同じソケットのままjoinの結果を設置する。 */
    public UdpEndpoint(DatagramSocket socket,Receiver receiver) {
        this(null,null,new SocketIo(socket),receiver,DEFAULT_INTERVAL,System::nanoTime);
    }
    public UdpEndpoint(DatagramSocket socket,Receiver receiver,Consumer<CloseReason> closedListener) {
        this(null,null,new SocketIo(socket),receiver,DEFAULT_INTERVAL,System::nanoTime,closedListener);
    }
    public UdpEndpoint(DatagramIo io,Receiver receiver,LongSupplier monotonicNanos) {
        this(null,null,io,receiver,DEFAULT_INTERVAL,monotonicNanos);
    }
    public UdpEndpoint(DatagramIo io,Receiver receiver,LongSupplier monotonicNanos,Consumer<CloseReason> closedListener) {
        this(null,null,io,receiver,DEFAULT_INTERVAL,monotonicNanos,closedListener);
    }
    UdpEndpoint(SessionManager sessions,AdminState admin,DatagramIo io,Receiver receiver,Duration interval,LongSupplier monotonicNanos) {
        this(sessions,admin,io,receiver,interval,monotonicNanos,reason->{});
    }
    public UdpEndpoint(SessionManager sessions,AdminState admin,DatagramIo io,Receiver receiver,Duration interval,LongSupplier monotonicNanos,Consumer<CloseReason> closedListener) {
        this.sessions=sessions;this.admin=admin;
        if(sessions!=null)sessions.setStoredMatcher(this::storedPeer);
        this.io=Objects.requireNonNull(io);this.receiver=Objects.requireNonNull(receiver);
        this.closedListener=Objects.requireNonNull(closedListener);
        long nanos=Objects.requireNonNull(interval).toNanos();
        if(nanos<=0) throw new IllegalArgumentException("時計の間隔は正でなければなりません");
        firstPackets=new FirstPacketGate(Objects.requireNonNull(monotonicNanos));
        timer=Executors.newSingleThreadScheduledExecutor(task->{
            Thread thread=new Thread(task,"distributak-udp-clock");thread.setDaemon(true);clockThread=thread;return thread;
        });
        notifications=Executors.newSingleThreadExecutor(task->{
            Thread thread=new Thread(task,"distributak-udp-closed");thread.setDaemon(true);notificationThread=thread;return thread;
        });
        receiving=new Thread(this::receiveLoop,"distributak-udp-receive");receiving.setDaemon(true);
        joins=new JoinPort(this,io,Objects.requireNonNull(monotonicNanos));
        timer.scheduleWithFixedDelay(this::tick,nanos,nanos,TimeUnit.NANOSECONDS);
        receiving.start();
    }
    private static String key(byte[] id) { Crypto.length(id,32);return Hex.toHexString(id); }
    private void open() { if(closed) throw new IllegalStateException("UDP の口は閉じています"); }
    private SessionManager member() { if(sessions==null)throw new IllegalStateException("加入が終わっていません");return sessions; }
    /** adminの所有を渡す。providerと受け口はjoinの作業スレッドでロックの外から呼ぶ。 */
    public InvitationRegistration registerInvitation(JoinHandshake.Admin admin,MaterialsProvider provider,Consumer<AdminJoined> callback) {
        synchronized(lock) { open();member();return joins.register(admin,provider,callback); }
    }
    /**
     * factoryはjoined.stateと同じAdminStateを使い、部分的な失敗では自分の作りかけを消す。
     * futureを返したあとは口がJoinerを所有する。同期的に例外を返したときは、
     * 呼び出し元がJoinerをcloseすること。大きさで拒むときは既に閉じている場合もある。
     * 停止要求と並んで、要求後にもfactory.createが走ることがある。
     * 設置しなかったfactoryの結果とJoinedは、作業スレッドのfinallyで閉じる。
     */
    public Future<AdminRecords.Record> join(Invitation invitation,JoinHandshake.Joiner joiner,JoinedFactory factory) {
        Objects.requireNonNull(invitation);
        if(io instanceof SocketIo socketIo && !EndpointAddress.compatible(socketIo.socket.getLocalAddress(),invitation.adminAddress()))
            throw new IllegalArgumentException("ソケットと招待のアドレス族が違います");
        synchronized(lock) {
            open();if(sessions!=null)throw new IllegalStateException("すでに加入済みです");
            try { return joins.join(invitation,joiner,factory); }
            catch(AddressCookies.ClockFailure e) { stop(CloseReason.CLOCK_FAILURE);throw e; }
        }
    }
    void installJoined(SessionManager sessions,JoinHandshake.Joined joined) {
        synchronized(lock) { open();if(this.sessions!=null)throw new IllegalStateException("加入済みです");this.sessions=sessions;admin=joined.state();joinedOwner=joined;sessions.setStoredMatcher(this::storedPeer);reserveStoredSlot(); }
    }
    void joinRejected() { rejected.incrementAndGet(); }
    void joinCallbackFailure() { callbackFailures.incrementAndGet(); }
    void joinSendFailure() { sendFailures.incrementAndGet(); }
    void failJoining() { synchronized(lock) { if(sessions==null)stop(CloseReason.JOIN_FAILURE); } }
    void joinClockFailure() { synchronized(lock) { stop(CloseReason.CLOCK_FAILURE); } }
    public void setPeerAddress(byte[] id,InetSocketAddress address) {
        Objects.requireNonNull(address);
        if(address.isUnresolved() || address.getPort()==0) throw new IllegalArgumentException("解決済みの相手の番地が必要です");
        synchronized(lock) { open();addresses.put(key(id),EndpointAddress.normalize(address)); }
    }
    public InetSocketAddress peerAddress(byte[] id) { synchronized(lock) { return addresses.get(key(id)); } }
    /** 招待で確かめた鍵と番地を1件だけ予約する。認証済みFIRSTだけが消費する。 */
    public void pinPeerAddress(byte[] handshakePublicKey,InetSocketAddress address) {
        Crypto.length(handshakePublicKey,32);Objects.requireNonNull(address);
        if(address.isUnresolved() || address.getPort()==0) throw new IllegalArgumentException("解決済みの相手の番地が必要です");
        synchronized(lock) {
            open();
            if(pinnedHandshake!=null) throw new IllegalStateException("予約した相手がいます");
            pinnedHandshake=handshakePublicKey.clone();pinnedAddress=EndpointAddress.normalize(address);reserveStoredSlot();
        }
    }
    /** 公開の証明書と登録番地の写し。秘密も未認証の候補も返さない。 */
    public List<AdminJoined> knownPeers() {
        synchronized(lock) {
            if(closed || sessions==null) return List.of();
            try {
                List<AdminJoined> result=new ArrayList<>();
                for(var entry:addresses.entrySet()) {
                    // 揮発の相手は画面にも保存にも出さない。
                    if(volatileKeys.contains(entry.getKey())) continue;
                    var certificate=sessions.knownCertificate(Hex.decode(entry.getKey()));
                    if(certificate!=null) result.add(new AdminJoined(certificate,entry.getValue()));
                }
                return List.copyOf(result);
            } finally { stopIfSessionsClosed(); }
        }
    }
    private void clearPin() { Crypto.wipe(pinnedHandshake);pinnedHandshake=null;pinnedAddress=null;reserveStoredSlot(); }
    /** 保存した相手が登録されている間（期待する証明書・pin）だけ、保存した相手の 1 枠を空けておく。 */
    private void reserveStoredSlot() { if(sessions!=null)sessions.setStoredSlotReserved(expectedPeerCertificate!=null||pinnedHandshake!=null); }
    /** 1 通目で新しく入る相手が、保存した相手（期待する証明書の身元・予約した鍵・登録した番地）か。ロックの中で呼ばれる。 */
    private boolean storedPeer(AdminRecords.Record certificate) {
        if(expectedPeerCertificate!=null&&Crypto.equal(certificate.field(0),expectedPeerCertificate.field(0)))return true;
        if(pinnedHandshake!=null&&Crypto.equal(pinnedHandshake,certificate.field(1)))return true;
        String peer=key(Crypto.blake2s(certificate.field(0)));
        return addresses.containsKey(peer)&&!volatileKeys.contains(peer);
    }
    /** 証明書の拒否など、核の例外はそのまま呼び出し元へ返す。 */
    public void rememberPeer(AdminRecords.Record certificate) {
        synchronized(lock) {
            open();
            try {
                member().rememberPeer(certificate);
                // 先に揮発として入っていた同じ身元の相手は、保存した相手の枠へ移す。
                volatileKeys.remove(key(Crypto.blake2s(certificate.field(0))));
                // 枠が揮発の相手で埋まっていて核が 1 台を手放したときは、その相手の番地と控えを片付けて、plugin に知らせる。
                sweepVolatile();
            } finally { stopIfSessionsClosed(); }
        }
    }
    private AdminRecords.Record expectedPeerCertificate;
    /** pluginの相手の枠。期限切れの証明書を通常のセッションへ登録せず、FIRSTの身元と発行順を絞る。 */
    public void expectPeerCertificate(AdminRecords.Record certificate) {
        synchronized(lock) {open();admin.verifyCertificate(certificate,certificate.field(1),true);expectedPeerCertificate=certificate;reserveStoredSlot();}
    }
    /** 失効が確定した相手の通信状態と番地だけを取り除く。期限切れでは消さない。 */
    public void forgetPeer(byte[] peerId) {
        synchronized(lock) {
            open();
            try {
                var certificate=member().removeRevokedPeer(peerId);
                if(expectedPeerCertificate!=null&&Crypto.equal(peerId,Crypto.blake2s(expectedPeerCertificate.field(0)))){expectedPeerCertificate=null;reserveStoredSlot();}
                String peer=key(peerId);var address=addresses.remove(peer);clearCookieAttempt(peer);volatileKeys.remove(peer);
                if(pinnedHandshake!=null && (certificate!=null && Crypto.equal(pinnedHandshake,certificate.field(1))
                        || certificate==null && address!=null && EndpointAddress.same(pinnedAddress,address)))clearPin();
            } finally { stopIfSessionsClosed(); }
        }
    }
    /** 同じ確立済みセッションに送る更新を発行する。対象外やセッション変更時はnull。 */
    public AdminRecords.Record authenticatedFirstCertificate(byte[] peerId) {
        synchronized(lock){open();return member().authenticatedFirstCertificate(peerId);}
    }
    /** 保存前の検査だけを行い、手元の証明書は差し替えない。 */
    public boolean validateLocalCertificateRenewal(AdminRecords.Record certificate) {
        synchronized(lock) { open();try { return member().validateLocalCertificateRenewal(certificate); } finally { stopIfSessionsClosed(); } }
    }
    /** 保存に成功した証明書を、同じ口のセッションへ反映する。 */
    public void updateLocalCertificate(AdminRecords.Record certificate) {
        synchronized(lock) { open();try { member().updateLocalCertificate(certificate); } finally { stopIfSessionsClosed(); } }
    }
    /** 表示だけに使う、認証前の目安。 */
    public boolean sawNewerKeyVersion() {
        synchronized(lock) { return !closed && sessions!=null && sessions.sawNewerKeyVersion(); }
    }
    /**
     * 同じグループの発見で見つけた宛先（相手の番号・握手の鍵・番地）へ 1 通目を出す。
     * 番地は条件（allowDiscoveredReplies）に合うときだけ使い、同じ番地は同時に 1 件まで。
     * 2 通目の証明書・身元・握手の鍵の検査が全部通るまで、番地は addresses・knownPeers に入れない。
     * 同じ宛先をもう一度呼ぶと同じ 1 通目を送り直す（5 秒未満は IllegalStateException）。例外の文に番地・鍵は出さない。
     */
    public void startDiscovered(byte[] nodeId,byte[] handshakeKey,InetSocketAddress address) {
        Crypto.length(nodeId,32);Crypto.length(handshakeKey,32);
        InetSocketAddress target=EndpointAddress.normalize(Objects.requireNonNull(address));
        synchronized(lock) {
            open();
            try {
                String peer=key(nodeId);
                // 入ったばかりの端末は、招待した相手とつながってから発見を使う（pin が残る間は開始もしない）。
                if(pinnedHandshake!=null) throw new IllegalStateException("予約した相手とつながるまで発見は使えません");
                if(!discoveredAllowed(target)) throw new SecurityException("宛先が条件に合いません");
                InetSocketAddress mine=addresses.containsKey(peer)?addresses.get(peer):unconfirmed.get(peer);
                if(mine!=null&&!EndpointAddress.same(mine,target)) throw new IllegalStateException("宛先が前と違います");
                if(mine==null) {
                    for(var other:addresses.values()) { if(EndpointAddress.same(other,target)) throw new IllegalStateException("その番地は使用中です"); }
                    for(var other:unconfirmed.values()) { if(EndpointAddress.same(other,target)) throw new IllegalStateException("その番地は使用中です"); }
                }
                boolean fresh=!addresses.containsKey(peer)&&!unconfirmed.containsKey(peer);
                if(fresh) unconfirmed.put(peer,target);
                boolean sent;
                try { sent=dispatch(List.of(member().startUnconfirmed(nodeId,handshakeKey))); }
                catch(RuntimeException e) { if(fresh) { unconfirmed.remove(peer);member().dropUnconfirmed(nodeId); }throw e; }
                // 送れなかった（例外は投げない）ときも、新しく置いた宛先を片付ける。残すと再試行が間隔の制限で止まる。
                if(!sent&&fresh) { unconfirmed.remove(peer);member().dropUnconfirmed(nodeId); }
            } finally { sweepVolatile();stopIfSessionsClosed(); }
        }
    }
    /** 発見で始めた宛先が、まだ検査待ちか。成功・失敗・期限切れ・同時開始で負けたあとは false。 */
    public boolean isDiscoveredPending(byte[] nodeId) {
        Crypto.length(nodeId,32);
        synchronized(lock) { return !closed&&unconfirmed.containsKey(key(nodeId)); }
    }
    /** 閉鎖・失効・握手の間隔など、核の例外はそのまま呼び出し元へ返す。 */
    public void start(byte[] id) {
        synchronized(lock) { open();try { dispatch(List.of(member().start(id))); } finally { stopIfSessionsClosed(); } }
    }
    /**
     * false は閉鎖・未知の番地・握手中・送信失敗。平文は預からない。
     * 自分の証明書が無効で核が閉じた場合も false。
     * その他の核の例外はそのまま返す（失効した相手への送信は SecurityException など）。
     */
    public boolean send(byte[] id,byte[] plaintext) {
        synchronized(lock) {
            try {
                if(closed || sessions==null || !addresses.containsKey(key(id))) return false;
                var result=sessions.sendWithStatus(id,plaintext);
                boolean sent=dispatch(result.outbound());return result.plaintextSent() && sent;
            } catch(IllegalStateException e) {
                if(sessions!=null&&sessions.isClosed()) return false;throw e;
            } finally { stopIfSessionsClosed(); }
        }
    }
    public boolean isEstablished(byte[] id) {
        synchronized(lock) { try { return !closed && sessions!=null && sessions.isEstablished(id); } finally { stopIfSessionsClosed(); } }
    }
    public byte[] sessionId(byte[] id) {
        synchronized(lock) { try { return closed||sessions==null?null:sessions.sessionId(id); } finally { stopIfSessionsClosed(); } }
    }
    /** 期待した管理者始動のセッションが今も同じときだけ、既存のFIRSTを始める（答え212）。 */
    public boolean start(byte[] peerId,byte[] expectedSession) {
        Crypto.length(expectedSession,16);
        synchronized(lock) {
            try {
                if(closed||sessions==null||!sessions.isPeerInitiatedSession(peerId,expectedSession))return false;
                start(peerId);return true;
            }finally{stopIfSessionsClosed();}
        }
    }
    public boolean isPeerInitiatedSession(byte[] peerId,byte[] sessionId) {
        synchronized(lock) {
            try{return !closed&&sessions!=null&&sessions.isPeerInitiatedSession(peerId,sessionId);}
            finally{stopIfSessionsClosed();}
        }
    }
    /** 送出まで同じlockを保ち、前のセッションの待ちを新しい鍵へ載せない。 */
    public boolean sendIfSession(byte[] id,byte[] sessionId,byte[] plaintext) {
        Crypto.length(sessionId,16);
        synchronized(lock) {
            byte[] active=null;
            try {
                if(closed||sessions==null)return false;active=sessions.sessionId(id);
                return active!=null&&Crypto.equal(active,sessionId)&&send(id,plaintext);
            }finally{Crypto.wipe(active);stopIfSessionsClosed();}
        }
    }
    /**
     * 端点、sessionsの順にロックし、送出直前に共通の許可を確かめる。
     * <p>
     * Locks the endpoint before sessions and checks shared permission immediately before emission.
     */
    public boolean sendIfSession(byte[] id,byte[] sessionId,byte[] plaintext,CorePersistenceCoordinator.Operation operation){
        synchronized(lock){
            return !closed&&sessions!=null&&sessions.execute(operation,()->sendIfSession(id,sessionId,plaintext));
        }
    }
    /**
     * 通常の自動再接続を、限定復旧で許す握手と分けて判定する。
     * <p>
     * Checks normal automatic reconnection separately from the handshakes allowed during limited recovery.
     */
    public boolean startIfPermitted(byte[] peer,CorePersistenceCoordinator.Operation operation){
        synchronized(lock){
            return !closed&&sessions!=null&&sessions.execute(operation,()->{start(peer);return true;});
        }
    }
    /**
     * 発見による開始も、送信直前に共通の許可を確かめる。
     * <p>
     * Checks shared permission immediately before a discovery handshake is sent.
     */
    public boolean startDiscoveredIfPermitted(byte[] peer,byte[] handshake,InetSocketAddress address){
        synchronized(lock){
            return !closed&&sessions!=null&&sessions.execute(CorePersistenceCoordinator.Operation.RECONNECT,
                    ()->{startDiscovered(peer,handshake,address);return true;});
        }
    }
    /**
     * 管理者始動のセッションを示すFIRSTにも通常の再接続の許可を使う。
     * <p>
     * Uses normal reconnection permission for FIRST on a peer initiated session.
     */
    public boolean startIfPermitted(byte[] peer,byte[] session){
        synchronized(lock){
            return !closed&&sessions!=null&&sessions.execute(CorePersistenceCoordinator.Operation.RECONNECT,()->start(peer,session));
        }
    }
    /**
     * 保存前の更新検査を、端点からセッションの順にロックして行う。
     * <p>
     * Validates renewal before saving while locking the endpoint before the sessions.
     */
    public boolean validateRenewalIfPermitted(AdminRecords.Record certificate){
        return renewalValidationIfPermitted(certificate)==RenewalValidation.UPDATE;
    }
    /**
     * 更新の拒否と、検査済みで更新が不要な場合を分ける。
     * <p>
     * Distinguishes denied renewal from a validated certificate that needs no update.
     */
    public enum RenewalValidation {DENIED,UNCHANGED,UPDATE}
    /**
     * 許可と更新の要否を、同じ端点とセッションのロックで検査する。
     * <p>
     * Checks permission and the need for renewal under the same endpoint and session locks.
     */
    public RenewalValidation renewalValidationIfPermitted(AdminRecords.Record certificate){
        synchronized(lock){
            if(closed||sessions==null)return RenewalValidation.DENIED;
            RenewalValidation[] result={RenewalValidation.DENIED};
            sessions.execute(CorePersistenceCoordinator.Operation.RENEWAL,()->{
                result[0]=validateLocalCertificateRenewal(certificate)?RenewalValidation.UPDATE:RenewalValidation.UNCHANGED;
                return true;
            });
            return result[0];
        }
    }
    /**
     * 保存後にも許可を確かめて証明書を公開する。
     * <p>
     * Checks permission again before publishing a saved certificate.
     */
    public boolean updateRenewalIfPermitted(AdminRecords.Record certificate){
        synchronized(lock){
            return !closed&&sessions!=null&&sessions.execute(CorePersistenceCoordinator.Operation.RENEWAL,
                    ()->{updateLocalCertificate(certificate);return true;});
        }
    }
    public boolean acceptRevocations(AdminRecords.Record record) {
        synchronized(lock) { open();member();synchronized(sessions){
            if(!sessions.permitsAdministration())return false;
            try { return admin.acceptRevocations(record); } finally { refreshAndCheckClosed(); }
        }}
    }
    public boolean acceptAdministrators(AdminRecords.Record record,LongConsumer missingVersion) {
        // 呼び出し元の受け口をロックの外で呼ぶ。
        long[] missing={-1};boolean accepted;
        synchronized(lock) {
            open();member();synchronized(sessions){
                if(!sessions.permitsAdministration())return false;
                try { accepted=admin.acceptAdministrators(record,value->missing[0]=value); }
                finally { refreshAndCheckClosed(); }
            }
        }
        if(missing[0]>=0) missingVersion.accept(missing[0]);return accepted;
    }
    private boolean dispatch(List<SessionManager.Outbound> outbound) {
        boolean success=true;
        for(var item:outbound) {
            InetSocketAddress address=addresses.get(key(item.peerId()));
            if(address==null) address=unconfirmed.get(key(item.peerId()));
            if(closed || address==null) { success=false;continue; }
            byte[] wire=item.packet();
            try {
                if(SessionPacket.decode(wire).kind()==SessionPacket.FIRST) {
                    CookieWire.firstKind(wire);String peerKey=key(item.peerId());
                    if(!cookieAttempts.containsKey(peerKey)&&cookieAttempts.size()>=sessions.maximumPeers()) { success=false;continue; }
                    CookieAttempt old=cookieAttempts.put(peerKey,new CookieAttempt(wire,address));if(old!=null)old.clear();
                }
                io.send(wire,address);
            }
            catch(IOException e) { sendFailures.incrementAndGet();success=false; }
            finally { Crypto.wipe(wire); }
        }
        return success;
    }
    private void tick() {
        synchronized(lock) {
            if(closed) return;
            try { firstPackets.refresh();if(sessions!=null){dispatch(sessions.poll());sweepVolatile();} } // poll の先頭で refresh も行う。
            catch(RandomFailure e) { stop(CloseReason.RANDOM_FAILURE); }
            catch(RuntimeException e) { stopIfSessionsClosed();stop(CloseReason.CLOCK_FAILURE); }
            finally { stopIfSessionsClosed();completedTicks.incrementAndGet(); }
        }
    }
    private void receiveLoop() {
        try {
            while(!closed) {
                Datagram datagram=io.receive();byte[] plaintext=null,peer=null,inner=null,sessionId=null;
                try {
                    if(datagram.wire()==null||datagram.wire().length>1232)throw new IllegalArgumentException("パケットの長さが違います");
                    InetSocketAddress source=EndpointAddress.normalize(datagram.source());
                    byte[] wire=datagram.wire();
                    if(CookieWire.isCookie(wire)) {
                        try(var frame=CookieWire.decode(wire)) {
                            if(frame.kind()==CookieWire.CHALLENGE) {
                                if(!joins.answerChallenge(frame,source)&&!answerMemberChallenge(frame,source))rejected.incrementAndGet();
                                continue;
                            }
                            if(CookieWire.firstKind(frame.first())==2&&!joins.acceptsCookieRequest(frame.first()))throw new SecurityException("招待が開いていません");
                            if(!firstPackets.accept(frame.cookie(),frame.first(),source))throw new SecurityException("1通目を受けられません");
                            inner=frame.first().clone();wire=inner;
                        }
                    } else {
                        boolean first;
                        if(JoinWire.isJoin(wire)) {
                            try(var frame=JoinWire.decode(wire)) { first=frame.kind()==JoinWire.REQUEST; }
                            if(first&&!joins.acceptsCookieRequest(wire))throw new SecurityException("招待が開いていません");
                        } else first=SessionPacket.decode(wire).kind()==SessionPacket.FIRST;
                        if(first) {
                            byte[] challenge=firstPackets.challenge(wire,source);
                            try { if(challenge!=null)io.send(challenge,source); }
                            catch(IOException e) { sendFailures.incrementAndGet(); }
                            finally { Crypto.wipe(challenge); }
                            if(challenge==null)rejected.incrementAndGet();continue;
                        }
                    }
                    if(JoinWire.isJoin(wire)) { joins.receive(wire,source);continue; }
                    synchronized(lock) {
                        if(closed) return;
                        try {
                            // 大きさと DTK の構文を暗号の検査より先に確かめる。
                            var packet=SessionPacket.decode(wire);
                            try(var result=member().receive(wire,certificate->checkFirstPeer(certificate,source))){
                            peer=result.peerId();
                            String peerKey=key(peer);
                            if(packet.kind()==SessionPacket.FIRST && !addresses.containsKey(peerKey)) {
                                if(pinnedHandshake!=null) {
                                    if(EndpointAddress.same(pinnedAddress,source)) {
                                        var certificate=sessions.knownCertificate(peer);
                                        if(certificate!=null && Crypto.equal(pinnedHandshake,certificate.field(1))) {
                                            addresses.put(peerKey,source);clearPin();
                                        }
                                    }
                                } else if(sessions.isUnregistered(peer)) {
                                    // 検査を全部通った、揮発の相手の番地だけをここで覚える。
                                    addresses.put(peerKey,source);volatileKeys.add(peerKey);
                                }
                            } else if(packet.kind()==SessionPacket.FIRST && volatileKeys.contains(peerKey)
                                    && !EndpointAddress.same(addresses.get(peerKey),source)
                                    && discoveredAllowed(source) && !addressUsedByOther(peerKey,source)) {
                                // 揮発の相手が同じサブネットの別の番地から出し直した。クッキーの PROOF と
                                // 全部の検査（member().receive）が通ったあとなので、返事の届く新しい番地へ直す。
                                // 番地の重なりは checkFirstPeer が先に断っている。保存した相手・pin の相手は変えない。
                                addresses.put(peerKey,source);
                            }
                            if(packet.kind()==SessionPacket.SECOND) {
                                clearCookieAttempt(peerKey);
                                // 検査が全部通ったときだけ、未確認の宛先を相手の番地として覚える。
                                InetSocketAddress found=unconfirmed.get(peerKey);
                                if(found!=null&&sessions.hasPeer(peer)&&!sessions.hasUnconfirmed(peer)&&!addresses.containsKey(peerKey)) {
                                    unconfirmed.remove(peerKey);
                                    if(pinnedHandshake!=null) {
                                        // pin を付ける前に始めた握手は、pin が残る間は入れない。つながった分も片付ける。
                                        if(sessions.isUnregistered(peer)) member().forgetVolatile(peer);
                                    } else {
                                        addresses.put(peerKey,found);
                                        if(sessions.isUnregistered(peer)) volatileKeys.add(peerKey);
                                    }
                                }
                            }
                            // DATA は認証と番号の窓を通ったときだけ返る。重なった SECOND は
                            // 確認の送り直しにも使うので、番地の変更には使わない。
                            if(packet.kind()==SessionPacket.DATA && addresses.containsKey(peerKey)) {
                                // 揮発の相手の番地は、自分のサブネットの中にしか動かさない。条件外の番地からの DATA は、
                                // 復号して番号の窓を進めたあとに捨てる（平文は result の中だけにあり、上へ渡さない）。
                                if(volatileKeys.contains(peerKey) && !discoveredAllowed(source)) {
                                    throw new SecurityException("発見で出会った相手の送り元が条件に合いません");
                                }
                                addresses.put(peerKey,source);
                            }
                            dispatch(result.outbound());plaintext=result.plaintext();sessionId=result.sessionId();
                            }
                        } finally { sweepVolatile();stopIfSessionsClosed(); }
                    }
                } catch(RandomFailure e) {
                    synchronized(lock) { stop(CloseReason.RANDOM_FAILURE); }
                    return;
                } catch(AddressCookies.ClockFailure e) {
                    synchronized(lock) { stop(CloseReason.CLOCK_FAILURE); }
                    return;
                } catch(SecurityException | IllegalArgumentException | IllegalStateException e) {
                    rejected.incrementAndGet();continue;
                } finally {
                    Crypto.wipe(datagram.wire());Crypto.wipe(inner);
                }
                if(plaintext!=null) {
                    try { if(!closed) receiver.receive(peer,sessionId,plaintext); }
                    catch(RuntimeException e) { callbackFailures.incrementAndGet(); }
                    finally { Crypto.wipe(plaintext);Crypto.wipe(sessionId); }
                }
            }
        } catch(IOException | RuntimeException e) {
            // 受信口の故障は繰り返さず閉じる。例外やパケットの内容は外へ出さない。
        } finally { synchronized(lock) { stop(CloseReason.RECEIVE_FAILURE); } }
    }
    private void clearCookieAttempt(String key) { CookieAttempt old=cookieAttempts.remove(key);if(old!=null)old.clear(); }
    private boolean answerMemberChallenge(CookieWire.Frame challenge,InetSocketAddress source) {
        synchronized(lock) {
            if(closed||sessions==null)return false;
            var iterator=cookieAttempts.entrySet().iterator();
            while(iterator.hasNext()) {
                var attempt=iterator.next().getValue();
                // 無関係なCHALLENGEでは核のrefreshも呼ばない。
                if(attempt.proved||!EndpointAddress.same(attempt.address,source)||!Crypto.equal(attempt.hash,challenge.hash()))continue;
                try {
                    if(!sessions.awaitsFirst(attempt.first)) { attempt.clear();iterator.remove();return false; }
                    attempt.proved=true;byte[] proof=CookieWire.proof(challenge.cookie(),attempt.first);
                    try { io.send(proof,source); }catch(IOException e){sendFailures.incrementAndGet();}finally{Crypto.wipe(proof);}
                    return true;
                } finally { stopIfSessionsClosed(); }
            }
            stopIfSessionsClosed();return false;
        }
    }
    /**
     * 受け入れの判定（1 か所）。保存した相手には今までの検査をそのまま行い、
     * 身元が同じときだけ発行の順と中身を比べる。予約が残っている間は、予約と違う相手を全部断る。
     * どれでもない相手は、同じグループの発見で出会った揮発の相手として方針で判定する。
     * 例外の文に番地・鍵を出さない。1 通目の時刻の記録や相手の表を変える前に呼ばれる。
     */
    private void checkFirstPeer(AdminRecords.Record certificate,InetSocketAddress source) {
        boolean sameIdentity=expectedPeerCertificate!=null&&Crypto.equal(certificate.field(0),expectedPeerCertificate.field(0));
        if(sameIdentity&&(certificate.issuedAt()<expectedPeerCertificate.issuedAt()
                ||certificate.issuedAt()==expectedPeerCertificate.issuedAt()&&!Arrays.equals(certificate.signedBytes(),expectedPeerCertificate.signedBytes())))
            throw new SecurityException("保存した相手の身元か発行順が違います");
        // 予約と違う正しいメンバーで、予約した1枠を埋められないようにする。
        byte[] id=Crypto.blake2s(certificate.field(0));String peer=key(id);
        if(pinnedHandshake!=null && !addresses.containsKey(peer)
                && (!EndpointAddress.same(pinnedAddress,source) || !Crypto.equal(pinnedHandshake,certificate.field(1))))
            throw new SecurityException("予約した相手と違います");
        boolean registered=sameIdentity
                || pinnedHandshake!=null&&Crypto.equal(pinnedHandshake,certificate.field(1))
                || addresses.containsKey(peer)&&!volatileKeys.contains(peer)
                || sessions.hasPeer(id)&&!sessions.isUnregistered(id);
        if(registered) return;
        if(!discoveredAllowed(source)) throw new SecurityException("登録のない相手の送り元が条件に合いません");
        // 自分の項目は除く。すでに表にいる揮発の相手が別の番地から来たときも、重なりを見る。
        if(addressUsedByOther(peer,source)) throw new SecurityException("その番地は別の相手が使っています");
    }
    /** その番地を、peer 以外の相手が addresses か unconfirmed で使っているか。 */
    private boolean addressUsedByOther(String peer,InetSocketAddress source) {
        for(var entry:addresses.entrySet()) {
            if(!entry.getKey().equals(peer)&&EndpointAddress.same(entry.getValue(),source)) return true;
        }
        for(var entry:unconfirmed.entrySet()) {
            if(!entry.getKey().equals(peer)&&EndpointAddress.same(entry.getValue(),source)) return true;
        }
        return false;
    }
    private boolean discoveredAllowed(InetSocketAddress source) {
        Predicate<InetSocketAddress> policy=discoveredPolicy;
        if(policy==null) return false;
        try { return policy.test(source); } catch(RuntimeException e) { return false; }
    }
    /**
     * 登録のない相手の 1 通目を受けるときの、送り元の条件（同じサブネットなど）を設定する。null は「受けない」（既定）。
     * 条件は受信スレッドからロックの中で呼ばれるので、待たずに返すこと。例外を投げた場合は「許さない」として扱う。
     */
    public void allowDiscoveredReplies(Predicate<InetSocketAddress> policy) {
        synchronized(lock) { open();discoveredPolicy=policy; }
    }
    /** 揮発の相手を片付けたとき、相手の番号を渡す。ロックの中で呼ばれるので短く。例外は callbackFailures に数える。 */
    public void onVolatilePeerForgotten(Consumer<byte[]> listener) {
        synchronized(lock) { open();volatileForgotten=listener; }
    }
    /** 揮発の相手を 1 台消す。保存した相手・知らない相手は false。1 通目の時刻の記録は消さない。 */
    public boolean forgetVolatilePeer(byte[] peerId) {
        synchronized(lock) {
            open();
            try { boolean removed=member().forgetVolatile(peerId);sweepVolatile();return removed; }
            finally { stopIfSessionsClosed(); }
        }
    }
    /** ネットワークが変わったとき。揮発の相手を全部消す。保存した相手は残す。 */
    public void networkChanged() {
        synchronized(lock) {
            open();
            try { member().forgetAllVolatile();sweepVolatile(); }
            finally { stopIfSessionsClosed(); }
        }
    }
    /** 相手の表から消えた揮発の相手の番地・1通目の控えを片付け、保存した相手へ移った相手は印だけ外す。 */
    private void sweepVolatile() {
        sweepUnconfirmed();
        if(sessions==null||volatileKeys.isEmpty()) return;
        for(var iterator=volatileKeys.iterator();iterator.hasNext();) {
            String peer=iterator.next();byte[] id=Hex.decode(peer);
            boolean present=sessions.hasPeer(id);
            if(present&&sessions.isUnregistered(id)) continue;
            iterator.remove();
            if(present) continue;
            addresses.remove(peer);clearCookieAttempt(peer);
            Consumer<byte[]> listener=volatileForgotten;
            if(listener!=null) {
                try { listener.accept(id); } catch(RuntimeException e) { callbackFailures.incrementAndGet(); }
            }
        }
    }
    /**
     * 核が候補を消した（検査の失敗・期限切れ・ネットワーク変更・同時開始で負け）宛先の番地と 1 通目の控えを片付ける。
     * 既に表に入った相手の番地を持つ宛先は、握手の続きの間だけ残す。
     */
    private void sweepUnconfirmed() {
        if(sessions==null||unconfirmed.isEmpty()) return;
        for(var iterator=unconfirmed.entrySet().iterator();iterator.hasNext();) {
            String peer=iterator.next().getKey();byte[] id=Hex.decode(peer);
            boolean keep=sessions.hasUnconfirmed(id)
                    ||sessions.hasPeer(id)&&!addresses.containsKey(peer)&&sessions.isHandshaking(id);
            if(keep) continue;
            iterator.remove();clearCookieAttempt(peer);
        }
    }
    public long rejectedPackets() { return rejected.get(); }
    public long sendFailures() { return sendFailures.get(); }
    public long callbackFailures() { return callbackFailures.get(); }
    private void refreshAndCheckClosed() {
        try { sessions.refresh();sweepVolatile(); } finally { stopIfSessionsClosed(); }
    }
    private void stopIfSessionsClosed() { if(sessions!=null&&sessions.isClosed()) stop(sessions.closeReason()); }
    /** 最初の閉鎖理由を返す。例外の本文や秘密の値は返さない。 */
    public CloseReason closeReason() { return closeReason; }
    private void stop(CloseReason reason) {
        if(closed) return;closeReason=reason;closed=true;
        timer.shutdownNow();
        try { io.close(); } finally {
            try {
                firstPackets.close();clearPin();for(var attempt:cookieAttempts.values())attempt.clear();cookieAttempts.clear();volatileKeys.clear();unconfirmed.clear();
                joins.stop();if(sessions!=null)sessions.close();if(joinedOwner!=null)joinedOwner.close();addresses.clear();
            } finally {
                notifications.execute(()->{
                    awaitWorkers();
                    try { closedListener.accept(reason); }
                    catch(RuntimeException e) { callbackFailures.incrementAndGet(); }
                });
                notifications.shutdown();
            }
        }
    }
    public boolean isTerminated() { return closed && !receiving.isAlive() && timer.isTerminated() && joins.terminated() && notifications.isTerminated(); }
    boolean isInternalThread() { return Thread.currentThread()==receiving || Thread.currentThread()==clockThread || Thread.currentThread()==notificationThread || joins.isWorkerThread(); }
    @Override public void close() {
        synchronized(lock) { stop(CloseReason.CLOSED_BY_CALLER); }
        // 通知同士から同時に閉じても、受信とjoinのスレッドが互いを待たない。
        if(isInternalThread())return;
        awaitWorkers();
        boolean interrupted=false;
        while(!notifications.isTerminated()) {
            try { notifications.awaitTermination(1,TimeUnit.SECONDS); } catch(InterruptedException e) { interrupted=true; }
        }
        if(interrupted) Thread.currentThread().interrupt();
    }
    private void awaitWorkers() {
        boolean interrupted=false;
        if(Thread.currentThread()!=receiving) {
            while(receiving.isAlive()) {
                try { receiving.join(); } catch(InterruptedException e) { interrupted=true; }
            }
        }
        while(!timer.isTerminated()) {
            try { timer.awaitTermination(1,TimeUnit.SECONDS); } catch(InterruptedException e) { interrupted=true; }
        }
        joins.await();
        if(interrupted) Thread.currentThread().interrupt();
    }
}
