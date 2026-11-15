// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;

/**
 * 第 12 段: グループの DHT の模擬（PC の上だけ。電波は出さない）。
 * 本物の核（DhtNode・DhtDispatcher・DhtPublisher・DhtResponder・DiscoveryStore）を、仮想の時計と待ち行列でつなぐ。
 * 無線・握手の暗号・LanGroup は模擬の側で代わりをする（握手は「相手に届き、返事が戻ったらセッションができる」だけ）。
 * 結果は件数と統計だけにする。端末の番号・鍵・記録の鍵・座標は結果にも失敗の文にも出さない（ADR 0030 答え 166(5)）。
 *
 * 模擬の約束（利用者の決定。ADR 0030 答え 181〜188。ここでは根拠の番号だけを残す）:
 * ・参加時に知っている 1〜3 台は「保存した相手」。両側が覚え、手放さない。揮発の枠は 127（総数 128 − 1。答え 184 の 6・190 の 1）。
 * ・満杯の端末は握手を受けても誰も追い出さず、返事もしない（答え 186 の 5）。始めた側は核の既定どおり 90 秒で失敗。
 * ・手放すのは手放した側だけが閉じる。閉じた知らせは送らない。相手は枠を持ったまま（核の仕組みが閉じるまで）。
 * ・r19 相当（DHT を持たない端末）は保存した相手の握手にだけ答え、DHT の線は黙って捨てる（答え 158 の 4）。
 */
final class DhtSim {
    private DhtSim(){}

    /**
     * 1 台が持てる相手の総数。製品のプラグイン LanGroup.MAX_PEERS（128）の写し（ADR 0030 答え 192 (3)・(5)・193）。
     * 製品側を変えたらここも合わせる。揮発の枠は総数 − 1（保存した相手が 1 つ以上あるときの値）。
     */
    static final int MAX_PEERS=128;
    static final int VOLATILE_SLOTS=MAX_PEERS-1;
    /** 1 端末に保存した相手として選ばれる数の上限。模擬の仮定（参加の偏りを抑える）。 */
    static final int STORED_CAP=8;
    static final long SEC=1_000_000_000L,MS=1_000_000L;
    static final long START=1_000L*SEC,WALL0=1_700_000_000_000L;
    static final int PORT=50000;
    static final byte[] GROUP=new byte[32];
    static{Arrays.fill(GROUP,(byte)0x5A);}

    record Config(int nodes,long seed,int noDhtPercent,int existingPerNode,int missingPerNode,int lossPermille,int duplicatePermille,
                  int departurePercent,int evilPercent,boolean faultyDelay,boolean expiry,long eventLimit,boolean closeNotify) {
        /** 既定は決定どおり（手放した側だけが閉じる）。closeNotify=true は「閉じたと相手へ知らせる」場合の比較用（製品の仕様ではない）。 */
        Config(int nodes,long seed,int noDhtPercent,int existingPerNode,int missingPerNode,int lossPermille,int duplicatePermille,
               int departurePercent,int evilPercent,boolean faultyDelay,boolean expiry,long eventLimit) {
            this(nodes,seed,noDhtPercent,existingPerNode,missingPerNode,lossPermille,duplicatePermille,departurePercent,evilPercent,
                 faultyDelay,expiry,eventLimit,false);
        }
    }

    static final class Result {
        int nodesJoined;
        long existingLookups,existingFound,missingLookups,missingFound,revokedLookups,badAdopted,queryOverruns,abnormalStops;
        long expiredLookups,expiredStillFound,liveLookups,liveFound;
        int depthP95,depthMax;
        boolean eventLimitHit;
        final Map<String,Long> counts=new LinkedHashMap<>();
    }

    static Result run(Config cfg){return run(cfg,Integer.MAX_VALUE);}

    /** lookupers: 探索を行う端末の数の上限（大きい構成の手動実行で探索の総数を絞るため）。 */
    static Result run(Config cfg,int lookupers){return new Sim(cfg,lookupers).go();}

    /**
     * 探索の終わり方の集計名（答え 191 (4)(6)。数えは模擬の側だけに置き、核には足さない）。
     * 締切・問い合わせ上限は値あり・値なしを分ける。COMPLETE は値ありを従来どおり COMPLETE、値なしを COMPLETE_NOVALUE と数える。
     */
    static String endKey(DhtNode.Stop stop,boolean hasValue) {
        switch(stop) {
            case DEADLINE: return hasValue?"DEADLINE_WITH_VALUE":"DEADLINE_NOVALUE";
            case QUERY_LIMIT: return hasValue?"QUERY_LIMIT_WITH_VALUE":"QUERY_LIMIT_NOVALUE";
            case COMPLETE: return hasValue?"COMPLETE":"COMPLETE_NOVALUE";
            default: return stop.name();
        }
    }

    private enum Kind { EXISTING,MISSING,REVOKED,LIVE,EXPIRED }

    private static final class Sess {
        final byte[] sid;final boolean stored;final AuthenticatedPeer peer;
        Sess(byte[] sid,boolean stored,DhtId id){this.sid=sid;this.stored=stored;this.peer=AuthenticatedPeer.fromVerifiedDhtResponse(new Contact(id));}
    }

    private static final class Track {
        final Kind kind;final DhtId key;final DhtId expectedNode;final long notBefore;
        DhtNode<DiscoveryRecord>.Lookup lookup;DiscoveryLookup verifier;long expectVersion;
        final Map<DhtId,Integer> depth=new HashMap<>();int foundDepth=Integer.MAX_VALUE,maxResponded;
        long startedAt;
        Track(Kind kind,DhtId key,DhtId expectedNode,long notBefore){this.kind=kind;this.key=key;this.expectedNode=expectedNode;this.notBefore=notBefore;}
    }

    private static final class Ev implements Comparable<Ev> {
        final long at,seq;final Runnable run;
        Ev(long at,long seq,Runnable run){this.at=at;this.seq=seq;this.run=run;}
        @Override public int compareTo(Ev o){return at!=o.at?Long.compare(at,o.at):Long.compare(seq,o.seq);}
    }

    private static final class Sim {
        final Config cfg;final int lookuperLimit;final Random rng;
        /** 端末の「DHT 対応・悪意」の割り当て用。振る舞いで共有の乱数の進み方が変わっても、母集団は変わらない。 */
        final Random popRng;
        /** 参加の相手選び用。同じ理由で別にしている。 */
        final Random joinRng;
        long now=START,seq,events;boolean limitHit,faultsOn,finished;
        final PriorityQueue<Ev> queue=new PriorityQueue<>();
        final Clock clock=new Clock() {
            @Override public ZoneId getZone(){return ZoneId.of("UTC");}
            @Override public Clock withZone(ZoneId zone){return this;}
            @Override public long millis(){return WALL0+(now-START)/MS;}
            @Override public Instant instant(){return Instant.ofEpochMilli(millis());}
        };
        final List<SimNode> all=new ArrayList<>();
        final Map<DhtId,SimNode> byId=new HashMap<>();
        final Set<DhtId> revoked=new HashSet<>();
        final Map<String,Long> counts=new LinkedHashMap<>();
        final Result result=new Result();
        final int[] depthHist=new int[64];
        int joined,reportsLeft,tracksTotal,tracksDone,evilCounter;
        long l0,tPub,gapNanos;
        boolean lookupPhaseStarted;
        SimNode revokedNode;

        Sim(Config cfg,int lookupers){this.cfg=cfg;this.lookuperLimit=lookupers;this.rng=new Random(cfg.seed());this.popRng=new Random(cfg.seed()*0x9E3779B97F4A7C15L+1);this.joinRng=new Random(cfg.seed()*0xC2B2AE3D27D4EB4FL+2);}

        // ---- 小道具 ----
        void c(String name){counts.merge(name,1L,Long::sum);}
        void c(String name,long v){counts.merge(name,v,Long::sum);}
        void max(String name,long v){counts.merge(name,v,Math::max);}
        void at(long when,Runnable r){queue.add(new Ev(Math.max(when,now),seq++,r));}
        long delay() {
            long d=20*MS+(long)(rng.nextDouble()*180*MS);
            if(faultsOn&&cfg.faultyDelay()&&rng.nextInt(100)<5){d+=300*MS+(long)(rng.nextDouble()*500*MS);c("packetsDelayed");}
            return d;
        }
        boolean lost(){return faultsOn&&cfg.lossPermille()>0&&rng.nextInt(1000)<cfg.lossPermille();}
        byte[] newSid(){byte[] s=new byte[16];rng.nextBytes(s);return s;}

        // ---- 端末 ----
        static final int A_SENT=1,A_LOST=2,A_ARRIVED=4,A_FULL=8,A_NODHT=16,A_DEPARTED=32,A_ANSWERED=64,A_ANSLOST=128,A_DONE=256,A_SLOT=512;
        static final class AttRec{final DhtCandidates.Attempt attempt;int f;AttRec(DhtCandidates.Attempt a){attempt=a;}}

        /** 試みの終わりの理由を 1 つだけ数える（優先順位つき）。件数だけ。 */
        void finishAttempt(AttRec r) {
            c("att.total");
            int f=r.f;
            if((f&A_DONE)!=0)c("att.completed");
            else if((f&A_SLOT)!=0)c("att.fail.initiatorSlotLost");
            else if((f&A_FULL)!=0)c("att.fail.receiverFullSilent");
            else if((f&A_NODHT)!=0)c("att.fail.receiverNoDht");
            else if((f&A_DEPARTED)!=0)c("att.fail.receiverDeparted");
            else if((f&A_ANSLOST)!=0)c("att.fail.answerLost");
            else if((f&A_SENT)==0)c("att.fail.neverSent");
            else if((f&A_ARRIVED)==0)c("att.fail.allFirstsLost");
            else c("att.fail.other");
        }

        void flagAttempt(SimNode a,SimNode b,int flag) {
            AttRec r=a.att.get(b.id);
            if(r!=null)r.f|=flag;
        }

        final class SimNode implements DhtLink {
            final int index;final byte[] secret,hsKey,ip;final DhtId id;final boolean dht;
            boolean departed,joinedFlag,publishStarted,wakePending,firstReportSeen;
            int evil,volatileOpen,storedCount;
            final Map<DhtId,Sess> sess=new HashMap<>(48);
            DhtNode<DiscoveryRecord> node;DiscoveryStore store;DhtResponder responder;DhtDispatcher disp;DhtPublisher pub;
            long wakeTime,wakeToken,publishAt=Long.MAX_VALUE,bytesSent,version,firstReportAt=Long.MAX_VALUE;
            DiscoveryRecord rec;byte[] recBytes;DhtPublisher.Report lastSeen;
            final ArrayDeque<Track> waiting=new ArrayDeque<>();final List<Track> running=new ArrayList<>(2);
            final Map<DhtId,Track> tracked=new HashMap<>();
            /** 相手ごとの、最後の握手の試みの記録（失敗の理由を試みごとに 1 つに分けて数える）。 */
            final Map<DhtId,AttRec> att=new HashMap<>();
            long sentMsgs,recvMsgs;

            SimNode(int index,boolean dht) {
                this.index=index;this.dht=dht;
                secret=new byte[32];rng.nextBytes(secret);
                hsKey=Crypto.x25519Public(secret);
                id=DhtId.fromIdentityPublicKey(Crypto.ed25519Public(secret));
                int n=index+1;
                ip=new byte[]{10,(byte)(n>>16),(byte)(n>>8),(byte)n};
                if(dht)buildCore();
            }

            void buildCore() {
                DhtTransport transport=new DhtTransport() {
                    @Override public boolean send(Contact destination,Request request){return disp.send(destination,request);}
                    @Override public Readiness prepare(Contact destination){return prepareHook(SimNode.this,destination);}
                    @Override public void firstBusy(Contact destination){disp.firstBusy(destination);}
                };
                node=new DhtNode<>(id,clock,()->now,transport,(key,bytes,clk)->{throw new SecurityException("unused");},
                        (x,y)->Long.compare(x.version(),y.version()));
                store=new DiscoveryStore(GROUP,clock,()->now,revoked::contains);
                responder=new DhtResponder(node,store,()->now);
                disp=new DhtDispatcher(GROUP,node,responder,store,this,
                        peer->{
                            SimNode n=byId.get(peer);
                            return n==null?null:new DhtWire.NodeContact(n.id,n.hsKey,n.ip,PORT);
                        },
                        (peer,kind,data)->c("transferSinkCalls"),()->now,rng,DhtTransfers.Limits.defaults());
                pub=new DhtPublisher(node,disp,store);
                disp.networkChanged(1,new LocalNetwork(ip,8));
            }

            @Override public AuthenticatedPeer authenticated(byte[] peerId,byte[] sessionId) {
                if(departed||peerId.length!=32)return null;
                Sess s=sess.get(new DhtId(peerId));
                return s!=null&&Arrays.equals(s.sid,sessionId)?s.peer:null;
            }
            @Override public boolean send(byte[] peerId,byte[] sessionId,byte[] plaintext){return sendPacket(this,peerId,sessionId,plaintext);}
            @Override public boolean releaseVolatile(byte[] peerId) {
                DhtId peer=new DhtId(peerId);
                Sess s=sess.get(peer);
                if(s==null||s.stored)return false;
                sess.remove(peer);volatileOpen--;
                c("releases");
                SimNode other=byId.get(peer);
                if(other!=null){
                    Sess o=other.sess.get(id);
                    if(o!=null&&Arrays.equals(o.sid,s.sid)){
                        c("releasedPeerKeepsSlot");
                        if(cfg.closeNotify()&&!o.stored)at(now+delay(),()->peerClosed(other,id,s.sid));
                    }
                }
                return true;
            }
            @Override public boolean volatileSlotFree(){return slotFree(this);}

            // ---- 起床 ----
            void wakeAt(long t) {
                if(departed)return;
                if(wakePending&&wakeTime<=t)return;
                wakePending=true;wakeTime=t;final long token=++wakeToken;
                at(t,()->{if(token!=wakeToken)return;wakePending=false;step();});
            }

            void step() {
                if(departed||!dht)return;
                node.poll();disp.poll();pub.poll(now);
                if(recBytes!=null&&now>=publishAt&&pub.publishDue(now)&&node.canStartLookup()){
                    boolean started=pub.publish(recBytes,now);
                    c(publishStarted?"repub.tries":"pub.tries");if(started)c(publishStarted?"repub.started":"pub.started");
                    if(started)publishStarted=true;
                }
                accountReport();
                if(node.canStartLookup()&&node.refreshDue())node.findNode(id);
                runTracks();
                boolean busy=node.activeLookups()>0||disp.pendingCount()>0||pub.active()||!running.isEmpty();
                long next=now+(busy?100*MS:30*SEC);
                if(!waiting.isEmpty()){
                    long nb=waiting.peek().notBefore;
                    if(nb>now)next=Math.min(next,nb);else next=Math.min(next,now+100*MS);
                }
                if(publishAt>now)next=Math.min(next,publishAt);
                wakeAt(next);
            }

            void accountReport() {
                DhtPublisher.Report r=pub.lastReport();
                if(r==null||pub.active()||r==lastSeen)return;
                lastSeen=r;
                c("publishReports");c("publishDestinations",r.destinations());c("publishSent",r.sent());c("publishAcked",r.acked());
                c("publishRefused",r.refused());c("publishExpired",r.expired());
                if(r.selfStored())c("publishSelfStored");
                // 公開の前の FIND_NODE の終わり方と STORE の数（最初の公開 pub.* と、出し直し repub.*）
                String pk=firstReportSeen?"repub.":"pub.";
                c(pk+"reports");c(pk+"stop."+r.lookupStop());c(pk+"destinations",r.destinations());c(pk+"sent",r.sent());c(pk+"acked",r.acked());
                c(pk+"refused",r.refused());c(pk+"expired",r.expired());
                String ps=pk+"by."+r.lookupStop()+".";
                c(ps+"reports");c(ps+"destinations",r.destinations());c(ps+"sent",r.sent());c(ps+"acked",r.acked());c(ps+"expired",r.expired());
                if(!firstReportSeen){firstReportSeen=true;firstReportAt=now;reportsLeft--;if(reportsLeft==0)allPublished();}
            }

            void runTracks() {
                for(int i=running.size()-1;i>=0;i--){
                    Track t=running.get(i);
                    if(t.lookup.done()){running.remove(i);tracked.remove(t.key);finalizeTrack(this,t);}
                }
                while(running.size()<2&&!waiting.isEmpty()&&waiting.peek().notBefore<=now&&node.canStartLookup()){
                    Track t=waiting.poll();
                    t.verifier=store.newLookupVerifier();
                    if(t.kind==Kind.LIVE){SimNode p=byId.get(t.expectedNode);t.expectVersion=p==null?0:p.version;}
                    t.lookup=node.findValue(t.key,t.verifier,t.verifier);
                    t.startedAt=now;
                    tracked.put(t.key,t);running.add(t);c("lookupsStarted");
                }
            }
        }

        /** 比較用（closeNotify）。閉じた知らせが届いた。同じセッションのままなら、こちらも閉じる。 */
        void peerClosed(SimNode x,DhtId from,byte[] sid) {
            if(x.departed)return;
            Sess o=x.sess.get(from);
            if(o==null||o.stored||!Arrays.equals(o.sid,sid))return;
            x.sess.remove(from);x.volatileOpen--;c("closedByNotice");
            if(x.dht)x.disp.volatilePeerForgotten(from.bytes());
            x.wakeAt(now+MS);
        }

        // ---- 握手（模擬の側が代わりをする） ----
        DhtTransport.Readiness prepareHook(SimNode a,Contact dest) {
            DhtId peer=dest.id();
            Optional<DhtCandidates.Attempt> before=a.node.candidates().attemptFor(peer);
            // 件数だけ: UNAVAILABLE の理由を、呼ぶ前の状態から分ける。核には数を足さない。
            DhtCandidates.Start pre=a.node.candidates().check(peer);
            boolean hadSession=a.sess.containsKey(peer);
            DhtTransport.Readiness r=a.disp.prepare(dest);
            if(r==DhtTransport.Readiness.UNAVAILABLE){
                if(hadSession)c("diag.unavail.sessionNoProbe");
                else if(pre==DhtCandidates.Start.REFUSED)c("diag.unavail.refusedNotInTable");
                else c("diag.unavail.other");
            }
            if(r==DhtTransport.Readiness.CONNECTING){
                Optional<DhtCandidates.Attempt> after=a.node.candidates().attemptFor(peer);
                if(after.isPresent()&&(before.isEmpty()||before.get()!=after.get()))startHandshake(a,after.get());
            }
            return r;
        }

        void startHandshake(SimNode a,DhtCandidates.Attempt attempt) {
            SimNode b=byId.get(attempt.candidate().node());
            if(b==null)return;
            c("handshakesStarted");
            AttRec prev=a.att.put(b.id,new AttRec(attempt));
            if(prev!=null)finishAttempt(prev);
            for(int k=0;k<3;k++)at(now+k*10*SEC+k*5*MS,()->handshakeTry(a,b,attempt));
        }

        void handshakeTry(SimNode a,SimNode b,DhtCandidates.Attempt attempt) {
            if(a.departed)return;
            DhtCandidates cands=a.node.candidates();
            Optional<DhtCandidates.Attempt> cur=cands.attemptFor(b.id);
            if(cur.isEmpty()||cur.get()!=attempt||!cands.firstDue(attempt))return;
            cands.firstSent(attempt);
            c("handshakeFirsts");a.bytesSent+=200;
            flagAttempt(a,b,A_SENT);
            if(lost()){c("handshakeFirstLost");flagAttempt(a,b,A_LOST);return;}
            at(now+delay(),()->handshakeArrive(a,b));
        }

        /** 製品の SessionManager.hasVolatileSlot と同じ: 総数 < MAX_PEERS、かつ揮発 < MAX_PEERS − 1。 */
        boolean slotFree(SimNode x){return slotFree(x,null);}

        boolean slotFree(SimNode x,DhtId except){return x.sess.size()<MAX_PEERS&&x.volatileOpen<VOLATILE_SLOTS;}

        void handshakeArrive(SimNode a,SimNode b) {
            c("handshakeArrived");flagAttempt(a,b,A_ARRIVED);
            if(b.departed){c("hsNoAnswerDeparted");flagAttempt(a,b,A_DEPARTED);return;}
            Sess existing=b.sess.get(a.id);
            if(!b.dht&&(existing==null||!existing.stored)){c("hsNoAnswerNoDht");flagAttempt(a,b,A_NODHT);return;}
            if(existing==null&&!slotFree(b)){
                c("hsNoAnswerFull");flagAttempt(a,b,A_FULL);
                return;
            }
            byte[] sid=newSid();
            install(b,a,sid,existing!=null&&existing.stored);
            b.bytesSent+=200;c("handshakeAnswered");flagAttempt(a,b,A_ANSWERED);
            if(lost()){c("handshakeAnswerLost");flagAttempt(a,b,A_ANSLOST);return;}
            at(now+delay(),()->handshakeComplete(a,b,sid));
        }

        void handshakeComplete(SimNode a,SimNode b,byte[] sid) {
            if(a.departed)return;
            Sess ex=a.sess.get(b.id);
            Optional<DhtCandidates.Attempt> cur=a.node.candidates().attemptFor(b.id);
            if(cur.isEmpty())c("answerWithoutAttempt");
            if(ex==null&&!slotFree(a,b.id)){c("initiatorSlotLost");flagAttempt(a,b,A_SLOT);return;}
            install(a,b,sid,ex!=null&&ex.stored);
            c("handshakeCompleted");flagAttempt(a,b,A_DONE);
        }

        /** x の表に y のセッションを入れる（sid が新しい握手の値）。DHT を持つ側には核へ知らせる。 */
        void install(SimNode x,SimNode y,byte[] sid,boolean stored) {
            Sess fresh=new Sess(sid,stored,y.id);
            Sess old=x.sess.put(y.id,fresh);
            if(old==null&&!stored)x.volatileOpen++;
            else if(old!=null&&!old.stored&&stored)x.volatileOpen--;
            max("peakVolatile",x.volatileOpen);max("peakStored",x.storedCount);max("peakTotalPeers",x.sess.size());
            if(!x.joinedFlag){x.joinedFlag=true;joined++;}
            if(x.dht)x.disp.sessionStarted(y.id.bytes(),sid);
            x.wakeAt(now+MS);
        }

        // ---- 配送 ----
        boolean sendPacket(SimNode from,byte[] peerId,byte[] sid,byte[] wire) {
            if(from.departed)return false;
            DhtId to=new DhtId(peerId);
            Sess s=from.sess.get(to);
            if(s==null||!Arrays.equals(s.sid,sid)){c("sendRejectedNoSession");return false;}
            byte[] out=wire;
            if(from.evil!=0){
                out=evilize(from,wire);
                if(out==null){c("evilSwallowed");return true;}
            }
            from.bytesSent+=out.length+84L;c("packetsSent");from.sentMsgs++;
            SimNode dst=byId.get(to);
            if(dst==null)return true;
            if(lost()){c("packetsLost");return true;}
            final byte[] payload=out;
            at(now+delay(),()->deliver(from,dst,sid,payload));
            if(faultsOn&&cfg.duplicatePermille()>0&&rng.nextInt(1000)<cfg.duplicatePermille()){
                c("packetsDuplicated");
                at(now+delay()+(long)(rng.nextDouble()*50*MS),()->deliver(from,dst,sid,payload));
            }
            return true;
        }

        byte[] evilize(SimNode n,byte[] wire) {
            DhtWire.Message m;
            try{m=DhtWire.parse(wire);}catch(RuntimeException malformed){return wire;}
            DhtWire.Op op=m.op();
            switch(n.evil) {
                case 1:
                    if(op==DhtWire.Op.VALUE){byte[] w=wire.clone();w[w.length/2]^=0x55;c("evilTampered");return w;}
                    return wire;
                case 2:
                    if(op==DhtWire.Op.VALUE&&n.recBytes!=null){c("evilWrongKey");return DhtWire.value(GROUP,m.requestId(),m.target(),n.recBytes);}
                    return wire;
                default:
                    if(op==DhtWire.Op.PONG||op==DhtWire.Op.NODES||op==DhtWire.Op.VALUE||op==DhtWire.Op.STORE_RESULT)return null;
                    return wire;
            }
        }

        void deliver(SimNode from,SimNode to,byte[] sid,byte[] wire) {
            if(to.departed){c("pktToDeparted");return;}
            to.recvMsgs++;
            Sess s=to.sess.get(from.id);
            if(s==null||!Arrays.equals(s.sid,sid)){
                c("pktNoSession");
                return;
            }
            if(!to.dht){c("pktSwallowedNoDht");return;}
            c("packetsDelivered");
            if(!to.tracked.isEmpty())trace(to,from,wire);
            to.disp.receive(from.id.bytes(),sid,wire);
            to.wakeAt(now+MS);
        }

        void trace(SimNode to,SimNode from,byte[] wire) {
            DhtWire.Message m;
            try{m=DhtWire.parse(wire);}catch(RuntimeException malformed){return;}
            DhtWire.Op op=m.op();
            if(op!=DhtWire.Op.NODES&&op!=DhtWire.Op.VALUE)return;
            Track t=to.tracked.get(m.target());
            if(t==null)return;
            int d=t.depth.getOrDefault(from.id,1);
            if(op==DhtWire.Op.VALUE){t.foundDepth=Math.min(t.foundDepth,d);return;}
            t.maxResponded=Math.max(t.maxResponded,d);
            for(DhtWire.NodeContact nc:m.contacts())t.depth.putIfAbsent(nc.node(),d+1);
        }

        // ---- 参加 ----
        SimNode newNode(int i) {
            boolean dht=i==0||cfg.noDhtPercent()<=0||popRng.nextInt(100)>=cfg.noDhtPercent();
            SimNode n=new SimNode(i,dht);
            if(dht&&cfg.evilPercent()>0&&i>0&&popRng.nextInt(100)<cfg.evilPercent())n.evil=1+(evilCounter++%3);
            all.add(n);byId.put(n.id,n);
            return n;
        }

        void join(int i) {
            SimNode n=newNode(i);
            if(i==0){n.joinedFlag=true;joined++;return;}
            int want=1+joinRng.nextInt(3);
            List<SimNode> targets=new ArrayList<>(3);
            boolean haveDht=!n.dht;
            for(int draws=0;targets.size()<want&&draws<20;draws++){
                SimNode t=all.get(joinRng.nextInt(all.size()-1));
                if(t.storedCount>=STORED_CAP||targets.contains(t)){c("storedSkips");continue;}
                targets.add(t);if(t.dht)haveDht=true;
            }
            for(int draws=0;!haveDht&&draws<40;draws++){
                SimNode t=all.get(joinRng.nextInt(all.size()-1));
                if(!t.dht||t.storedCount>=STORED_CAP||targets.contains(t))continue;
                targets.add(t);haveDht=true;
            }
            if(targets.isEmpty()){c("joinNoTarget");return;}
            if(!haveDht)c("joinWithoutDhtTarget");
            for(SimNode t:targets){
                t.storedCount++;n.storedCount++;
                at(now+2*delay(),()->makeStored(n,t));
            }
        }

        void makeStored(SimNode a,SimNode b) {
            byte[] sid=newSid();
            install(a,b,sid,true);install(b,a,sid,true);
            c("storedLinks");
        }

        // ---- 段階 ----
        void startPublishPhase() {
            faultsOn=true;
            long p0=now;
            for(SimNode n:all){
                if(!n.dht)continue;
                n.version=1;
                n.rec=DiscoveryRecord.issue(GROUP,n.secret,n.hsKey,n.ip,PORT,n.version,clock.millis());
                n.recBytes=n.rec.encode();
                n.publishAt=p0+(long)(rng.nextDouble()*60*SEC);
                reportsLeft++;
                n.wakeAt(n.publishAt);
            }
            result.counts.put("dhtNodes",(long)reportsLeft);
            at(p0+20*60*SEC,()->{
                if(reportsLeft>0&&!lookupPhaseStarted&&l0==0){c("publishIncomplete",reportsLeft);allPublished();}
            });
        }

        void allPublished() {
            if(l0!=0)return;
            tPub=now;
            if(cfg.expiry()){
                l0=tPub+26*3600*SEC+15*60*SEC;
                for(SimNode n:all)if(n.dht)for(int k=1;k<=26;k++){
                    final SimNode node=n;
                    at(tPub+k*3600*SEC+(long)(rng.nextDouble()*600*SEC),()->reissue(node));
                }
                at(tPub+30*60*SEC,this::departNodes);
            } else {
                l0=now+30*SEC;
            }
            at(l0,this::startLookupPhase);
        }

        void reissue(SimNode n) {
            if(n.departed||n.rec==null)return;
            n.version++;
            n.rec=DiscoveryRecord.issue(GROUP,n.secret,n.hsKey,n.ip,PORT,n.version,clock.millis());
            n.recBytes=n.rec.encode();
            n.pub.recordChanged();
            c("reissues");
            n.wakeAt(now+MS);
        }

        void departNodes() {
            List<SimNode> pool=new ArrayList<>(all);
            pool.remove(revokedNode);
            Collections.shuffle(pool,rng);
            int k=all.size()*cfg.departurePercent()/100;
            for(int i=0;i<k&&i<pool.size();i++)pool.get(i).departed=true;
            c("departures",Math.min(k,pool.size()));
        }

        void startLookupPhase() {
            lookupPhaseStarted=true;
            if(!cfg.expiry()){
                if(cfg.evilPercent()>0){
                    for(SimNode n:all)if(n.dht&&n.evil==0&&n.index>0){revokedNode=n;break;}
                }
                departNodes();
                if(revokedNode!=null){
                    revoked.add(revokedNode.id);
                    for(SimNode n:all)if(n.dht&&!n.departed)n.store.removeRevoked();
                }
            }
            List<SimNode> publishers=new ArrayList<>();
            for(SimNode n:all)if(n.dht&&n.rec!=null&&n!=revokedNode)publishers.add(n);
            List<SimNode> lookupers=new ArrayList<>();
            for(SimNode n:all)if(n.dht&&!n.departed&&n!=revokedNode)lookupers.add(n);
            Collections.shuffle(lookupers,rng);
            if(lookupers.size()>lookuperLimit)lookupers=new ArrayList<>(lookupers.subList(0,lookuperLimit));
            List<SimNode> live=new ArrayList<>(),dead=new ArrayList<>();
            for(SimNode p:publishers)(p.departed?dead:live).add(p);
            for(SimNode n:lookupers){
                long nb=now+(long)(rng.nextDouble()*120*SEC);
                Set<DhtId> used=new HashSet<>();
                if(cfg.expiry()){
                    addTracks(n,live,cfg.existingPerNode(),Kind.LIVE,nb,used);
                    addTracks(n,dead,dead.isEmpty()?0:1,Kind.EXPIRED,nb,used);
                } else {
                    addTracks(n,publishers,cfg.existingPerNode(),Kind.EXISTING,nb,used);
                }
                for(int i=0;i<cfg.missingPerNode();i++){
                    byte[] raw=new byte[32];rng.nextBytes(raw);
                    n.waiting.add(new Track(Kind.MISSING,new DhtId(raw),null,nb));tracksTotal++;
                }
                if(revokedNode!=null){n.waiting.add(new Track(Kind.REVOKED,revokedNode.rec.key(),revokedNode.id,nb));tracksTotal++;}
                n.wakeAt(Math.max(now+MS,nb));
            }
            result.counts.put("lookupers",(long)lookupers.size());
            result.counts.put("tracksTotal",(long)tracksTotal);
            at(now+20*60*SEC,()->{
                if(!finished){c("lookupsUnfinished",tracksTotal-tracksDone);finished=true;}
            });
            if(tracksTotal==0)finished=true;
        }

        void addTracks(SimNode n,List<SimNode> from,int count,Kind kind,long nb,Set<DhtId> used) {
            if(from.isEmpty())return;
            int added=0;
            for(int tries=0;added<count&&tries<count*20+20;tries++){
                SimNode p=from.get(rng.nextInt(from.size()));
                if(p==n||!used.add(p.id))continue;
                n.waiting.add(new Track(kind,p.rec.key(),p.id,nb));tracksTotal++;added++;
            }
        }

        final List<Long> durs=new ArrayList<>();
        // ---- 探索の結果 ----
        void finalizeTrack(SimNode n,Track t) {
            DhtNode.Result<DiscoveryRecord> r=t.lookup.result();
            tracksDone++;c("lookupsDone");
            if(r.queried()>DhtLimits.MAX_QUERIES)result.queryOverruns++;
            switch(r.stop()) {
                case CLOCK_RESET,NETWORK_CHANGED->result.abnormalStops++;
                case QUERY_LIMIT->c("lookupStopQueryLimit");
                case DEADLINE->c("lookupStopDeadline");
                case COMPLETE->c("lookupStopComplete");
            }
            c("lookupQueried",r.queried());c("lookupResponded",r.responded());
            Optional<DiscoveryRecord> v=r.value();
            String endName=endKey(r.stop(),v.isPresent());
            c("end."+endName);if(v.isPresent()){c("lookupsWithValue");c("lookupQueriedWithValue",r.queried());}
            boolean ok=v.isPresent()&&v.get().key().equals(t.key)&&(t.expectedNode==null||v.get().nodeId().equals(t.expectedNode));
            if(t.kind==Kind.EXISTING) {
                // 終わり方の内訳・探索 1 本の時間・古い版を採った数。
                c("ek."+endName);durs.add((now-t.startedAt)/MS);
                SimNode pub=byId.get(t.expectedNode);
                if(v.isPresent()&&pub!=null&&v.get().version()<pub.version)c("ek.staleVersionAdopted");
            }
            switch(t.kind) {
                case EXISTING->{
                    result.existingLookups++;
                    if(ok)result.existingFound++;else if(v.isPresent())result.badAdopted++;
                }
                case LIVE->{
                    result.liveLookups++;
                    if(ok&&v.get().version()>=t.expectVersion)result.liveFound++;
                    else if(v.isPresent()&&!ok)result.badAdopted++;
                    else if(v.isPresent()){c("liveOutdated");SimNode lp=byId.get(t.expectedNode);long lag=lp==null?0:lp.version-v.get().version();c("liveLag."+(lag>=3?"3plus":Long.toString(lag)));}
                }
                case EXPIRED->{
                    result.expiredLookups++;
                    if(v.isPresent())result.expiredStillFound++;
                }
                case MISSING->{
                    result.missingLookups++;
                    if(v.isPresent()){result.missingFound++;result.badAdopted++;}
                }
                case REVOKED->{
                    result.revokedLookups++;
                    if(v.isPresent()){result.badAdopted++;c("revokedAdopted");}
                }
            }
            int d=v.isPresent()&&t.foundDepth!=Integer.MAX_VALUE?t.foundDepth:t.maxResponded;
            depthHist[Math.min(d,depthHist.length-1)]++;
            if(tracksDone==tracksTotal&&lookupPhaseStarted)finished=true;
        }

        /** DHT 対応の端末ごとの、送った・受けたメッセージ数の平均と p95（統計だけ）。 */
        void finishMessages() {
            List<Long> snt=new ArrayList<>(),rcv=new ArrayList<>();
            for(SimNode n:all)if(n.dht){snt.add(n.sentMsgs);rcv.add(n.recvMsgs);}
            if(snt.isEmpty())return;
            Collections.sort(snt);Collections.sort(rcv);
            int k=snt.size();long ss=0,rs=0;for(long v:snt)ss+=v;for(long v:rcv)rs+=v;
            counts.put("msg.sentMean",ss/k);counts.put("msg.sentP95",snt.get(Math.min(k-1,(int)Math.ceil(k*0.95)-1)));
            counts.put("msg.recvMean",rs/k);counts.put("msg.recvP95",rcv.get(Math.min(k-1,(int)Math.ceil(k*0.95)-1)));
            counts.put("msg.dhtNodes",(long)k);
            if(!durs.isEmpty()){
                List<Long> d=new ArrayList<>(durs);Collections.sort(d);int m=d.size();
                counts.put("lookup.n",(long)m);counts.put("lookup.durP50ms",d.get(m/2));
                counts.put("lookup.durP95ms",d.get(Math.min(m-1,(int)Math.ceil(m*0.95)-1)));
            }
        }

        // ---- 実行 ----
        Result go() {
            long gap=cfg.nodes()<=1024?2*SEC:250*MS;gapNanos=gap;
            for(int i=0;i<cfg.nodes();i++){final int idx=i;at(START+i*gap,()->join(idx));}
            long joinEnd=START+(long)cfg.nodes()*gap;
            at(joinEnd+60*SEC,this::startPublishPhase);
            while(!queue.isEmpty()&&!finished){
                Ev e=queue.poll();now=e.at;
                if(++events>cfg.eventLimit()){limitHit=true;break;}
                e.run.run();
            }
            finish();
            return result;
        }

        void finish() {
            result.nodesJoined=joined;result.eventLimitHit=limitHit;
            result.counts.put("events",events);
            result.counts.put("virtualSeconds",(now-START)/SEC);
            long total=0;int sum=0;for(int h:depthHist)sum+=h;
            int acc=0;int p95=0;
            for(int d=0;d<depthHist.length;d++){
                if(depthHist[d]>0)result.depthMax=d;
                acc+=depthHist[d];if(sum>0&&p95==0&&acc*100L>=sum*95L)p95=d;
            }
            result.depthP95=p95;
            long maxBytes=0;int count=0;
            for(SimNode n:all){total+=n.bytesSent;maxBytes=Math.max(maxBytes,n.bytesSent);count++;}
            if(count>0){counts.put("bytesPerNodeMean",total/count);counts.put("bytesPerNodeMax",maxBytes);}
            for(SimNode n:all){
                if(!n.dht)continue;
                DhtDispatcher.Statistics s=n.disp.statistics();
                c("core.busy",s.busy());c("core.nothingReleasable",s.nothingReleasable());c("core.droppedStarted",s.droppedStarted());
                c("core.releasedNotYes",s.releasedNotYes());c("core.releasedOutsideTable",s.releasedOutsideTable());
                c("core.releasedCrowdedBucket",s.releasedCrowdedBucket());c("core.releasedNo",s.releasedNo());
                c("core.busyConcurrent",s.busyConcurrent());c("core.busyWindow",s.busyWindow());
                c("core.busyNothingReleasable",s.busyNothingReleasable());c("core.busyRecent30s",s.busyRecent30s());
                c("core.lookupsQueryLimit",s.lookupsQueryLimit());c("core.lookupsDeadline",s.lookupsDeadline());
                c("core.unavailableFailed",s.unavailableFailed());c("core.connectingTimedOut",s.connectingTimedOut());c("core.connectingReleased",s.connectingReleased());
                c("core.rehandshakeAfterRelease",s.rehandshakeAfterRelease());c("core.probeBudgetBlocked",s.probeBudgetBlocked());
                c("core.received",s.received());c("core.malformed",s.malformed());c("core.unauthenticated",s.unauthenticated());
                c("core.wrongGroup",s.wrongGroup());c("core.unsolicited",s.unsolicited());c("core.mismatched",s.mismatched());
                c("core.expired",s.expired());c("core.stale",s.stale());c("core.probesSent",s.probesSent());
            }
            for(SimNode n:all)for(AttRec r:n.att.values())finishAttempt(r);
            finishMessages();
            result.counts.putAll(counts);
        }
    }
}
