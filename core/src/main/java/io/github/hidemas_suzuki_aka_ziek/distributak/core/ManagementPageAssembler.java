// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.DhtId;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.dht.TransferResources;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 認証済みの相手とセッション世代に結び付けた有限のページ組立。完成と digest の一致だけを返し、記録は適用しない。
 * 署名・権限の検証は呼び出し側が全体に対して行う（04 §4.5）。
 * <p>
 * Bounded page assembly bound to an authenticated peer and session generation. Returns only completion with a matching digest, without applying records.
 * The caller verifies signatures and authority over the whole object (04 §4.5).
 */
public final class ManagementPageAssembler {
    public static final long PROGRESS_MILLIS=30_000,TOTAL_MILLIS=240_000;
    public static final int MAX_REMEMBERED=8,MAX_RETIRED=64;
    public enum Status {INCOMPLETE,DUPLICATE,COMPLETE,REJECTED,CORRUPT}
    /**
     * 完成した未検証の全体。署名・権限が有効だという意味は持たない。
     * <p>
     * A complete unverified object, without implying valid signatures or authority.
     */
    public static final class Completed implements AutoCloseable {
        private final ManagementPage first;private final byte[] data;private final long began;
        private Completed(Assembly assembly){first=assembly.first;data=assembly.buffer;began=assembly.started;}
        private Completed(ManagementPage first,byte[] data,long began){this.first=first;this.data=data;this.began=began;}
        public ManagementPage.Kind kind(){return first.kind();}
        public byte[] data(){return data.clone();}
        public byte[] group(){return first.group();}
        public byte[] operationId(){return first.operationId();}
        public byte[] objectDigest(){return first.objectDigest();}
        public int totalEntries(){return first.totalEntries();}
        public long began(){return began;}
        @Override public void close(){Crypto.wipe(data);}
        @Override public String toString(){return "Complete unverified management object";}
    }
    /**
     * 既定のackは配送の確認だけ。保存確認モードの完了ackはconfirm後だけ返す。拒否と破損ではnull。
     * <p>
     * Default ACKs confirm delivery only. In persistence-confirmation mode, completion ACKs require confirm; null for rejection and corruption.
     */
    public record Result(Status status,Completed completed,ManagementPageAck ack){
        public Result(Status status,Completed completed){this(status,completed,null);}
    }
    /**
     * 完了記録内だけの名簿ACK再投入情報。本体を保持せず、元の期限を保つ。
     * <p>
     * Roster ACK retry metadata held only in completion records, retaining no body and preserving original deadlines.
     */
    public record RosterAckRetry(byte[] peer,byte[] session,long generation,ManagementPageAck ack,long received,long began){
        public RosterAckRetry(byte[] peer,byte[] session,long generation,ManagementPageAck ack,long received,long began){
            this.peer=peer.clone();this.session=session.clone();this.generation=generation;this.ack=ack;this.received=received;this.began=began;
        }
        @Override public byte[] peer(){return peer.clone();}
        @Override public byte[] session(){return session.clone();}
        @Override public String toString(){return "Roster ACK retry";}
    }
    private static final class Remembered implements AutoCloseable {
        final DhtId peer;final ManagementPage first;final byte[] session;final long generation;
        final byte[][] rosterPages;
        final long began;RosterAckRetry retry;
        byte[] summaryBody;long summaryReceived;
        long at;boolean confirmed;
        Remembered(DhtId peer,Assembly assembly,long now){
            this.peer=peer;first=assembly.first;session=assembly.session.clone();generation=assembly.generation;at=now;began=assembly.started;
            if(first.kind()==ManagementPage.Kind.ROSTER){
                rosterPages=new byte[assembly.have.length][];
                for(int i=0;i<rosterPages.length;i++)if(assembly.have[i])rosterPages[i]=digestAndWipe(Arrays.copyOfRange(assembly.buffer,
                        i*ManagementPage.PAGE_BYTES,Math.min(assembly.buffer.length,(i+1)*ManagementPage.PAGE_BYTES)),Crypto::blake2s);
            }else rosterPages=null;
        }
        void clearRetry(){if(retry!=null){Crypto.wipe(retry.peer);Crypto.wipe(retry.session);retry=null;}}
        void clearSummary(){Crypto.wipe(summaryBody);summaryBody=null;}
        public void close(){clearSummary();clearRetry();Crypto.wipe(session);}
        boolean matches(DhtId peer,ManagementPage page,byte[] session,long generation){
            return this.peer.equals(peer)&&metadata(first,page)&&this.generation==generation&&Arrays.equals(this.session,session);
        }
    }
    private static ManagementPage metadataOnly(ManagementPage page){
        return new ManagementPage(page.kind(),page.operationId(),page.group(),page.objectDigest(),page.totalBytes(),page.pageIndex(),page.pageCount(),
                new byte[Math.min(ManagementPage.PAGE_BYTES,page.totalBytes()-page.pageIndex()*ManagementPage.PAGE_BYTES)],page.totalEntries());
    }
    /**
     * 一時の平文の写しは、照合の計算が失敗しても消す。
     * <p>
     * Wipes a temporary plaintext copy even when digest calculation fails.
     */
    static byte[] digestAndWipe(byte[] copy,java.util.function.Function<byte[],byte[]> digest){
        try{return digest.apply(copy);}finally{Crypto.wipe(copy);}
    }
    private static boolean sameTarget(ManagementPage first,ManagementPage page){
        return first.kind()==page.kind()&&Arrays.equals(first.operationId(),page.operationId())&&Arrays.equals(first.objectDigest(),page.objectDigest());
    }
    private static boolean metadata(ManagementPage first,ManagementPage page){
        return sameTarget(first,page)&&first.totalBytes()==page.totalBytes()&&first.pageCount()==page.pageCount()
                &&first.totalEntries()==page.totalEntries()&&Arrays.equals(first.group(),page.group());
    }
    private static final class Assembly {
        final ManagementPage first;final byte[] session,buffer;final long generation,started;
        final TransferResources.Lease lease;final boolean[] have;
        long progress,lastClock;int received;
        Assembly(ManagementPage first,byte[] session,long generation,long now,TransferResources.Lease lease){
            this.first=metadataOnly(first);this.session=session.clone();this.generation=generation;started=now;progress=now;lastClock=now;this.lease=lease;
            buffer=new byte[first.totalBytes()];have=new boolean[first.pageCount()];
        }
        boolean matches(ManagementPage page,byte[] session,long generation){
            return this.generation==generation&&Arrays.equals(this.session,session)&&first.kind()==page.kind()
                    &&first.totalBytes()==page.totalBytes()&&first.pageCount()==page.pageCount()&&first.totalEntries()==page.totalEntries()
                    &&Arrays.equals(first.group(),page.group())&&Arrays.equals(first.operationId(),page.operationId())
                    &&Arrays.equals(first.objectDigest(),page.objectDigest());
        }
        boolean expired(long now){
            boolean expired=now<lastClock||now-started>=TOTAL_MILLIS||now-progress>=PROGRESS_MILLIS;
            lastClock=now;return expired;
        }
    }
    private final byte[] group;private final Clock clock;private final TransferResources resources;
    private final boolean requireConfirmation;
    private final Map<DhtId,Assembly> assemblies=new LinkedHashMap<>();
    private final java.util.ArrayDeque<Remembered> completed=new java.util.ArrayDeque<>(),retired=new java.util.ArrayDeque<>();
    private long lastClock=Long.MIN_VALUE;
    private static void remember(java.util.ArrayDeque<Remembered> records,DhtId peer,Assembly assembly,long now){
        if(records.size()>=MAX_REMEMBERED)records.removeFirst().close();records.addLast(new Remembered(peer,assembly,now));
    }
    private void rememberRetired(DhtId peer,Assembly assembly,long now){
        rememberRetired(new Remembered(peer,assembly,now));
    }
    private void rememberRetired(Remembered record){
        var peer=record.peer;
        // 相手ごとの最古を先に外し、全体の上限に達したときだけ他の相手の記録も外す。
        // Evict the peer's oldest record first, and evict other peers' records only at the overall limit.
        if(retired.stream().filter(r->r.peer.equals(peer)).count()>=MAX_REMEMBERED){
            var iterator=retired.iterator();
            while(iterator.hasNext()){var old=iterator.next();if(old.peer.equals(peer)){iterator.remove();old.close();break;}}
        }
        if(retired.size()>=MAX_RETIRED)retired.removeFirst().close();
        retired.addLast(record);
    }
    public ManagementPageAssembler(byte[] group,Clock clock,TransferResources resources){
        this(group,clock,resources,false);
    }
    public ManagementPageAssembler(byte[] group,Clock clock,TransferResources resources,boolean requireConfirmation){
        Crypto.length(group,32);this.group=group.clone();this.clock=Objects.requireNonNull(clock);this.resources=Objects.requireNonNull(resources);
        this.requireConfirmation=requireConfirmation;
    }
    /**
     * 認証済みのセッションで受けたページを渡す。途中の結果には全体のバイト列を含めない。
     * <p>
     * Supplies a page received in an authenticated session. Intermediate results never contain object bytes.
     */
    public synchronized Result receive(byte[] peer,byte[] session,long generation,ManagementPage page){
        return receiveAt(peer,session,generation,page,clock.millis());
    }
    /**
     * 保留前の受信時刻を使い、処理の遅れで進捗期限を延ばさない。
     * <p>
     * Uses the original reception time so delayed processing cannot extend the progress deadline.
     */
    public synchronized Result receiveAt(byte[] peer,byte[] session,long generation,ManagementPage page,long receivedAt){
        Crypto.length(peer,32);Crypto.length(session,16);Objects.requireNonNull(page);poll();
        if(!Arrays.equals(group,page.group())||!page.withinKindLimits())return result(Status.REJECTED);
        var key=new DhtId(peer);var assembly=assemblies.get(key);long now=clock.millis();
        if(receivedAt>now||now-receivedAt>=PROGRESS_MILLIS)return result(Status.REJECTED);
        for(var record:completed)if(record.matches(key,page,session,generation)){
            if(record.summaryBody!=null){
                byte[] copy=page.data();
                try{int offset=page.pageIndex()*ManagementPage.PAGE_BYTES;
                    for(int i=0;i<copy.length;i++)if(copy[i]!=record.summaryBody[offset+i])return result(Status.REJECTED);
                }finally{Crypto.wipe(copy);}
                return new Result(Status.COMPLETE,new Completed(record.first,record.summaryBody.clone(),record.began));
            }
            return !requireConfirmation||record.confirmed?acknowledged(Status.DUPLICATE,null,page,true):result(Status.DUPLICATE);
        }
        if(page.kind()==ManagementPage.Kind.ROSTER_SUMMARY&&completed.stream().anyMatch(r->r.peer.equals(key)&&r.summaryBody!=null))
            return result(Status.REJECTED);
        if(retired.stream().anyMatch(r->r.matches(key,page,session,generation)))return result(Status.REJECTED);
        if(assembly!=null&&!assembly.matches(page,session,generation)){
            if(page.pageIndex()!=0||assembly.generation!=generation||!Arrays.equals(assembly.session,session)||sameTarget(assembly.first,page))
                return result(Status.REJECTED);
            rememberRetired(key,assembly,now);remove(key);assembly=null;
        }
        if(assembly==null){
            var lease=resources.acquire(key,page.totalBytes());if(lease==null)return result(Status.REJECTED);
            try{assembly=new Assembly(page,session,generation,receivedAt,lease);assemblies.put(key,assembly);}
            catch(RuntimeException|Error failure){lease.close();throw failure;}
        }
        int index=page.pageIndex(),offset=index*ManagementPage.PAGE_BYTES;byte[] data=page.data();
        try{
            if(assembly.have[index]){
                for(int i=0;i<data.length;i++)if(assembly.buffer[offset+i]!=data[i]){
                    remove(key);return result(Status.CORRUPT);
                }
                // 一致する重複も進捗に数えるが、組立を作った時刻は変えない。
                // Count matching duplicates as progress without changing the assembly creation time.
                assembly.progress=Math.max(assembly.progress,receivedAt);
                return acknowledged(Status.DUPLICATE,null,page,false);
            }
            System.arraycopy(data,0,assembly.buffer,offset,data.length);assembly.have[index]=true;assembly.received++;assembly.progress=Math.max(assembly.progress,receivedAt);
            if(assembly.received!=assembly.have.length)return acknowledged(Status.INCOMPLETE,null,page,false);
            assemblies.remove(key);assembly.lease.close();
            if(!Crypto.equal(ManagementPage.digestOf(assembly.buffer),page.objectDigest())){Crypto.wipe(assembly.buffer);Crypto.wipe(assembly.session);return result(Status.CORRUPT);}
            remember(completed,key,assembly,requireConfirmation?assembly.started:now);
            Crypto.wipe(assembly.session);var object=new Completed(assembly);
            return requireConfirmation?new Result(Status.COMPLETE,object):acknowledged(Status.COMPLETE,object,page,true);
        }finally{Crypto.wipe(data);}
    }
    /**
     * 処理・保存に成功した同じ束縛だけを確定し、元の保持期限は変えない。
     * <p>
     * Confirms only the same binding after successful processing and persistence without changing its original retention deadline.
     */
    public synchronized ManagementPageAck confirm(byte[] peer,byte[] session,long generation,ManagementPage page){
        poll();var key=new DhtId(peer);
        for(var record:completed)if(record.matches(key,page,session,generation)){
            record.confirmed=true;record.clearSummary();return acknowledged(Status.DUPLICATE,null,page,true).ack();
        }
        return null;
    }
    /**
     * 元の期限を検査してから公開し、公開が成功した対象だけを確定する。名簿の保存後公開に使う。
     * <p>
     * Checks original deadlines before publication and confirms only successfully published objects, for post-save roster publication.
     */
    public synchronized ManagementPageAck confirmAfter(byte[] peer,byte[] session,long generation,ManagementPage page,Runnable publish){
        poll();var key=new DhtId(peer);
        for(var record:completed)if(record.matches(key,page,session,generation)){
            publish.run();record.confirmed=true;record.clearSummary();return acknowledged(Status.DUPLICATE,null,page,true).ack();
        }
        return null;
    }
    /**
     * 依存本体を待つ告知を未確定の完了枠へ置き、元の期限を保つ。
     * <p>
     * Holds an announcement awaiting dependencies in its unconfirmed completion slot, preserving original deadlines.
     */
    public synchronized void retryAnnouncement(byte[] peer,byte[] session,long generation,ManagementPage page,byte[] body,long receivedAt){
        if(page.kind()!=ManagementPage.Kind.ANNOUNCEMENT)return;
        retainBody(peer,session,generation,page,body,receivedAt);
    }
    /**
     * 応答の送信待ちが満杯なら、未確定の完了記録にsummary本体を元の期限内だけ保持する。
     * <p>
     * Retains a summary body within original deadlines in its unconfirmed completion record when response sending is full.
     */
    public synchronized void retryRosterSummary(byte[] peer,byte[] session,long generation,ManagementPage page,byte[] body,long receivedAt){
        if(page.kind()!=ManagementPage.Kind.ROSTER_SUMMARY)return;
        retainBody(peer,session,generation,page,body,receivedAt);
    }
    private void retainBody(byte[] peer,byte[] session,long generation,ManagementPage page,byte[] body,long receivedAt){
        if(body==null||body.length!=page.totalBytes()||body.length>RosterMessage.MAX_BYTES)throw new IllegalArgumentException("Invalid summary body");
        poll();var key=new DhtId(peer);
        for(var record:completed)if(!record.confirmed&&record.matches(key,page,session,generation)){
            if(record.summaryBody==null){record.summaryBody=body.clone();record.summaryReceived=receivedAt;}return;
        }
    }
    /**
     * 保留summaryの束縛と権限を呼出側で再検査する。
     * <p>
     * Lets the caller recheck bindings and authority for pending summaries.
     */
    @FunctionalInterface public interface RosterCurrent {boolean test(byte[] peer,byte[] session,long generation);}
    /**
     * 束縛や権限を失った保留本体だけを消し、別対象の組立を変えない。
     * <p>
     * Wipes pending bodies that lost binding or authority without changing other object assemblies.
     */
    public synchronized void pruneRosterSummaryRetries(RosterCurrent current){
        poll();for(var record:new java.util.ArrayList<>(completed))if(record.first.kind()==ManagementPage.Kind.ROSTER_SUMMARY&&record.summaryBody!=null){
            boolean retain=false;
            try{retain=current.test(record.peer.bytes(),record.session.clone(),record.generation);}
            finally{if(!retain)record.clearSummary();}
        }
    }
    /**
     * 所有側のcloseで保留summaryの平文をすべて消す。
     * <p>
     * Wipes all pending summary plaintext on owner close.
     */
    public synchronized void clearRosterSummaryRetries(){for(var record:completed)if(record.first.kind()==ManagementPage.Kind.ROSTER_SUMMARY)record.clearSummary();}
    /**
     * 既存の有限な完了記録だけを調べ、名簿ページの内容まで正確に一致する再送へACKを返す。
     * <p>
     * Looks only in existing bounded completion records and acknowledges roster retransmissions with exactly matching page contents.
     */
    public synchronized ManagementPageAck completedRosterAck(byte[] peer,byte[] session,long generation,ManagementPage page){
        var replay=completedRosterAck(peer,session,generation,page,clock.millis());return replay==null?null:replay.ack();
    }
    /**
     * 再送ACKにも完了記録の元の起点を付け、別対象の到着時刻を使わない。
     * <p>
     * Attaches the completion record's original start to replay ACKs instead of using another target's arrival time.
     */
    public synchronized RosterAckRetry completedRosterAck(byte[] peer,byte[] session,long generation,ManagementPage page,long receivedAt){
        poll();long now=clock.millis();
        if(page.kind()!=ManagementPage.Kind.ROSTER||receivedAt>now||now-receivedAt>=PROGRESS_MILLIS)return null;var key=new DhtId(peer);
        for(var record:completed)if(record.confirmed&&record.matches(key,page,session,generation)
                &&record.rosterPages!=null&&Crypto.equal(record.rosterPages[page.pageIndex()],digestAndWipe(page.data(),Crypto::blake2s)))
            return new RosterAckRetry(peer,session,generation,acknowledged(Status.DUPLICATE,null,page,true).ack(),receivedAt,record.began);
        return null;
    }
    /**
     * キューに入らない名簿完了ACKを既存の8件の記録へ預ける。失効ACKには使わない。
     * <p>
     * Defers an unqueued roster completion ACK into the existing eight records, never for revocation ACKs.
     */
    public synchronized boolean deferRosterAck(byte[] peer,byte[] session,long generation,ManagementPageAck ack,long received,long began){
        poll();if(!ack.complete()||ack.pageIndices().length>4)return false;var key=new DhtId(peer);
        for(var record:completed)if(record.confirmed&&(record.first.kind()==ManagementPage.Kind.ROSTER||record.first.kind()==ManagementPage.Kind.ROSTER_SUMMARY)
                &&record.peer.equals(key)&&record.generation==generation&&Arrays.equals(record.session,session)
                &&Arrays.equals(record.first.group(),ack.group())&&Arrays.equals(record.first.operationId(),ack.operationId())
                &&Arrays.equals(record.first.objectDigest(),ack.objectDigest())){
            if(record.retry==null)record.retry=new RosterAckRetry(peer,session,generation,ack,received,Math.min(began,record.began));
            return true;
        }
        return false;
    }
    /**
     * 元の受信30秒・組立240秒の内側の再投入情報だけを返す。
     * <p>
     * Returns retry metadata only within thirty seconds of reception and 240 seconds of assembly start.
     */
    public synchronized java.util.List<RosterAckRetry> rosterAckRetries(){
        poll();long now=clock.millis();var result=new java.util.ArrayList<RosterAckRetry>();
        for(var record:completed)if(record.retry!=null){var retry=record.retry;
            if(now<retry.received()||now<retry.began()||now-retry.received()>=PROGRESS_MILLIS||now-retry.began()>=TOTAL_MILLIS)record.clearRetry();
            else result.add(retry);
        }
        return java.util.List.copyOf(result);
    }
    /**
     * 再投入できた情報、または束縛を失った情報だけを消す。
     * <p>
     * Removes metadata that was requeued or lost its binding.
     */
    public synchronized void removeRosterAckRetry(RosterAckRetry retry){for(var record:completed)if(record.retry==retry){record.clearRetry();return;}}
    /**
     * 所有側のcloseで再投入情報をすべて捨て、他の管理記録を変えない。
     * <p>
     * Discards all retry metadata on owner close without changing other management records.
     */
    public synchronized void clearRosterAckRetries(){for(var record:completed)record.clearRetry();}
    /**
     * 検証や保存に失敗した未確定の組立完成を、有限の破棄記録へ移す。
     * <p>
     * Moves an unconfirmed completion that failed verification or persistence into bounded retirement records.
     */
    public synchronized void reject(byte[] peer,byte[] session,long generation,ManagementPage page){
        var key=new DhtId(peer);var iterator=completed.iterator();
        while(iterator.hasNext()){
            var record=iterator.next();
            if(!record.confirmed&&record.matches(key,page,session,generation)){
                iterator.remove();record.clearSummary();record.at=clock.millis();rememberRetired(record);return;
            }
        }
    }
    private static void discard(java.util.ArrayDeque<Remembered> records,java.util.function.Predicate<Remembered> predicate){
        records.removeIf(record->{if(!predicate.test(record))return false;record.close();return true;});
    }
    private static Result acknowledged(Status status,Completed completed,ManagementPage page,boolean complete){
        return new Result(status,completed,new ManagementPageAck(page.group(),page.operationId(),page.objectDigest(),new int[]{page.pageIndex()},complete));
    }
    private static Result result(Status status){return new Result(status,null);}
    private void remove(DhtId peer){var assembly=assemblies.remove(peer);if(assembly!=null){assembly.lease.close();Crypto.wipe(assembly.buffer);Crypto.wipe(assembly.session);}}
    public synchronized void poll(){
        long now=clock.millis();boolean rollback=now<lastClock;
        if(now<lastClock){
            // 時計が戻っても完了・破棄の記録を保ち、保持期間を今から数え直す。
            // Preserve completion and retirement records on clock rollback and restart their retention period from now.
            for(var record:completed)record.at=now;
            for(var record:retired)record.at=now;
        }lastClock=now;
        var pending=completed.iterator();
        while(pending.hasNext()){
            var record=pending.next();
            if(record.summaryBody!=null&&(rollback||now<record.summaryReceived||now<record.began
                    ||now-record.summaryReceived>=PROGRESS_MILLIS||now-record.began>=TOTAL_MILLIS)){
                pending.remove();record.clearSummary();record.at=now;rememberRetired(record);
            }
        }
        discard(completed,r->now-r.at>=TOTAL_MILLIS);discard(retired,r->now-r.at>=TOTAL_MILLIS);
        var iterator=assemblies.entrySet().iterator();
        while(iterator.hasNext()){
            var entry=iterator.next();var assembly=entry.getValue();
            if(assembly.expired(now)){
                // 期限で捨てた対象の残りから新しい組立を作り、配送完了と誤認するのを防ぐ。
                // Prevent a fresh assembly from expired target remnants from falsely confirming delivery.
                rememberRetired(entry.getKey(),assembly,now);iterator.remove();assembly.lease.close();Crypto.wipe(assembly.buffer);Crypto.wipe(assembly.session);
            }
        }
    }
    public synchronized void forget(byte[] peer){
        var key=new DhtId(peer);remove(key);discard(completed,r->r.peer.equals(key));discard(retired,r->r.peer.equals(key));
    }
    public synchronized void clear(){for(var assembly:assemblies.values()){assembly.lease.close();Crypto.wipe(assembly.buffer);Crypto.wipe(assembly.session);}assemblies.clear();discard(completed,r->true);discard(retired,r->true);}
    public synchronized int active(){poll();return assemblies.size();}
    @Override public String toString(){return "Management page assembler";}
}
