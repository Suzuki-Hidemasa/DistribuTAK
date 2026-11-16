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
    public static final class Completed {
        private final ManagementPage first;private final byte[] data;
        private Completed(Assembly assembly){first=assembly.first;data=assembly.buffer;}
        public ManagementPage.Kind kind(){return first.kind();}
        public byte[] data(){return data.clone();}
        public byte[] group(){return first.group();}
        public byte[] operationId(){return first.operationId();}
        public byte[] objectDigest(){return first.objectDigest();}
        public int totalEntries(){return first.totalEntries();}
        @Override public String toString(){return "Complete unverified management object";}
    }
    /**
     * ackは配送の確認だけで、記録の署名・権限・適用を保証しない。拒否と破損ではnull。
     * <p>
     * The ack confirms delivery only, not signatures, authority or application; null for rejection and corruption.
     */
    public record Result(Status status,Completed completed,ManagementPageAck ack){
        public Result(Status status,Completed completed){this(status,completed,null);}
    }
    private static final class Remembered {
        final DhtId peer;final ManagementPage first;final byte[] session;final long generation;
        long at;
        Remembered(DhtId peer,Assembly assembly,long now){
            this.peer=peer;first=assembly.first;session=assembly.session.clone();generation=assembly.generation;at=now;
        }
        boolean matches(DhtId peer,ManagementPage page,byte[] session,long generation){
            return this.peer.equals(peer)&&metadata(first,page)&&this.generation==generation&&Arrays.equals(this.session,session);
        }
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
            this.first=first;this.session=session.clone();this.generation=generation;started=now;progress=now;lastClock=now;this.lease=lease;
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
    private final Map<DhtId,Assembly> assemblies=new LinkedHashMap<>();
    private final java.util.ArrayDeque<Remembered> completed=new java.util.ArrayDeque<>(),retired=new java.util.ArrayDeque<>();
    private long lastClock=Long.MIN_VALUE;
    private static void remember(java.util.ArrayDeque<Remembered> records,DhtId peer,Assembly assembly,long now){
        if(records.size()>=MAX_REMEMBERED)records.removeFirst();records.addLast(new Remembered(peer,assembly,now));
    }
    private void rememberRetired(DhtId peer,Assembly assembly,long now){
        // 相手ごとの最古を先に外し、全体の上限に達したときだけ他の相手の記録も外す。
        // Evict the peer's oldest record first, and evict other peers' records only at the overall limit.
        if(retired.stream().filter(r->r.peer.equals(peer)).count()>=MAX_REMEMBERED){
            var iterator=retired.iterator();
            while(iterator.hasNext())if(iterator.next().peer.equals(peer)){iterator.remove();break;}
        }
        if(retired.size()>=MAX_RETIRED)retired.removeFirst();
        retired.addLast(new Remembered(peer,assembly,now));
    }
    public ManagementPageAssembler(byte[] group,Clock clock,TransferResources resources){
        Crypto.length(group,32);this.group=group.clone();this.clock=Objects.requireNonNull(clock);this.resources=Objects.requireNonNull(resources);
    }
    /**
     * 認証済みのセッションで受けたページを渡す。途中の結果には全体のバイト列を含めない。
     * <p>
     * Supplies a page received in an authenticated session. Intermediate results never contain object bytes.
     */
    public synchronized Result receive(byte[] peer,byte[] session,long generation,ManagementPage page){
        Crypto.length(peer,32);Crypto.length(session,16);Objects.requireNonNull(page);poll();
        if(!Arrays.equals(group,page.group())||!page.withinKindLimits())return result(Status.REJECTED);
        var key=new DhtId(peer);var assembly=assemblies.get(key);long now=clock.millis();
        if(completed.stream().anyMatch(r->r.matches(key,page,session,generation)))return acknowledged(Status.DUPLICATE,null,page,true);
        if(retired.stream().anyMatch(r->r.matches(key,page,session,generation)))return result(Status.REJECTED);
        if(assembly!=null&&!assembly.matches(page,session,generation)){
            if(page.pageIndex()!=0||assembly.generation!=generation||!Arrays.equals(assembly.session,session)||sameTarget(assembly.first,page))
                return result(Status.REJECTED);
            rememberRetired(key,assembly,now);remove(key);assembly=null;
        }
        if(assembly==null){
            var lease=resources.acquire(key,page.totalBytes());if(lease==null)return result(Status.REJECTED);
            try{assembly=new Assembly(page,session,generation,now,lease);assemblies.put(key,assembly);}
            catch(RuntimeException|Error failure){lease.close();throw failure;}
        }
        int index=page.pageIndex(),offset=index*ManagementPage.PAGE_BYTES;byte[] data=page.data();
        if(assembly.have[index]){
            for(int i=0;i<data.length;i++)if(assembly.buffer[offset+i]!=data[i]){
                remove(key);return result(Status.CORRUPT);
            }
            // 一致する重複も進捗に数えるが、組立を作った時刻は変えない。
            // Count matching duplicates as progress without changing the assembly creation time.
            assembly.progress=now;
            return acknowledged(Status.DUPLICATE,null,page,false);
        }
        System.arraycopy(data,0,assembly.buffer,offset,data.length);assembly.have[index]=true;assembly.received++;assembly.progress=now;
        if(assembly.received!=assembly.have.length)return acknowledged(Status.INCOMPLETE,null,page,false);
        remove(key);
        if(!Crypto.equal(ManagementPage.digestOf(assembly.buffer),page.objectDigest()))return result(Status.CORRUPT);
        remember(completed,key,assembly,now);
        return acknowledged(Status.COMPLETE,new Completed(assembly),page,true);
    }
    private static Result acknowledged(Status status,Completed completed,ManagementPage page,boolean complete){
        return new Result(status,completed,new ManagementPageAck(page.group(),page.operationId(),page.objectDigest(),new int[]{page.pageIndex()},complete));
    }
    private static Result result(Status status){return new Result(status,null);}
    private void remove(DhtId peer){var assembly=assemblies.remove(peer);if(assembly!=null)assembly.lease.close();}
    public synchronized void poll(){
        long now=clock.millis();
        if(now<lastClock){
            // 時計が戻っても完了・破棄の記録を保ち、保持期間を今から数え直す。
            // Preserve completion and retirement records on clock rollback and restart their retention period from now.
            for(var record:completed)record.at=now;
            for(var record:retired)record.at=now;
        }lastClock=now;
        completed.removeIf(r->now-r.at>=TOTAL_MILLIS);retired.removeIf(r->now-r.at>=TOTAL_MILLIS);
        var iterator=assemblies.entrySet().iterator();
        while(iterator.hasNext()){
            var entry=iterator.next();var assembly=entry.getValue();
            if(assembly.expired(now)){
                // 期限で捨てた対象の残りから新しい組立を作り、配送完了と誤認するのを防ぐ。
                // Prevent a fresh assembly from expired target remnants from falsely confirming delivery.
                rememberRetired(entry.getKey(),assembly,now);iterator.remove();assembly.lease.close();
            }
        }
    }
    public synchronized void forget(byte[] peer){
        var key=new DhtId(peer);remove(key);completed.removeIf(r->r.peer.equals(key));retired.removeIf(r->r.peer.equals(key));
    }
    public synchronized void clear(){for(var assembly:assemblies.values())assembly.lease.close();assemblies.clear();completed.clear();retired.clear();}
    public synchronized int active(){poll();return assemblies.size();}
    @Override public String toString(){return "Management page assembler";}
}
