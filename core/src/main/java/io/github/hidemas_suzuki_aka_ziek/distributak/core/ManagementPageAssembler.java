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
    public record Result(Status status,Completed completed){}
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
        if(!Arrays.equals(group,page.group()))return result(Status.REJECTED);
        var key=new DhtId(peer);var assembly=assemblies.get(key);long now=clock.millis();
        if(assembly==null){
            var lease=resources.acquire(key,page.totalBytes());if(lease==null)return result(Status.REJECTED);
            try{assembly=new Assembly(page,session,generation,now,lease);assemblies.put(key,assembly);}
            catch(RuntimeException|Error failure){lease.close();throw failure;}
        }else if(!assembly.matches(page,session,generation))return result(Status.REJECTED);
        int index=page.pageIndex(),offset=index*ManagementPage.PAGE_BYTES;byte[] data=page.data();
        if(assembly.have[index]){
            for(int i=0;i<data.length;i++)if(assembly.buffer[offset+i]!=data[i]){
                remove(key);return result(Status.CORRUPT);
            }
            return result(Status.DUPLICATE);
        }
        System.arraycopy(data,0,assembly.buffer,offset,data.length);assembly.have[index]=true;assembly.received++;assembly.progress=now;
        if(assembly.received!=assembly.have.length)return result(Status.INCOMPLETE);
        remove(key);
        if(!Crypto.equal(ManagementPage.digestOf(assembly.buffer),page.objectDigest()))return result(Status.CORRUPT);
        return new Result(Status.COMPLETE,new Completed(assembly));
    }
    private static Result result(Status status){return new Result(status,null);}
    private void remove(DhtId peer){var assembly=assemblies.remove(peer);if(assembly!=null)assembly.lease.close();}
    public synchronized void poll(){
        long now=clock.millis();var iterator=assemblies.values().iterator();
        while(iterator.hasNext()){
            var assembly=iterator.next();if(assembly.expired(now)){iterator.remove();assembly.lease.close();}
        }
    }
    public synchronized void forget(byte[] peer){remove(new DhtId(peer));}
    public synchronized void clear(){for(var assembly:assemblies.values())assembly.lease.close();assemblies.clear();}
    public synchronized int active(){poll();return assemblies.size();}
    @Override public String toString(){return "Management page assembler";}
}
