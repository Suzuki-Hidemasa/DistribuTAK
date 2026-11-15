// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/** 変更しない送信一覧と、全ページがそろうまで不存在を判断しない受信一覧。 */
public final class SyncInventory {
    public static final int PAGE_ENTRIES=64,MAX_PAGES=64,PEER_BYTES=8*1024*1024,TOTAL_BYTES=32*1024*1024;
    private SyncInventory(){}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("同期の一覧か求めが範囲外です");}
    static int charge(SyncSchema.SyncInventoryEntry item){return 2*item.getSerializedSize()+64;}
    public static Offer offer(SyncState state,byte[] snapshotId,long now){return offer(state,snapshotId,now,PEER_BYTES);}
    public static Offer offer(SyncState state,byte[] snapshotId,long now,int availableBytes){
        return offer(state,snapshotId,now,availableBytes,item->true);
    }
    private static Offer offer(SyncState state,byte[] snapshotId,long now,int availableBytes,Predicate<CotRecord> allowed){
        Crypto.length(snapshotId,16);var copy=state.copy();copy.prune(now);
        var records=new ArrayList<>(copy.records());records.sort((a,b)->SyncState.compareUid(a.uid(),b.uid()));
        var entries=new ArrayList<SyncSchema.SyncInventoryEntry>();int bytes=128;
        for(CotRecord record:records){
            if(record.hop()>=CotRecord.MAX_HOP||!allowed.test(record))continue;
            try{record.validateAt(now);}catch(IllegalArgumentException e){continue;}
            var entry=SyncWire.entry(record);bytes+=charge(entry);
            if(entries.size()>=SyncState.MAX_UIDS||bytes>availableBytes||bytes>PEER_BYTES)throw invalid();entries.add(entry);
        }
        if(bytes>availableBytes)throw invalid();return new Offer(snapshotId,entries,bytes);
    }
    public static final class CacheMiss extends IllegalArgumentException {
        CacheMiss(){super("退避した一覧を取り直します");}
    }
    public static Offer offer(SyncState state,byte[] snapshotId,long now,int availableBytes,SyncCache cache,String scope){
        return offer(state,snapshotId,now,availableBytes,cache,scope,null);
    }
    public static Offer offer(SyncState state,byte[] snapshotId,long now,int availableBytes,SyncCache cache,String scope,java.util.function.Supplier<SyncState> recovery){
        return offer(state,snapshotId,now,availableBytes,cache,scope,recovery,item->true);
    }
    static Offer offer(SyncState state,byte[] snapshotId,long now,int availableBytes,SyncCache cache,String scope,java.util.function.Supplier<SyncState> recovery,Predicate<CotRecord> allowed){
        Offer offer=offer(state,snapshotId,now,availableBytes,allowed);if(cache==null)return offer;
        var refs=new SyncCache.Ref[offer.pageCount()];
        try{
            for(int page=0;page<refs.length;page++){
                byte[] wire=offer.page(page);try{refs[page]=cache.put(scope,wire,2);if(refs[page]==null)throw new CacheMiss();}finally{Crypto.wipe(wire);}
            }
            return new Offer(snapshotId,refs,cache,recovery,now,allowed);
        }catch(RuntimeException e){for(var ref:refs)cache.forget(ref);throw e;}
    }
    public static final class Offer implements AutoCloseable {
        private final byte[] id;private final List<SyncSchema.SyncInventoryEntry> entries;private final int bytes;
        private SyncCache cache;private SyncCache.Ref[] cold;
        private java.util.function.Supplier<SyncState> recovery;private long frozenAt;private Predicate<CotRecord> allowed;
        private Offer(byte[] id,List<SyncSchema.SyncInventoryEntry> entries,int bytes){this.id=id.clone();this.entries=List.copyOf(entries);this.bytes=bytes;}
        private Offer(byte[] id,SyncCache.Ref[] refs,SyncCache cache,java.util.function.Supplier<SyncState> recovery,long frozenAt,Predicate<CotRecord> allowed){this.id=id.clone();entries=null;cold=refs;this.cache=cache;this.recovery=recovery;this.frozenAt=frozenAt;this.allowed=allowed;bytes=128+SyncCache.REFERENCE_BYTES*refs.length;}
        public void prefetch(int index){if(cache!=null&&index>=0&&index<cold.length)cache.prefetch(cold[index]);}
        public void close(){if(cache!=null)for(var ref:cold)cache.forget(ref);}
        public byte[] id(){return id.clone();}
        public int pageCount(){if(cold!=null)return cold.length;return Math.max(1,(entries.size()+PAGE_ENTRIES-1)/PAGE_ENTRIES);}
        public int retainedBytes(){return bytes;}
        public byte[] page(int index){
            if(index<0||index>=pageCount())throw invalid();
            if(cache!=null){
                byte[] wire=cache.get(cold[index]);
                if(wire==null&&recovery!=null){
                    Offer current=offer(recovery.get(),id,frozenAt,PEER_BYTES,allowed);byte[] rebuilt=index<current.pageCount()?current.page(index):null;
                    var repaired=cache.repair(cold[index],rebuilt);
                    if(repaired!=null){cold[index]=repaired;wire=rebuilt;}else Crypto.wipe(rebuilt);
                }
                if(wire==null)throw new CacheMiss();prefetch(index+1);return wire;
            }
            return SyncWire.envelope().setInventory(SyncSchema.SyncInventory.newBuilder().setSnapshotId(SyncWire.bytes(id))
                    .setPage(index).setLast(index==pageCount()-1).addAllEntries(pageEntries(index))).build().toByteArray();
        }
        private List<SyncSchema.SyncInventoryEntry> pageEntries(int index){
            if(cache!=null){byte[] wire=page(index);try{return SyncWire.parse(wire).getInventory().getEntriesList();}finally{Crypto.wipe(wire);}}
            return entries.subList(index*PAGE_ENTRIES,Math.min(entries.size(),(index+1)*PAGE_ENTRIES));
        }
        /** 返す項目は自分の一覧への参照。相手が出したXMLなどは保持しない。 */
        public List<SyncSchema.SyncInventoryEntry> request(byte[] wire){
            var envelope=SyncWire.parse(wire);if(!envelope.hasRequest())throw invalid();var request=envelope.getRequest();
            int page=request.getPage();
            if(!Arrays.equals(id,request.getSnapshotId().toByteArray())||page<0||page>=pageCount()||request.getWantedCount()>PAGE_ENTRIES)throw invalid();
            var provided=new LinkedHashMap<String,SyncSchema.SyncInventoryEntry>();
            for(var entry:pageEntries(page))provided.put(entry.getUid(),entry);
            var result=new ArrayList<SyncSchema.SyncInventoryEntry>();var names=new HashSet<String>();
            for(var wanted:request.getWantedList()){
                SyncWire.validateEntry(wanted);var entry=provided.get(wanted.getUid());
                if(entry==null||!entry.equals(wanted)||!names.add(wanted.getUid()))throw invalid();result.add(entry);
            }
            return List.copyOf(result);
        }
        @Override public String toString(){return "Inventory offer";}
    }
    public static final class Receiver implements AutoCloseable {
        private static final int BASE_BYTES=128+36*MAX_PAGES;
        private byte[] id;
        private int last=-1,bytes;
        private final SyncSchema.SyncInventory[] pages=new SyncSchema.SyncInventory[MAX_PAGES];
        private final SyncSchema.SyncRequest[] requests=new SyncSchema.SyncRequest[MAX_PAGES];
        private final Map<String,SyncSchema.SyncInventoryEntry> entries=new LinkedHashMap<>();
        private final SyncCache cache;private final String scope;
        private final SyncCache.Ref[] coldPages=new SyncCache.Ref[MAX_PAGES],coldRequests=new SyncCache.Ref[MAX_PAGES];
        private final Map<String,Integer> index=new LinkedHashMap<>();
        private final int[] charges=new int[MAX_PAGES];private final boolean[] saved=new boolean[MAX_PAGES];
        public Receiver(){this(null,null);}
        public Receiver(SyncCache cache,String scope){this.cache=cache;this.scope=scope;}
        private boolean has(int page){return cache==null?pages[page]!=null:coldPages[page]!=null;}
        private void drop(int page){
            if(cache==null)return;cache.forget(coldPages[page]);cache.forget(coldRequests[page]);coldPages[page]=null;coldRequests[page]=null;saved[page]=false;
            index.values().removeIf(value->value==page);bytes-=charges[page];charges[page]=0;
        }
        private SyncSchema.SyncInventory readPage(int page){
            if(cache==null)return pages[page];byte[] wire=cache.get(coldPages[page]);if(wire==null){drop(page);throw new CacheMiss();}
            try{return SyncWire.parse(wire).getInventory();}finally{Crypto.wipe(wire);}
        }
        private SyncSchema.SyncRequest readRequest(int page){
            if(cache==null)return requests[page];byte[] wire=cache.get(coldRequests[page]);if(wire==null){drop(page);throw new CacheMiss();}
            try{return SyncWire.parse(wire).getRequest();}finally{Crypto.wipe(wire);}
        }
        public void close(){if(cache!=null)for(int page=0;page<MAX_PAGES;page++)drop(page);}
        public boolean requestedSaved(Predicate<SyncSchema.SyncInventoryEntry> present){
            for(int page=0;page<MAX_PAGES;page++)if(has(page)&&!saved[page]){
                boolean done=true;try{for(var entry:readRequest(page).getWantedList())if(!present.test(entry)){done=false;break;}}
                catch(CacheMiss e){return false;}saved[page]=done;if(!done)return false;
            }return true;
        }
        public byte[] accept(byte[] wire,Predicate<SyncSchema.SyncInventoryEntry> wanted){return accept(wire,wanted,PEER_BYTES);}
        public byte[] accept(byte[] wire,Predicate<SyncSchema.SyncInventoryEntry> wanted,int availableBytes){
            var envelope=SyncWire.parse(wire);if(!envelope.hasInventory())throw invalid();var page=envelope.getInventory();
            int index=page.getPage();byte[] snapshot=page.getSnapshotId().toByteArray();
            if(snapshot.length!=16||index<0||index>=MAX_PAGES||page.getEntriesCount()>PAGE_ENTRIES
                    ||id!=null&&!Arrays.equals(id,snapshot)||last>=0&&index>last)throw invalid();
            if(has(index)){
                try{if(!readPage(index).equals(page))throw invalid();return request(index);}catch(CacheMiss e){/* このページだけを再評価する。 */}
            }
            if(page.getLast()){
                if(last>=0&&last!=index)throw invalid();
                for(int n=index+1;n<MAX_PAGES;n++)if(has(n))throw invalid();
            }else if(index==last)throw invalid();
            int added=(id==null?BASE_BYTES:0)+128;var names=new HashSet<String>();
            var request=SyncSchema.SyncRequest.newBuilder().setSnapshotId(page.getSnapshotId()).setPage(index);
            for(var entry:page.getEntriesList()){
                SyncWire.validateEntry(entry);
                if((cache==null?entries.containsKey(entry.getUid()):this.index.containsKey(entry.getUid()))||!names.add(entry.getUid()))throw invalid();
                added+=charge(entry);
                // protobufの不変な項目を参照し、UIDやhashをもう一度複製しない。
                if(wanted.test(entry)){request.addWanted(entry);added+=8;}
            }
            var fixedRequest=request.build();
            // 保持する既知ページと固定Requestの実データ量を必ず算入する。
            added=Math.max(added,(id==null?BASE_BYTES:0)+128+page.getSerializedSize()+fixedRequest.getSerializedSize()+8*page.getEntriesCount());
            if(cache!=null){added=(id==null?BASE_BYTES:0)+2*SyncCache.REFERENCE_BYTES+64;for(String uid:names)added+=128+2*uid.length();}
            if((cache==null?entries.size():this.index.size())+names.size()>SyncState.MAX_UIDS||bytes+added>availableBytes||bytes+added>PEER_BYTES)throw invalid();
            if(cache!=null){
                byte[] requestWire=SyncWire.envelope().setRequest(fixedRequest).build().toByteArray();
                SyncCache.Ref pageRef=null,requestRef=null;
                try{pageRef=cache.put(scope+"/pages",wire,2);requestRef=cache.put(scope+"/requests",requestWire,2);
                    if(pageRef==null||requestRef==null){cache.forget(pageRef);cache.forget(requestRef);throw new CacheMiss();}
                }finally{Crypto.wipe(requestWire);}
                coldPages[index]=pageRef;coldRequests[index]=requestRef;charges[index]=added-(id==null?BASE_BYTES:0);
                for(String uid:names)this.index.put(uid,index);
            }else{pages[index]=page;requests[index]=fixedRequest;}
            id=snapshot;bytes+=added;
            if(page.getLast())last=index;
            if(cache==null)for(var entry:page.getEntriesList())entries.put(entry.getUid(),entry);
            return request(index);
        }
        private byte[] request(int index){return SyncWire.envelope().setRequest(readRequest(index)).build().toByteArray();}
        public boolean complete(){if(last<0)return false;for(int n=0;n<=last;n++)if(!has(n))return false;return true;}
        public boolean knows(String uid){if(!complete())throw new IllegalStateException("一覧の全ページを待っています");return cache==null?entries.containsKey(uid):index.containsKey(uid);}
        public List<SyncSchema.SyncInventoryEntry> entries(){if(!complete())throw new IllegalStateException("一覧の全ページを待っています");if(cache==null)return List.copyOf(entries.values());var result=new ArrayList<SyncSchema.SyncInventoryEntry>();for(int page=0;page<=last;page++)result.addAll(readPage(page).getEntriesList());return List.copyOf(result);}
        public List<SyncSchema.SyncInventoryEntry> wanted(){
            var result=new ArrayList<SyncSchema.SyncInventoryEntry>();for(int page=0;page<MAX_PAGES;page++)if(has(page))result.addAll(readRequest(page).getWantedList());return List.copyOf(result);
        }
        public int retainedBytes(){return bytes;}
        public boolean started(){return id!=null;}
        @Override public String toString(){return "Inventory receiver";}
    }
    static boolean matches(CotRecord record,SyncSchema.SyncInventoryEntry entry){
        return record!=null&&record.uid().equals(entry.getUid())&&record.time()==entry.getVersion().getWallMillis()
                &&Arrays.equals(record.author(),entry.getVersion().getEudId().toByteArray())
                &&Arrays.equals(record.hash(),entry.getHash().toByteArray())&&record.deleted()==entry.getDeleted();
    }
    static int compare(CotRecord record,SyncSchema.SyncInventoryEntry entry){
        int order=Long.compare(record.time(),entry.getVersion().getWallMillis());
        if(order==0)order=AdminRecords.compareBytes(record.author(),entry.getVersion().getEudId().toByteArray());
        return order!=0?order:-AdminRecords.compareBytes(record.hash(),entry.getHash().toByteArray());
    }
}
