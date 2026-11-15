// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import com.atakmap.android.maps.*;
import com.atakmap.android.cot.CotMapComponent;
import com.atakmap.android.importexport.CotEventFactory;
import com.atakmap.comms.CommsMapComponent;
import com.atakmap.commoncommo.CoTSendMethod;
import com.atakmap.coremap.cot.event.CotDetail;
import com.atakmap.coremap.cot.event.CotEvent;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/** 公開APIだけを使うATAKの口。受信CoTは登録済みの柵と取り込みの門を通す。 */
final class AndroidCotPort implements CotPort {
    private final MapView map;
    private final Clock clock;
    private final LongSupplier nanos;
    private final String selfUid;
    private final CotFixtureDiagnostics counts=new CotFixtureDiagnostics(BuildConfig.DEBUG);
    private final CotMapListeners<MapSignal,MapEventDispatcher.MapEventDispatchListener> mapListeners=new CotMapListeners<>();
    private static final String[] MAP_TYPES={MapEvent.ITEM_ADDED,MapEvent.ITEM_PERSIST,MapEvent.ITEM_REFRESH,MapEvent.ITEM_REMOVED,MapEvent.ITEM_IMPORTED};
    private final CotFixtureControl fixture=new CotFixtureControl(BuildConfig.DEBUG,counts);
    private final AtomicBoolean capturing=new AtomicBoolean();
    private final Handler main=new Handler(Looper.getMainLooper());
    private long captureGeneration;
    private CotCapturePolicy mapPolicy=new CotCapturePolicy();
    private CotCaptureReconcile mapReconcile;
    private volatile Map<String,Boolean> savedCreated=Map.of();
    private final Map<String,Boolean> knownCreated=new HashMap<>();
    private final Set<String> pending=new LinkedHashSet<>();
    private final CotMapSignals signals=new CotMapSignals();
    private boolean pendingOverflow,scanQueued;
    private volatile boolean mapLimit;
    private CotMapScan.Snapshot previousScan;
    private Runnable mapTick,positionTick;
    // 第1段はXMLを作らず、公開APIからuidと型を読む。
    private static final CotMapScan.Access<MapGroup,MapItem> MAP_ACCESS=new CotMapScan.Access<>(){
        public Iterable<MapGroup> groups(MapGroup group){return group.getChildGroups();}
        public Iterable<MapItem> items(MapGroup group){return group.getItems();}
        public String uid(MapItem item){return item.getUID();}
        public String type(MapItem item){return item.getType();}
    };
    private volatile CotFence fence=new CotFence();
    private volatile Set<String> saved=Set.of();
    private volatile boolean active;
    private Listener listener;
    private Consumer<Runnable> guarded;
    private Marker self;
    private CommsMapComponent comms;
    private Processor processor;
    private PointMapItem.OnPointChangedListener points;
    private record MapSignal(String uid,int eventKind){}
    private volatile long importAttempts;
    private MapSignal signalOf(MapEvent event){
        MapItem item=event.getItem();String type=event.getType();
        int kind=MapEvent.ITEM_ADDED.equals(type)?0:MapEvent.ITEM_IMPORTED.equals(type)?1:MapEvent.ITEM_PERSIST.equals(type)?2:
                MapEvent.ITEM_REFRESH.equals(type)?3:MapEvent.ITEM_REMOVED.equals(type)?4:5;
        String uid=item==null?null:item.getUID();
        if(uid!=null&&uid.length()>256)uid=null;
        return new MapSignal(uid,kind);
    }
    AndroidCotPort(MapView map,Clock clock,LongSupplier nanos){
        this.map=map;this.clock=clock;this.nanos=nanos;
        Marker marker=map.getSelfMarker();selfUid=marker==null?null:marker.getUID();
    }
    public String selfUid(){return selfUid;}
    public void start(Listener listener,Consumer<Runnable> guardedMain){
        if(active)throw new IllegalStateException("同期の口は使用中です");
        this.listener=listener;guarded=guardedMain;self=map.getSelfMarker();
        if(self==null||selfUid==null||!selfUid.equals(self.getUID()))throw new IllegalStateException("自分の位置を識別できません");
        captureGeneration++;capturing.set(false);mapPolicy=new CotCapturePolicy();previousScan=null;pending.clear();pendingOverflow=false;scanQueued=false;mapLimit=false;importAttempts=0;fixture.reset();fence=new CotFence();fence.saved(saved);fence.begin(nanos.getAsLong());active=true;
        knownCreated.clear();listener.captureStarted();mapReconcile=CotCaptureReconcile.closed(mapPolicy,uid->selfUid.equals(uid)||fence.contains(uid),uid->map.getMapItem(uid)==null);
        processor=new Processor(fence,nanos,counts);comms=CommsMapComponent.getInstance();
        if(comms==null)throw new IllegalStateException("柵を登録できません");
        comms.registerPreSendProcessor(processor);
        signals.clear();
        long pointGeneration=captureGeneration;
        points=item->{if(item==self)main.post(()->guarded.accept(()->{if(active&&pointGeneration==captureGeneration)captureSoon();}));};
        var dispatcher=map.getMapEventDispatcher();
        mapListeners.startRouted(new CotMapListeners.Bindings<>(){
            public MapEventDispatcher.MapEventDispatchListener create(Consumer<MapSignal> callback){return event->guarded.accept(()->callback.accept(signalOf(event)));}
            public void add(CotMapListeners.Route route,int kind,MapEventDispatcher.MapEventDispatchListener callback){
                switch(route){
                    case TYPED -> dispatcher.addMapEventListener(MAP_TYPES[kind],callback);
                    case BASE -> dispatcher.addMapEventListenerToBase(MAP_TYPES[kind],callback);
                }
            }
            public void remove(CotMapListeners.Route route,int kind,MapEventDispatcher.MapEventDispatchListener callback){
                switch(route){
                    case TYPED -> dispatcher.removeMapEventListener(MAP_TYPES[kind],callback);
                    case BASE -> dispatcher.removeMapEventListenerFromBase(MAP_TYPES[kind],callback);
                }
            }
        },Runnable::run,this::observe);
        self.addOnPointChangedListener(points);captureSoon();
        long generation=captureGeneration;
        mapTick=()->guarded.accept(()->{
            if(!active||generation!=captureGeneration)return;
            reconcile(false);main.postDelayed(mapTick,Math.max(1,mapPolicy.due()-nanos.getAsLong()/1_000_000));
        });
        positionTick=()->guarded.accept(()->{
            if(!active||generation!=captureGeneration)return;
            captureSoon();main.postDelayed(positionTick,CotCapturePolicy.POSITION_MILLIS);
        });
        main.post(mapTick);main.postDelayed(positionTick,CotCapturePolicy.POSITION_MILLIS);
    }
    private void observe(CotMapListeners.Route route,MapSignal event){
        if(!active)return;
        String uid=event.uid();int eventKind=event.eventKind();
        if(uid==null)return;
        mapReconcile.beforeBaseline(uid);
        // 外来と確かめたuidの印は、合図の容量とは別に従来の有限の待ちへ渡す。
        if(eventKind==1&&!selfUid.equals(uid))CotExternalObservation.observe(uid,fence.contains(uid),listener.externalMarked(uid),listener::external);
        if(signals.offer(uid,mapListeners.generation(),eventKind)){
            long epoch=captureGeneration;
            main.post(()->guarded.accept(()->{
                if(!active||epoch!=captureGeneration)return;
                var batch=signals.drain(mapListeners.generation());pendingOverflow|=batch.overflow();
                for(var entry:batch.kinds().entrySet()){
                    String name=entry.getKey();MapItem current=map.getMapItem(name);
                    if(fence.contains(name)){if(current!=null)mark(current,name);continue;}
                    if(selfUid.equals(name)){if((entry.getValue()&~(1<<4))!=0)captureSoon();continue;}
                    signal(name);
                }
            }));
        }
    }
    private void signal(String uid){
        if(uid==null||uid.isEmpty()||uid.length()>256)return;
        if(!pending.contains(uid)&&pending.size()>=CotCapturePolicy.MAX_REVIEW_UIDS)pendingOverflow=true;
        else pending.add(uid);
        if(scanQueued)return;scanQueued=true;long epoch=captureGeneration;
        main.post(()->guarded.accept(()->{
            if(!active||epoch!=captureGeneration)return;scanQueued=false;reconcile(true);
        }));
    }
    private void reconcile(boolean signal){
        long begin=nanos.getAsLong(),now=begin/1_000_000;
        if(!mapPolicy.begin(now,signal))return;
        var timing=new CotCaptureTiming(nanos);boolean periodic=mapPolicy.periodic();
        CotCapturePolicy.Result result=CotCapturePolicy.Result.INTERRUPTED;
        CotMapScan.Snapshot scan=null;
        try{
            scan=CotMapScan.read(map.getRootGroup(),MAP_ACCESS);result=scan.result;
            if(result!=CotCapturePolicy.Result.SUCCESS)return;
            var check=CotMapScan.read(map.getRootGroup(),MAP_ACCESS);mapReconcile.beforeBaseline(check.items.keySet());
            if(!scan.same(check)){result=check.result==CotCapturePolicy.Result.SUCCESS?CotCapturePolicy.Result.INCONSISTENT:check.result;return;}
            if(previousScan!=null&&!scan.sameTopology(previousScan))mapReconcile.resetContinuity();
            previousScan=scan;
            if(pendingOverflow){result=CotCapturePolicy.Result.LIMIT;return;}
            // 許す表は空。本体の照合だけを行い、未判定の物からXMLや所有の証拠を作らない。
            var after=CotMapScan.read(map.getRootGroup(),MAP_ACCESS);mapReconcile.beforeBaseline(after.items.keySet());
            if(!scan.same(after)){result=after.result==CotCapturePolicy.Result.SUCCESS?CotCapturePolicy.Result.INCONSISTENT:after.result;return;}
        }catch(RuntimeException failure){result=CotCapturePolicy.Result.INTERRUPTED;}
        finally{
            try{
                for(var entry:savedCreated.entrySet())if(!Objects.equals(knownCreated.get(entry.getKey()),entry.getValue())){
                    mapReconcile.saved(entry.getKey(),entry.getValue());knownCreated.put(entry.getKey(),entry.getValue());
                }
                mapReconcile.complete(scan==null?Map.of():scan.items,periodic,result);
                if(mapReconcile.limited())result=CotCapturePolicy.Result.LIMIT;
                if(periodic&&active)try{mapListeners.rebind();}finally{timing.finish();}else timing.finish();
                mapPolicy.end(nanos.getAsLong()/1_000_000,scan==null?0:scan.visitedItems,result,timing.policyNanos());
                if(result==CotCapturePolicy.Result.LIMIT)mapLimit=true;else if(result==CotCapturePolicy.Result.SUCCESS)mapLimit=false;
                pending.clear();pendingOverflow=false;
            }finally{timing.finish();}
        }
    }
    private void captureSoon(){
        if(!active||!capturing.compareAndSet(false,true))return;
        long epoch=captureGeneration;
        // guardedはmainへ載せる。位置の変化が続いても待ちは1件だけ。
        main.post(()->guarded.accept(()->{
            try{
                if(!active||epoch!=captureGeneration)return;
                if(map.getSelfMarker()!=self||!selfUid.equals(self.getUID()))throw new IllegalStateException("自分の位置が変わりました");
                CotPositionCapture.capture(()->serialize(self),xml->listener.position(selfUid,xml));
            }finally{if(epoch==captureGeneration)capturing.set(false);}
        }));
    }
    /** SDKへ巨大なStringBuilderを渡さず、文字数とUTF-8の両方で64KiBまで。 */
    private byte[] serialize(MapItem item){
        return CotCaptureExport.position(item,self,()->CotEventFactory.createCotEvent(item),(event,out)->event.buildXml(out));
    }
    private static final class Processor implements CommsMapComponent.PreSendProcessor2 {
        private final CotFence gate;
        private final LongSupplier nanos;
        private final CotFixtureDiagnostics counts;
        Processor(CotFence gate,LongSupplier nanos,CotFixtureDiagnostics counts){this.gate=gate;this.nanos=nanos;this.counts=counts;}
        public void onRegister(boolean status){gate.registered(status,nanos.getAsLong());}
        public void processCotEvent(CotEvent event,String[] uids){}
        public Status processEvent(CotEvent event,String[] uids,CoTSendMethod method){
            int kind=method==CoTSendMethod.TAK_SERVER?0:method==CoTSendMethod.POINT_TO_POINT?1:method==CoTSendMethod.ANY?2:3;
            // 分類は件数だけに使い、すべて同じ柵を通す。
            CotSendFilter.Event view=event==null?null:new CotSendFilter.Event(){
                private CotDetail detail;
                public String uid(){return event.getUID();}
                public boolean deletion(){return "t-x-d-d".equals(event.getType());}
                public int linkCount(){detail=event.getDetail();return detail==null?0:detail.childCount();}
                public String linkUid(int index){CotDetail child=detail.getChild(index);return child!=null&&"link".equals(child.getElementName())?child.getAttribute("uid"):null;}
            };
            boolean blocked=counts.process(gate,view,nanos.getAsLong(),kind)==CotSendFilter.Result.CONSUMED;
            return blocked?Status.CONSUMED:Status.IGNORED;
        }
    }
    public void saved(Set<String> received){saved=Set.copyOf(received);fence.saved(saved);}
    public void reconnected(){if(active){mapReconcile.resetContinuity();mapListeners.rebind();}}
    public void captureSaved(SyncState state){
        var next=new HashMap<String,Boolean>();for(CotRecord record:state.records())if(state.origin(record.uid())==SyncState.Origin.LOCAL_CREATED)next.put(record.uid(),record.deleted());savedCreated=Map.copyOf(next);
    }
    public boolean ready(){return active&&fence.ready();}
    public boolean failed(){return active&&fence.failed();}
    public void poll(long now){fence.poll(now);}
    public String diagnostics(){return counts.text()+(BuildConfig.DEBUG?"\n柵 CONSUMED（今回の登録）: "+fence.consumed():"")+"\n柵: "+(ready()?"登録済み":failed()?"登録できなかった":"待機／停止")+"\n受信CoTの取り込み: "+CotImportGate.status(REAL_IMPORT_ENABLED);}
    public long importAttempts(){return importAttempts;}
    public String captureStatus(){return mapLimit?CotCapturePolicy.LIMIT_TEXT:"";}
    public void accept(CotRecord record){
        if(!CotImportGate.fenced(REAL_IMPORT_ENABLED,this::ready,()->fence.contains(record.uid())))return;
        byte[] xml=record.deleted()?CotImportXml.deletion(record.uid(),clock.millis()):record.xml();
        try{importXml(xml);}finally{Crypto.wipe(xml);if(importAttempts<Long.MAX_VALUE)importAttempts++;}
    }
    public void debug(){debugFixture(false);}
    public void debugFenceOnly(){debugFixture(true);}
    private void debugFixture(boolean only){
        fixture.inject(ready(),fence.contains(FIXTURE_UID),only,dispatching->{
            byte[] xml=CotFixture.xml(clock.millis());
            try{
                CotEvent event=parse(xml);
                MapItem old=map.getMapItem(FIXTURE_UID);if(old!=null)mark(old,FIXTURE_UID);
                importEvent(event,dispatching);
            }finally{Crypto.wipe(xml);}
        });
    }
    public void debugSend(Send method){
        fixture.send(ready(),fence.contains(FIXTURE_UID),method,calling->{
            byte[] xml=CotFixture.xml(clock.millis());
            try{
                CotEvent event=parse(xml);var dispatcher=CotMapComponent.getExternalDispatcher();
                calling.run();dispatcher.dispatchToBroadcast(event,CoTSendMethod.POINT_TO_POINT);
            }finally{Crypto.wipe(xml);}
        },calling->{
            byte[] xml=CotFixture.xml(clock.millis());
            try{CotEvent event=parse(xml);calling.run();comms.sendCoTToServersOnly(null,event);}
            finally{Crypto.wipe(xml);}
        },calling->{
            byte[] xml=CotFixture.xml(clock.millis());
            try{
                CotEvent event=parse(xml);var dispatcher=CotMapComponent.getExternalDispatcher();
                calling.run();dispatcher.dispatchToBroadcast(event,CoTSendMethod.ANY);
            }finally{Crypto.wipe(xml);}
        },calling->{
            byte[] xml=CotFixture.xml(clock.millis());
            try{
                CotEvent event=parse(xml);var dispatcher=CotMapComponent.getExternalDispatcher();
                calling.run();dispatcher.dispatchToBroadcast(event,CoTSendMethod.TAK_SERVER);
            }finally{Crypto.wipe(xml);}
        });
    }
    private void mark(MapItem item,String uid){
        if(fixture.nevercot(uid))item.setMetaBoolean("nevercot",true);else item.removeMetaData("nevercot");
    }
    private void importXml(byte[] xml){importEvent(parse(xml),()->{});}
    private static CotEvent parse(byte[] xml){
        CotXml.inspect(xml);return CotImportInput.parse(()->CotEvent.parse(new String(xml,StandardCharsets.UTF_8)),CotEvent::isValid);
    }
    private void importEvent(CotEvent event,Runnable dispatching){
        Bundle extras=new Bundle();extras.putString("from","distributak");
        var dispatcher=CotMapComponent.getInternalDispatcher();dispatching.run();dispatcher.dispatch(event,extras);
        MapItem item=map.getMapItem(event.getUID());if(item!=null)mark(item,event.getUID());
    }
    public void stop(){
        active=false;captureGeneration++;capturing.set(false);if(mapTick!=null)main.removeCallbacks(mapTick);if(positionTick!=null)main.removeCallbacks(positionTick);pending.clear();signals.clear();knownCreated.clear();savedCreated=Map.of();previousScan=null;importAttempts=0;mapLimit=false;fixture.reset();fence.stop();saved=Set.of();
        try{mapListeners.stop();}
        finally{try{if(self!=null&&points!=null)self.removeOnPointChangedListener(points);}
            finally{if(comms!=null&&processor!=null)comms.unregisterPreSendProcessor(processor);points=null;processor=null;comms=null;listener=null;self=null;}}
    }
}
