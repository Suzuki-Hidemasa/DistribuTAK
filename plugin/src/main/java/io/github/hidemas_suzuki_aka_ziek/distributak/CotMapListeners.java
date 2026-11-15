// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.ArrayList;
import java.util.function.Consumer;
import java.util.function.BiConsumer;

/** TYPEDとBASEの登録・再登録と、古い世代の通知の拒否。 */
final class CotMapListeners<E,L> {
    enum Route { TYPED,BASE }
    interface Bindings<E,L> {
        L create(Consumer<E> callback);
        void add(Route route,int kind,L callback);
        void remove(Route route,int kind,L callback);
    }
    private final class Entry {
        final Bindings<E,L> bindings;final Route route;final int kind;final L callback;
        Entry(Bindings<E,L> bindings,Route route,int kind,L callback){this.bindings=bindings;this.route=route;this.kind=kind;this.callback=callback;}
    }
    private final ArrayList<Entry> installed=new ArrayList<>();
    private volatile boolean active;
    private volatile long epoch;
    private Bindings<E,L> bindings;
    private BiConsumer<Route,E> forward;
    private Consumer<Runnable> guarded;
    long generation(){return epoch;}
    void start(Bindings<E,L> bindings,Consumer<E> forward){
        start(bindings,Runnable::run,forward);
    }
    void start(Bindings<E,L> bindings,Consumer<Runnable> guarded,Consumer<E> forward){startRouted(bindings,guarded,(route,event)->forward.accept(event));}
    void startRouted(Bindings<E,L> bindings,Consumer<Runnable> guarded,BiConsumer<Route,E> forward){
        if(active)return;
        this.bindings=bindings;this.guarded=guarded;this.forward=forward;
        // 外せなかった登録を残したまま、同じ口へ重ねて登録しない。
        stop();long generation=++epoch;active=true;
        try{
            for(Route route:new Route[]{Route.TYPED,Route.BASE})for(int kind=0;kind<5;kind++)add(bindings,route,kind,generation,forward);
        }catch(RuntimeException failure){
            try{stop();}catch(RuntimeException ignored){}throw failure;
        }
    }
    void rebind(){
        if(!active)return;
        var b=bindings;var g=guarded;var f=forward;stop();startRouted(b,g,f);
    }
    private void add(Bindings<E,L> bindings,Route route,int kind,long generation,BiConsumer<Route,E> forward){
        for(Entry entry:installed)if(entry.route==route&&entry.kind==kind)return;
        try{
            L callback=bindings.create(event->{
                if(!active||epoch!=generation)return;
                guarded.accept(()->{
                    if(active&&epoch==generation)forward.accept(route,event);
                });
            });
            // APIが登録後に例外を投げても、stopで片付けられるよう先に覚える。
            installed.add(new Entry(bindings,route,kind,callback));
            bindings.add(route,kind,callback);
        }catch(RuntimeException failure){/* 次の登録は試し、保存した登録はstopで片付ける。 */}
    }
    void stop(){
        active=false;epoch++;
        for(var iterator=installed.iterator();iterator.hasNext();){
            Entry entry=iterator.next();
            try{entry.bindings.remove(entry.route,entry.kind,entry.callback);iterator.remove();}
            catch(RuntimeException failure){/* 外せなかった自分の登録は次のstopでやり直す。 */}
        }
    }
}
