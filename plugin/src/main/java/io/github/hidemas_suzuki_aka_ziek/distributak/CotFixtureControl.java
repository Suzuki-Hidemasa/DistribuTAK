// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.function.Consumer;
import java.util.function.Supplier;

/** DEBUGの試しだけを許し、固定の架空UIDの印と件数を管理する。 */
final class CotFixtureControl {
    private final boolean debug;
    private final CotFixtureDiagnostics counts;
    private boolean fenceOnly;
    CotFixtureControl(boolean debug,CotFixtureDiagnostics counts){this.debug=debug;this.counts=counts;}
    static <T> T button(boolean debug,Supplier<T> create){return debug?create.get():null;}
    void reset(){fenceOnly=false;}
    boolean nevercot(String uid){return !debug||!fenceOnly||!CotPort.FIXTURE_UID.equals(uid);}
    void inject(boolean ready,boolean registered,boolean only,Consumer<Runnable> prepare){
        int mode=only?1:0;
        if(!debug||!ready||!registered){counts.fixture(mode,1);return;}
        fenceOnly=only;
        boolean[] entered={false};
        try{prepare.accept(()->{entered[0]=true;counts.fixture(mode,0);});}
        catch(RuntimeException e){if(!entered[0])counts.fixture(mode,2);throw e;}
    }
    void send(boolean ready,boolean registered,CotPort.Send method,Consumer<Runnable> broadcast,Consumer<Runnable> servers,Consumer<Runnable> any,Consumer<Runnable> takServer){
        counts.sendPressed();
        if(!debug||!ready||!registered){counts.sendDeclined();return;}
        switch(method){
            case BROADCAST -> attempt(0,broadcast);
            case SERVERS -> attempt(1,servers);
            case ANY -> attempt(2,any);
            case TAK_SERVER -> attempt(3,takServer);
        }
    }
    private void attempt(int api,Consumer<Runnable> prepare){
        // 解析・取得が済み、実際にAPIを呼ぶ直前にだけ呼び出し件数を増やす。
        try{prepare.accept(()->counts.apiCalled(api));}
        catch(RuntimeException ignored){counts.apiFailed(api);}
    }
}
