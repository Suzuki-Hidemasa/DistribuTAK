// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import android.content.Context;
import android.os.*;
import android.util.Log;
import java.time.Clock;
import java.security.SecureRandom;
import java.util.concurrent.*;
import com.atakmap.android.maps.MapView;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncLimits;

/** 公開Android APIを、制御へ渡す依存にまとめる。 */
final class AndroidLanRuntime {
    private AndroidLanRuntime(){}
    static LanController create(Context context,LanController.Ui ui,Runnable loaderCheck,MapView map){
        Context host=context.getApplicationContext();Handler main=new Handler(Looper.getMainLooper());
        var executor=Executors.newSingleThreadScheduledExecutor(r->new Thread(r,"distributak-lan"));
        var tasks=new LanRuntime.Tasks(){
            public void execute(Runnable task){executor.execute(task);}
            public void repeat(Runnable task){executor.scheduleWithFixedDelay(task,1,1,TimeUnit.SECONDS);}
            public void repeatSync(Runnable task){executor.scheduleAtFixedRate(task,250,250,TimeUnit.MILLISECONDS);}
            public void close(){executor.shutdown();}
        };
        var stores=new LanRuntime.Stores(){
            public LanRuntime.Storage open()throws Exception{return new AndroidStateStore(host);}
            public LanRuntime.Storage erase(Runnable stop,Runnable wipe)throws Exception{return AndroidStateStore.erase(host,stop,wipe);}
        };
        return new LanController(ui,new LanRuntime(stores,changed->new WifiLan(host,changed),tasks,main::post,
                fixed->Log.i(LanController.TAG,fixed),loaderCheck,Clock.systemUTC(),AndroidClocks.MONOTONIC_NANOS,new SecureRandom(),InvitationQr::encode,
                new AndroidCotPort(map,Clock.systemUTC(),AndroidClocks.MONOTONIC_NANOS),SyncLimits.forHeap(Runtime.getRuntime().maxMemory())));
    }
}
