// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.Set;
import java.util.function.Consumer;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.CotRecord;

/** ATAK依存の口。start/stop/importはmain、savedとpollはworkerでも呼べる。 */
interface CotPort {
    boolean REAL_IMPORT_ENABLED=true;
    String FIXTURE_UID="distributak-fence-fixture-v1";
    enum Send { BROADCAST,SERVERS,ANY,TAK_SERVER }
    interface Listener {default void captureStarted(){}void position(String uid,byte[] xml);void external(String uid);boolean externalMarked(String uid);}
    String selfUid();
    void start(Listener listener,Consumer<Runnable> guardedMain);
    void saved(Set<String> received);
    default void captureSaved(io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState state){}
    default void reconnected(){}
    void accept(CotRecord record);
    void debug();void debugFenceOnly();void debugSend(Send method);
    boolean ready();boolean failed();
    void poll(long nanos);
    default long importAttempts(){return 0;}
    String diagnostics();
    default String captureStatus(){return "";}
    void stop();
    CotPort NONE=new CotPort(){
        public String selfUid(){return null;}
        public void start(Listener listener,Consumer<Runnable> guardedMain){}
        public void saved(Set<String> received){}
        public void accept(CotRecord record){}
        public void debug(){}public void debugFenceOnly(){}public void debugSend(Send method){}
        public boolean ready(){return false;}public boolean failed(){return false;}
        public void poll(long nanos){}
        public String diagnostics(){return "";}
        public void stop(){}
    };
}
