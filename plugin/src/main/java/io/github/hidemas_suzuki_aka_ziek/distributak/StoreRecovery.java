// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

/** Androidの保存口を差し替えて、停止からの復旧順をPCでも試す。 */
final class StoreRecovery {
    private StoreRecovery(){}
    static int port(Integer configured,Integer authenticated) {
        Integer value=authenticated!=null?authenticated:configured;
        if(value==null)throw new SecurityException("ポートの記録がありません");
        return LanSupport.port(value,new java.security.SecureRandom());
    }
    static boolean canCreate(boolean member,boolean erasing){return !member&&!erasing;}
    static boolean canJoin(boolean member){return !member;}
    interface Completion {void run()throws Exception;}
    static void acceptJoined(java.util.concurrent.Future<?> join,Completion clear)throws Exception {
        if(!join.isDone())throw new IllegalStateException("加入は未完了です");
        join.get();clear.run();
    }
    static void acceptJoined(java.util.concurrent.Future<?> join,EraseTarget target,Completion save,Completion clearComplete)throws Exception {
        acceptJoined(join,()->create(target,save,clearComplete));
    }
    // 初回と消去後でtargetを分け、保存中の停止から元の未所属状態へ戻す。
    static void create(EraseTarget target,Completion save,Completion clearComplete)throws Exception {
        try {
            target.markPending();save.run();clearComplete.run();target.clearPending();
        }catch(Exception e){
            try{resume(target);}catch(Exception cleanup){e.addSuppressed(cleanup);}
            throw e;
        }
    }
    interface EraseTarget {
        boolean pending();
        void markPending()throws Exception;
        void stop()throws Exception;
        void deleteKey()throws Exception;
        void deleteRecords()throws Exception;
        void markComplete()throws Exception;
        void wipeMemory()throws Exception;
        void clearPending()throws Exception;
    }
    static void erase(EraseTarget target)throws Exception {target.markPending();resume(target);}
    static void resume(EraseTarget erased,EraseTarget initial)throws Exception {
        if(erased.pending()) {
            resume(erased);
            // 両方の印があれば消去済みを優先し、初回の復旧では上書きしない。
            initial.clearPending();
        }else resume(initial);
    }
    static void resume(EraseTarget target)throws Exception {
        if(!target.pending())return;
        target.stop();target.deleteKey();target.deleteRecords();target.markComplete();target.wipeMemory();target.clearPending();
    }
}
