// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.util.*;

/** 完了した列挙だけから候補を作る。所有の証拠と、保存成功の通知は別の口。 */
final class CotCaptureReconcile {
    static final Set<String> CONFIRMED_CREATED_TYPES=Set.of();
    static CotCaptureReconcile closed(CotCapturePolicy policy,java.util.function.Predicate<String> forbidden,java.util.function.Predicate<String> absent){
        return new CotCaptureReconcile(policy,new Port(){
            // 確認済みの作成経路とuidに結びつく証拠は、まだ一つも無い。
            public boolean owns(String uid,String type){return false;}
            public boolean forbidden(String uid){return forbidden.test(uid);}
            public boolean absent(String uid){return absent.test(uid);}
            public void capture(String uid){throw new IllegalStateException("自作の証拠を確認できません");}
            public void remove(String uid){throw new IllegalStateException("自作の証拠を確認できません");}
        });
    }
    interface Port {
        boolean owns(String uid,String type);
        boolean forbidden(String uid);
        boolean absent(String uid);
        void capture(String uid);
        void remove(String uid);
    }
    private final CotCapturePolicy policy;
    private final Port port;
    private final Set<String> allowedTypes;
    private final Set<String> before=new HashSet<>();
    private final Map<String,String> candidates=new HashMap<>();
    private boolean baseline,limited;
    private final Map<String,String> savedTypes=new HashMap<>();
    private final Set<String> pendingDeletion=new HashSet<>();
    CotCaptureReconcile(CotCapturePolicy policy,Port port){this(policy,port,CONFIRMED_CREATED_TYPES);}
    CotCaptureReconcile(CotCapturePolicy policy,Port port,Set<String> allowedTypes){this.policy=policy;this.port=port;this.allowedTypes=Set.copyOf(allowedTypes);}
    void beforeBaseline(String uid){
        if(baseline||limited||uid==null)return;
        if(!before.contains(uid)&&before.size()>=CotCapturePolicy.MAX_REVIEW_UIDS){limited=true;policy.resetContinuity();return;}
        before.add(uid);
    }
    void beforeBaseline(Iterable<String> uids){for(String uid:uids)beforeBaseline(uid);}
    boolean baselined(){return baseline;}
    boolean limited(){return limited;}
    int retained(){return before.size()+candidates.size();}
    void saved(String uid,boolean deleted){
        if(limited||!candidates.containsKey(uid))return;
        if(!savedTypes.containsKey(uid)&&savedTypes.size()>=CotCapturePolicy.MAX_REVIEW_UIDS)return;
        if(!savedTypes.containsKey(uid))savedTypes.put(uid,candidates.get(uid));
        policy.saved(uid,deleted);if(!deleted)policy.seen(Set.of(uid));pendingDeletion.remove(uid);
    }
    void complete(Map<String,String> present,boolean periodic,CotCapturePolicy.Result result){
        beforeBaseline(present.keySet());
        if(limited){policy.absent(present.keySet(),periodic,CotCapturePolicy.Result.LIMIT);return;}
        if(result!=CotCapturePolicy.Result.SUCCESS){policy.absent(present.keySet(),periodic,result);return;}
        if(!baseline){baseline=true;policy.resetContinuity();return;}
        try{
            // 上限を先に調べ、その回の途中で追加や削除を作らない。
            var captures=new LinkedHashMap<String,String>();int total=retained();
            for(var entry:present.entrySet()){
                String uid=entry.getKey();String type=entry.getValue();
                if(before.contains(uid)||type==null||!allowedTypes.contains(type)||port.forbidden(uid)||!port.owns(uid,type))continue;
                if(!candidates.containsKey(uid)&&++total>CotCapturePolicy.MAX_REVIEW_UIDS){limited=true;policy.resetContinuity();return;}
                captures.put(uid,type);
            }
            var deletions=new ArrayList<String>();
            policy.absent(present.keySet(),periodic,result);
            for(var entry:savedTypes.entrySet()){
                String uid=entry.getKey();
                if(present.containsKey(uid)||pendingDeletion.contains(uid)||before.contains(uid)||port.forbidden(uid))continue;
                if(policy.deletable(uid,port.absent(uid),port.owns(uid,entry.getValue())))deletions.add(uid);
            }
            for(var entry:captures.entrySet()){
                String uid=entry.getKey();candidates.put(uid,entry.getValue());pendingDeletion.remove(uid);
                if(savedTypes.containsKey(uid))savedTypes.put(uid,entry.getValue());
                port.capture(uid);
            }
            for(String uid:deletions){port.remove(uid);pendingDeletion.add(uid);}
        }catch(RuntimeException failure){policy.resetContinuity();throw failure;}
    }
    void resetContinuity(){policy.resetContinuity();pendingDeletion.clear();}
}
