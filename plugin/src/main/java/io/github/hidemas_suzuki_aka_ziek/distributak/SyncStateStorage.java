// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.SyncState;
import java.util.Objects;

/** 同期ファイルを確定してから、所属の包みに初期化済みを記録する。 */
final class SyncStateStorage {
    interface Source { boolean exists();byte[] read()throws Exception; }
    interface Action { void run()throws Exception; }
    private final StateEnvelope envelope;
    private final StateEnvelope.AtomicTarget target;
    private final Source source;
    private final ExternalStateStorage external;
    SyncStateStorage(StateEnvelope envelope,StateEnvelope.AtomicTarget target,Source source,ExternalStateStorage external) {
        this.envelope=Objects.requireNonNull(envelope).withMaximum(StateEnvelope.SYNC_MAX_BYTES);this.target=Objects.requireNonNull(target);this.source=Objects.requireNonNull(source);this.external=Objects.requireNonNull(external);
    }
    SyncState load(LanGroup group,Action saveGroup)throws Exception {
        external.load(group);
        SyncState state;
        if(source.exists()) {
            byte[] wire=source.read(),plain=null;
            try { plain=envelope.open(wire);state=SyncState.decode(plain,group.groupId,group.id()); }
            finally { Crypto.wipe(wire);Crypto.wipe(plain); }
        } else {
            if(group.syncInitialized)throw new SecurityException("同期の記録がありません。消去して作成か加入をやり直してください");
            state=new SyncState(group.groupId,group.id());write(group,state);
        }
        if(!group.syncInitialized) {
            group.syncInitialized=true;
            try { saveGroup.run(); }
            catch(Exception e) { group.syncInitialized=false;throw e; }
        }
        return state;
    }
    void save(LanGroup group,SyncState state)throws Exception {
        if(!group.syncInitialized)throw new SecurityException("同期の保存を初期化していません");write(group,state);
    }
    byte[] readEncoded(LanGroup group)throws Exception{
        if(!group.syncInitialized||!source.exists())throw new SecurityException("同期の正本がありません");
        byte[] wire=source.read();try{return envelope.open(wire);}finally{Crypto.wipe(wire);}
    }
    /** 核が正本と照合した平文を借り、保存用の写しだけを包みへ渡す。 */
    void saveEncoded(LanGroup group,SyncState state,byte[] encoded)throws Exception{
        if(!group.syncInitialized||!state.belongsTo(group.groupId,group.id()))throw new SecurityException("同期の保存先が違います");
        envelope.save(encoded.clone(),target);
    }
    private void write(LanGroup group,SyncState state)throws Exception {
        if(!state.belongsTo(group.groupId,group.id()))throw new SecurityException("同期の保存先が違います");
        envelope.save(state.encode(),target);
    }
}
