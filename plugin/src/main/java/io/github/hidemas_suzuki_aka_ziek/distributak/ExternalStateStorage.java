// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;

/** 同期と同じ鍵・包みで外来の要約を保存する。初期化の印は両ファイル共通。 */
final class ExternalStateStorage {
    private final StateEnvelope envelope;
    private final StateEnvelope.AtomicTarget target;
    private final SyncStateStorage.Source source;
    ExternalStateStorage(StateEnvelope envelope,StateEnvelope.AtomicTarget target,SyncStateStorage.Source source){this.envelope=envelope.withMaximum(ExternalMarks.MAX_ENVELOPE_BYTES);this.target=target;this.source=source;}
    ExternalMarks load(LanGroup group)throws Exception {
        if(!source.exists()){
            if(group.syncInitialized)throw new SecurityException("外来の印がありません。消去して作成か加入をやり直してください");
            var empty=new ExternalMarks(group.groupId,group.id());write(group,empty);return empty;
        }
        byte[] wire=source.read(),plain=null;
        try{plain=envelope.open(wire);return ExternalMarks.decode(plain,group.groupId,group.id());}
        finally{Crypto.wipe(wire);Crypto.wipe(plain);}
    }
    void save(LanGroup group,ExternalMarks marks)throws Exception {
        if(!group.syncInitialized)throw new SecurityException("同期の保存を初期化していません");write(group,marks);
    }
    private void write(LanGroup group,ExternalMarks marks)throws Exception {
        if(!marks.belongsTo(group.groupId,group.id()))throw new SecurityException("外来の印の保存先が違います");envelope.save(marks.encode(),target);
    }
}
