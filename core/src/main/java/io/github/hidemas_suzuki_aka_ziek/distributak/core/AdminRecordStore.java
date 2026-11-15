// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.util.ArrayList;
import java.util.List;

/**
 * 実際の保存・Keystore は上位が実装する。save は全体を一度に置き換える。
 * 巻き戻しはこの口では見つけられない。完全性の保護と巻き戻しの検出は保存を作る段で決める。
 */
public interface AdminRecordStore {
    Snapshot load();
    void save(Snapshot snapshot);
    void clear();

    /** 受けた順の一覧（起点・管理者・失効）と URL 管理者の添えた署名。版も検査し直す。 */
    record Snapshot(List<byte[]> records, byte[] anchorSignature, byte[] revocations,
                    long administratorVersion, long revocationVersion) {
        public Snapshot {
            records=copy(records);anchorSignature=anchorSignature.clone();
            revocations=revocations==null ? null : revocations.clone();
        }
        private static List<byte[]> copy(List<byte[]> values) {
            List<byte[]> result=new ArrayList<>();for(byte[] value:values) result.add(value.clone());return List.copyOf(result);
        }
        @Override public List<byte[]> records() { return copy(records); }
        @Override public byte[] anchorSignature() { return anchorSignature.clone(); }
        @Override public byte[] revocations() { return revocations==null ? null : revocations.clone(); }
    }
}
