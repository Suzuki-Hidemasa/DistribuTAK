// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 構造検証後の管理記録を受け取る口。権限・版の検査と保管は実装側が行う。
 * <p>
 * A sink for structurally verified managed records; implementations check authority and version and store the record.
 */
@FunctionalInterface
public interface ManagedTransferSink {
    ManagedTransferResult accept(ManagedTransferContext context,ManagedDhtRecord record);
    /**
     * 予約済みの組立が始まったことを通知する。拒否された最初の断片では呼ばない。
     * <p>
     * Reports that a reserved assembly has started, excluding rejected first fragments.
     */
    default void started(DhtId peer,byte[] session,long generation,DhtWire.TransferKind kind,byte[] request,long startedNanos) {}
    /**
     * 種類・セッション・世代と全体の結果を通知する。STORE_RESULT の送信は呼び出し側が後で行う。
     * <p>
     * Reports the kind, session, generation and whole-record result; the caller sends STORE_RESULT separately later.
     */
    default void completed(DhtId peer,byte[] session,long generation,DhtWire.TransferKind kind,byte[] request,ManagedTransferResult result) {}
}
