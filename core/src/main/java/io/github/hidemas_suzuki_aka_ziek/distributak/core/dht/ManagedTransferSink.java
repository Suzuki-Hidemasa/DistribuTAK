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
     * 全体の結果だけを通知する。STORE_RESULT の送信は呼び出し側が後で行う。
     * <p>
     * Reports only the whole-record result; the caller sends STORE_RESULT separately later.
     */
    default void completed(DhtId peer,byte[] request,ManagedTransferResult result) {}
}
