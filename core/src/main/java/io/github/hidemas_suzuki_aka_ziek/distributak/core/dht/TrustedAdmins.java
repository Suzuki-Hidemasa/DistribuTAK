// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;

/**
 * 手元が信頼している管理者一覧の鎖を、読むだけで使う口（04 §4.5）。管理用 DHT 記録の検査は、鎖の規則を自分で書かず、
 * この口を通して使う。見るだけで、状態も保存も変えない。
 * <p>
 * A read-only view of the trusted administrator list chain held locally (04 §4.5). The managed DHT record check uses it
 * instead of rewriting the chain rules. It only looks; neither state nor storage changes.
 */
public interface TrustedAdmins {
    /** 信頼済みの最新の管理者一覧。 / The latest trusted administrator list. */
    AdminRecords.Record latest();
    /** 指定の版の信頼済みの一覧。持っていなければ null。 / The trusted list of the given version, or null when not held. */
    AdminRecords.Record at(long version);
    /**
     * 候補が、直前の信頼済みの版から鎖でつながるか。最新と同じ版か、その次の版だけを調べる。
     * <p>
     * Whether the candidate chains from the directly preceding trusted version. Only the latest version or the next one is examined.
     */
    boolean continuesChain(AdminRecords.Record candidate);
}
