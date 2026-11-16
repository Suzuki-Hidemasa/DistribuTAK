// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.KeyAnnouncement;

/**
 * 管理記録が指す本体を読む口。検証器は取得した本体を改めて検査する。相手や名簿を登録しない。
 * <p>
 * Read access to bodies referenced by managed records. The verifier rechecks returned bodies and registers no peers or roster.
 */
public interface ManagedDependencies {
    /** 署名対象の digest で告知を読む。未取得なら null。 / Reads an announcement by signed-payload digest, or null if missing. */
    KeyAnnouncement announcement(byte[] digest);
    /** 版と署名対象の digest で失効本体を読む。未取得なら null。 / Reads a revocation body by version and signed-payload digest, or null if missing. */
    AdminRecords.Record revocations(long version,byte[] digest);
}
