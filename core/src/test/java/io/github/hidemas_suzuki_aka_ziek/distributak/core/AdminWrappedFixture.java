// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

/**
 * 別パッケージの試験が包まれた鍵の記録を作るための試料。製品のコードからは使わない。
 * <p>
 * Fixture for tests in other packages to build a wrapped-key record. Not used by product code.
 */
public final class AdminWrappedFixture {
    private AdminWrappedFixture() {}
    /** 包まれた鍵の記録を作る。 / Builds a wrapped-key record. */
    public static AdminRecords.Record wrapped(byte[] group, long version, long signedAt, byte[] recipient,
                                              byte[] handshake, byte[] enc, byte[] ciphertext, byte[] adminSecret) {
        return AdminRecords.wrapped(group,version,signedAt,recipient,handshake,enc,ciphertext,adminSecret);
    }
}
