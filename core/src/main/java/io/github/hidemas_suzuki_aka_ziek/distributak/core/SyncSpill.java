// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

/** worker専用の退避口。実装は暗号化して内部領域へ置く。引数は借り物。 */
public interface SyncSpill extends AutoCloseable {
    boolean put(byte[] key,byte[] plaintext);
    /** nullは欠落/破損を表す。空のページとして採用してはいけない。 */
    byte[] get(byte[] key);
    void remove(byte[] key);
    void clear();
    long bytes();
    int files();
    @Override default void close(){clear();}
}
