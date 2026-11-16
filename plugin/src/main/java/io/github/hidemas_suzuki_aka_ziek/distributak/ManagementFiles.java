// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.io.IOException;

/**
 * state が指す変更しない管理世代だけを読む。
 * <p>
 * Reads only the immutable management generation referenced by state.
 */
interface ManagementFiles {
    long nextGeneration()throws IOException;
    void write(long generation,byte[] wire)throws IOException;
    byte[] read(long generation)throws IOException;
    boolean hasSpace(long bytes);
    void cleanup(long retained)throws IOException;
}
