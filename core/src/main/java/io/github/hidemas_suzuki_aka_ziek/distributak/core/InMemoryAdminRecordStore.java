// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

/** PC の試験用。Snapshot は配列を写すため、呼び出し元と変更を共有しない。 */
public final class InMemoryAdminRecordStore implements AdminRecordStore {
    private Snapshot snapshot;
    @Override public synchronized Snapshot load() { return snapshot; }
    @Override public synchronized void save(Snapshot snapshot) { this.snapshot=snapshot; }
    @Override public synchronized void clear() { snapshot=null; }
}
