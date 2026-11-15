// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

public final class DiscoveryRejected extends IllegalArgumentException {
    private final DiscoveryStatus status;
    DiscoveryRejected(DiscoveryStatus status){super("発見記録を受け付けられません");this.status=status;}
    public DiscoveryStatus status(){return status;}
}
