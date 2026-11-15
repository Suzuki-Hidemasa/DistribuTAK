// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 経路表にいる端末の「番地と握手の鍵」を返す口（核C2）。NODES の返事に載せるために使う。
 * 番地のない相手は null を返し、返事に載せない。返す値は握手のための公開の値だけ。
 */
@FunctionalInterface
public interface DhtContactDirectory {
    DhtWire.NodeContact contact(DhtId id);
}
