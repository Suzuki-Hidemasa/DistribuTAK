// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import java.util.Objects;

/** 紹介された番号。番地や握手の状態は配送のアダプターで管理する。所属の証拠ではない。 */
public final class Contact {
    private final DhtId id;
    public Contact(DhtId id){this.id=Objects.requireNonNull(id);}
    public DhtId id(){return id;}
    @Override public String toString(){return "DHT contact";}
}
