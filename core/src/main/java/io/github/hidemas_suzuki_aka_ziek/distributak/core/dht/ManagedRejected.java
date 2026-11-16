// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 管理用 DHT 記録を断ったときの例外。受け取った内容は書かず、理由の種類だけ持つ。
 * <p>
 * Thrown when a managed DHT record is refused. It carries only the kind of reason, never the received content.
 */
public final class ManagedRejected extends IllegalArgumentException {
    private static final long serialVersionUID=1L;
    private final ManagedStatus status;
    ManagedRejected(ManagedStatus status) {
        super("管理記録を受け付けられません");
        this.status=status;
    }
    /** 断った理由。 / The reason for the refusal. */
    public ManagedStatus status(){return status;}
}
