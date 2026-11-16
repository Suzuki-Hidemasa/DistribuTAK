// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 管理用 DHT 記録を受け付けなかった理由。今は形・鍵・署名の違反だけ。権限・版・競合などは、後の検査で足す。
 * <p>
 * Why a managed DHT record was not accepted. For now only shape, key and signature violations; authority, version and
 * conflict reasons are added by later checks.
 */
public enum ManagedStatus {
    /** 形・鍵・署名・内側との一致が違う。 / The shape, key, signature or agreement with the inner record is wrong. */
    INVALID
}
