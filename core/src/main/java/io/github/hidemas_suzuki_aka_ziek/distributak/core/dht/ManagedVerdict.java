// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 管理用 DHT 記録の権限・版・競合の判定結果（04 §4.5）。受け取った内容は持たず、種類と、足りない版だけ持つ。
 * ACCEPTED・DUPLICATE・OLD・INVALID は STORE の答え（{@link DhtWire.StoreStatus}）に対応する。
 * NEEDS_VERSION・NEEDS_ANNOUNCEMENT は内部の保留で、通信の答えには出さない。
 * <p>
 * The verdict on authority, version and conflicts of a managed DHT record (04 §4.5). It holds no received content,
 * only the kind and the version still missing. ACCEPTED, DUPLICATE, OLD and INVALID correspond to STORE answers
 * ({@link DhtWire.StoreStatus}). NEEDS_VERSION and NEEDS_ANNOUNCEMENT are internal pending states and never appear on the wire.
 *
 * @param status 判定の種類。The kind of verdict.
 * @param neededVersion NEEDS_VERSION のとき、先に取りたい管理者一覧の版。それ以外は 0。For NEEDS_VERSION, the administrator list version to fetch first; 0 otherwise.
 */
public record ManagedVerdict(Status status,long neededVersion) {
    /** 判定の種類。 / The kinds of verdict. */
    public enum Status {
        /** 受け入れる。 / Accept. */ ACCEPTED,
        /** すでに同じものを持っている。 / The same record is already held. */ DUPLICATE,
        /** 手元のものより古いか、順位が下。 / Older than, or ranked below, what is held. */ OLD,
        /** 規則に反する。 / Violates a rule. */ INVALID,
        /** 先に管理者一覧の版が要る（保留）。 / An administrator list version is needed first (pending). */ NEEDS_VERSION,
        /** 先に告知が要る（保留）。 / An announcement is needed first (pending). */ NEEDS_ANNOUNCEMENT
    }
    static final ManagedVerdict ACCEPTED=new ManagedVerdict(Status.ACCEPTED,0),DUPLICATE=new ManagedVerdict(Status.DUPLICATE,0),
            OLD=new ManagedVerdict(Status.OLD,0),INVALID=new ManagedVerdict(Status.INVALID,0),
            NEEDS_ANNOUNCEMENT=new ManagedVerdict(Status.NEEDS_ANNOUNCEMENT,0);
    static ManagedVerdict needsVersion(long version){return new ManagedVerdict(Status.NEEDS_VERSION,version);}
}
