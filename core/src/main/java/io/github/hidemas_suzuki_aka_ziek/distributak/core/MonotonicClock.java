// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.time.*;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * 期限を数える単調時計。署名時刻や証明書の期限には使わない。
 * <p>
 * A monotonic clock for elapsed deadlines, never signing times or certificate validity.
 */
public final class MonotonicClock extends Clock {
    private final LongSupplier nanos;
    private final long origin;
    public MonotonicClock(LongSupplier nanos){this.nanos=Objects.requireNonNull(nanos);origin=nanos.getAsLong();}
    @Override public ZoneId getZone(){return ZoneOffset.UTC;}
    @Override public Clock withZone(ZoneId zone){if(!ZoneOffset.UTC.equals(zone))throw new IllegalArgumentException("UTC only");return this;}
    @Override public long millis(){return (nanos.getAsLong()-origin)/1_000_000L;}
    @Override public Instant instant(){return Instant.ofEpochMilli(millis());}
}
