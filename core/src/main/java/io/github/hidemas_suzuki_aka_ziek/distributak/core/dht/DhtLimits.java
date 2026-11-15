// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/** ADR0030答え66・181の仮の値。模擬と実際のUDPで見直す。 */
public final class DhtLimits {
    private DhtLimits(){}
    public static final int BUCKETS=256,K=20,ALPHA=3;
    public static final int MAX_CANDIDATES=256,MAX_QUERIES=128,MAX_LOOKUPS=4,RPC_RETRIES=1;
    public static final long RPC_NANOS=3_000_000_000L,LOOKUP_NANOS=120_000_000_000L;
    public static final long REFRESH_NANOS=3_600_000_000_000L,RECORD_LIFETIME_MILLIS=86_400_000L;
}
