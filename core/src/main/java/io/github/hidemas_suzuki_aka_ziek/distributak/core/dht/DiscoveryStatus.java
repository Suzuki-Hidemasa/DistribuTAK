// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/** ACCEPTEDとDUPLICATEは拒否ではない。値や身元は理由の中へ入れない。 */
public enum DiscoveryStatus {
    ACCEPTED,DUPLICATE,INVALID,EXPIRED,CAPACITY,SENDER_MISMATCH,OLD_VERSION,CONFLICT,REVOKED
}
