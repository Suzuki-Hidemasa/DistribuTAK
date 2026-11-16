// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 全体の検証・保管の結果。断片の配送 ACK とは別に扱う。
 * <p>
 * The result of whole-record verification and storage, separate from fragment delivery ACKs.
 */
public enum ManagedTransferResult { ACCEPTED,REJECTED,FAILED }
