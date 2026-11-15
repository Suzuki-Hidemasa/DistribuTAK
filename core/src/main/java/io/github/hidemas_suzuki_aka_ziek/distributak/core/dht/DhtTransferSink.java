// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 大きな転送（最大3MiB）で受け終わって、BLAKE2sの照合も通ったデータの渡し先（核C2）。
 * 第12段の本番は渡し先をつながない（Transfer は捨てて「未対応」と数える）。
 * 渡し先を決めるのは別の決定（法令の確認を含む）で、受けたデータは発見の記録の表にも FIND_VALUE の答えにも載せない。
 * 例外を投げても転送の処理には影響しない。
 */
@FunctionalInterface
public interface DhtTransferSink {
    void accept(DhtId peer,DhtWire.TransferKind kind,byte[] data);
}
