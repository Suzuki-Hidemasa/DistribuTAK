// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.UdpEndpoint.CloseReason;
/** 文言ではなく、核の検査結果で保存の扱いを決める。 */
final class StoredCertificateFailure extends SecurityException {
    final CloseReason reason;
    StoredCertificateFailure(CloseReason reason){super("保存した自分の証明書を受け入れられません");this.reason=reason;}
}
