// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminState;
import java.util.Objects;

/**
 * {@link AdminState} を {@link TrustedAdmins} として見せる。記録を受けても、相手・名簿・保存は動かさない。
 * <p>
 * Presents an {@link AdminState} as {@link TrustedAdmins}. Receiving a record moves no peer, roster or storage.
 */
public final class AdminStateTrust implements TrustedAdmins {
    private final AdminState state;
    /**
     * @param state 信頼済みの管理状態。The trusted administration state.
     */
    public AdminStateTrust(AdminState state){this.state=Objects.requireNonNull(state);}
    @Override public AdminRecords.Record latest(){return state.administrators();}
    @Override public AdminRecords.Record at(long version){return state.administratorsAt(version);}
    @Override public boolean continuesChain(AdminRecords.Record candidate){return state.continuesChain(candidate);}
}
