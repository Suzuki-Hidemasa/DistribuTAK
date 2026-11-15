// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

/** 利用者の位置や名前を参照しない、柵の確認専用のCoT。 */
final class CotFixture {
    private CotFixture(){}
    static byte[] xml(long now){
        String time=Instant.ofEpochMilli(now).toString(),stale=Instant.ofEpochMilli(now+300000).toString();
        return ("<event version=\"2.0\" uid=\""+CotPort.FIXTURE_UID+"\" type=\"a-f-G-U-C\" how=\"h-e\" time=\""+time+"\" start=\""+time+"\" stale=\""+stale
                +"\"><point lat=\"0\" lon=\"0\" hae=\"9999999\" ce=\"9999999\" le=\"9999999\"/><detail><contact callsign=\"DistribuTAK Fence Test\"/></detail></event>").getBytes(StandardCharsets.UTF_8);
    }
}
