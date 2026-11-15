// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.time.Instant;
import java.nio.charset.StandardCharsets;

/** 内部削除の対象を、公開CoTのlinkへ入れる。 */
final class CotImportXml {
    private CotImportXml(){}
    private static String attribute(String value){return value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;").replace("'","&apos;");}
    static byte[] deletion(String target,long now){
        String time=Instant.ofEpochMilli(now).toString(),stale=Instant.ofEpochMilli(now+300000).toString();
        return ("<event version=\"2.0\" uid=\"distributak-internal-deletion-v1\" type=\"t-x-d-d\" how=\"m-g\" time=\""+time+"\" start=\""+time+"\" stale=\""+stale
                +"\"><point lat=\"0\" lon=\"0\" hae=\"9999999\" ce=\"9999999\" le=\"9999999\"/><detail><link uid=\""+attribute(target)+"\" relation=\"none\" type=\"none\"/><__forcedelete/></detail></event>").getBytes(StandardCharsets.UTF_8);
    }
}
