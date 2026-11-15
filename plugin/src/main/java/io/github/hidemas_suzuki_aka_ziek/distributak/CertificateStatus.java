// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
final class CertificateStatus {
    private CertificateStatus(){}
    static String text(long expires,long now,int renewals){
        if(now>=expires)return "証明書 期限切れ（入り直しが必要）";
        long remaining=expires-Math.max(0,now),day=86_400_000L;
        return "証明書 残り "+(remaining/day+(remaining%day==0?0:1))+" 日（自動更新 "+renewals+" 回）";
    }
}
