// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.SyncSchema.ManagementEnvelope;

/**
 * 管理封筒の番号の定義。6 は予約、page_ack は 11 で確定（利用者の決定。04 §4.5）。
 * <p>
 * Management envelope field definitions. Six is reserved and page_ack is fixed at eleven (user decision; 04 §4.5).
 */
public final class ManagementEnvelopeFields {
    public static final int REVOCATION_PAGE=ManagementEnvelope.REVOCATION_PAGE_FIELD_NUMBER,
            DIRECTORY_PAGE=ManagementEnvelope.DIRECTORY_PAGE_FIELD_NUMBER,
            SIGNED_ANNOUNCEMENT=ManagementEnvelope.SIGNED_ANNOUNCEMENT_FIELD_NUMBER,
            DIRECTORY_SUMMARY_PAGE=ManagementEnvelope.DIRECTORY_SUMMARY_PAGE_FIELD_NUMBER,
            ADMIN_CONTROL=ManagementEnvelope.ADMIN_CONTROL_FIELD_NUMBER,
            CERTIFICATE_RENEWAL=ManagementEnvelope.CERTIFICATE_RENEWAL_FIELD_NUMBER,
            REVOCATIONS_RECOVERY_REQUEST=ManagementEnvelope.REVOCATIONS_RECOVERY_REQUEST_FIELD_NUMBER,
            PAGE_ACK=ManagementEnvelope.PAGE_ACK_FIELD_NUMBER;
    private ManagementEnvelopeFields(){}
    /**
     * 管理封筒を一度振り分けるための本体番号。構文が違う入力では0を返す。
     * <p>
     * Returns the body field for a single management-envelope dispatch, or zero for malformed input.
     */
    public static int field(byte[] wire){
        try{return ManagementWire.unwrap(wire).field();}
        catch(java.io.IOException|IllegalArgumentException invalid){return 0;}
    }
    public static int[] supported(){return new int[]{REVOCATION_PAGE,DIRECTORY_PAGE,SIGNED_ANNOUNCEMENT,
            DIRECTORY_SUMMARY_PAGE,ADMIN_CONTROL,CERTIFICATE_RENEWAL,REVOCATIONS_RECOVERY_REQUEST,PAGE_ACK};}
}
