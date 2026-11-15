// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import com.google.protobuf.CodedOutputStream;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.InvitationSchema;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/** checksum は認証ではない。URL の受け渡し先を確かめるのは上位の責務。 */
public final class InvitationUrl {
    private static final String PREFIX="distributak://join#";
    private static final int ADDRESS=InvitationSchema.Invitation.ADMIN_ADDRESS_FIELD_NUMBER;
    private static final int PORT=InvitationSchema.Invitation.UDP_PORT_FIELD_NUMBER;
    private static final int HANDSHAKE=InvitationSchema.Invitation.HANDSHAKE_PUBLIC_KEY_FIELD_NUMBER;
    private static final int ADMIN=InvitationSchema.Invitation.ADMIN_PUBLIC_KEY_FIELD_NUMBER;
    private static final int TOTP=InvitationSchema.Invitation.TOTP_SECRET_FIELD_NUMBER;
    private static final int GROUP=InvitationSchema.Invitation.GROUP_ID_FIELD_NUMBER;
    // 最大: IPv6(18) + port(4) + 32バイト値3個(102)。group_id(34)とchecksumを加えて174バイト。
    private static final int MAX_RAW=174;
    private InvitationUrl() {}
    private static byte[] body(Invitation invitation) {
        byte[] secret=invitation.totpSecret();
        try {
            byte[] address=invitation.adminAddress(),handshake=invitation.handshakePublicKey(),admin=invitation.adminPublicKey();
            int size=CodedOutputStream.computeByteArraySize(ADDRESS,address)+CodedOutputStream.computeUInt32Size(PORT,invitation.udpPort())
                +CodedOutputStream.computeByteArraySize(HANDSHAKE,handshake)+CodedOutputStream.computeByteArraySize(ADMIN,admin)+CodedOutputStream.computeByteArraySize(TOTP,secret)+CodedOutputStream.computeByteArraySize(GROUP,invitation.groupId());
            byte[] body=new byte[size];var out=CodedOutputStream.newInstance(body);
            out.writeByteArray(ADDRESS,address);out.writeUInt32(PORT,invitation.udpPort());out.writeByteArray(HANDSHAKE,handshake);
            out.writeByteArray(ADMIN,admin);out.writeByteArray(TOTP,secret);out.writeByteArray(GROUP,invitation.groupId());out.checkNoSpaceLeft();return body;
        } catch(IOException impossible) { throw new IllegalStateException(impossible); }
        finally { Crypto.wipe(secret); }
    }
    public static String encode(Invitation invitation) {
        byte[] body=body(invitation), raw=Crypto.concat(body,Crypto.blake2s128(body));
        try { return PREFIX+Base64.getUrlEncoder().withoutPadding().encodeToString(raw); }
        finally { Crypto.wipe(body);Crypto.wipe(raw); }
    }
    public static Invitation decode(String url) {
        if(url==null || !url.startsWith(PREFIX) || url.length()>PREFIX.length()+232) throw new IllegalArgumentException("招待 URL の形が違います");
        String encoded=url.substring(PREFIX.length());
        if(!encoded.matches("[A-Za-z0-9_-]+")) throw new IllegalArgumentException("base64url の形が違います");
        byte[] raw=Base64.getUrlDecoder().decode(encoded), body=null, secret=null;
        try {
            if(raw.length<16 || raw.length>MAX_RAW || !Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(encoded)) throw new IllegalArgumentException("base64url が正規形ではありません");
            body=Arrays.copyOf(raw,raw.length-16);
            if(!Crypto.equal(Crypto.blake2s128(body),Arrays.copyOfRange(raw,raw.length-16,raw.length))) throw new SecurityException("招待の checksum が合いません");
            var in=CodedInputStream.newInstance(body); int seen=0,port=0;byte[] address=null,handshake=null,admin=null,group=null;
            while(!in.isAtEnd()) {
                int tag=in.readTag(),field=tag>>>3,wire=tag&7;
                if(field<1 || field>6 || (seen&(1<<field))!=0 || wire!=(field==PORT ? 0 : 2)) throw new IllegalArgumentException("招待に未対応か重複した項目があります");
                seen|=1<<field;
                if(field==ADDRESS) address=in.readByteArray();
                else if(field==PORT) port=in.readUInt32();
                else if(field==HANDSHAKE) handshake=in.readByteArray();
                else if(field==ADMIN) admin=in.readByteArray();
                else if(field==TOTP) secret=in.readByteArray();
                else if(field==GROUP) group=in.readByteArray();
            }
            if(seen!=126) throw new IllegalArgumentException("招待の項目が足りません");
            Invitation invitation=new Invitation(address,port,handshake,admin,secret,group);
            byte[] canonical=body(invitation);
            try {
                if(!Crypto.equal(body,canonical)) { invitation.close();throw new IllegalArgumentException("Protocol Buffers が正規形ではありません"); }
                return invitation;
            } finally { Crypto.wipe(canonical); }
        } catch(IOException e) { throw new IllegalArgumentException("Protocol Buffers が壊れています",e); }
        finally { Crypto.wipe(raw);Crypto.wipe(body);Crypto.wipe(secret); }
    }
}
