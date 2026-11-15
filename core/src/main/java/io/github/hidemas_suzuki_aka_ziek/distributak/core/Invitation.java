// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

/** 秘密を toString に出さない。読み取った招待は使い終わったら close する。 */
public final class Invitation implements AutoCloseable {
    private final byte[] address,handshake,admin,totp,group;
    private final int port;
    private boolean closed;
    public Invitation(byte[] address, int port, byte[] handshake, byte[] admin, byte[] totp, byte[] group) {
        if(address==null || (address.length!=4 && address.length!=16)) throw new IllegalArgumentException("IP 番地の長さが違います");
        if(port<1 || port>65535) throw new IllegalArgumentException("UDP の番号が範囲外です");
        Crypto.length(handshake,32);Crypto.length(admin,32);Crypto.length(totp,32);Crypto.length(group,32);
        this.address=address.clone();this.port=port;this.handshake=handshake.clone();this.admin=admin.clone();this.totp=totp.clone();this.group=group.clone();
    }
    public byte[] groupId(){return group.clone();}
    public byte[] adminAddress() { return address.clone(); }
    public int udpPort() { return port; }
    public byte[] handshakePublicKey() { return handshake.clone(); }
    public byte[] adminPublicKey() { return admin.clone(); }
    public synchronized byte[] totpSecret() {
        if(closed) throw new IllegalStateException("招待は閉じています"); return totp.clone();
    }
    @Override public synchronized void close() { closed=true;Crypto.wipe(totp); }
}
