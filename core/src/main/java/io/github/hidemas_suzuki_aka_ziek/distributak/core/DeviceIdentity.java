// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

public final class DeviceIdentity {
    private DeviceIdentity() {}
    public static byte[] id(byte[] ed25519PublicKey) { Crypto.length(ed25519PublicKey,32); return Crypto.blake2s(ed25519PublicKey); }
    public static byte[] ula(byte[] ed25519PublicKey) {
        byte[] id=id(ed25519PublicKey), address=new byte[16];
        address[0]=(byte)0xfd;System.arraycopy(id,0,address,1,15);return address;
    }
}
