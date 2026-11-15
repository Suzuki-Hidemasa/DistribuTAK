// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

/** 暗号providerと原子的な保存先を差し替えられる包み。 */
final class StateEnvelope {
    static final int MAX_BYTES=1024*1024,HEADER_BYTES=10;
    static final int SYNC_MAX_BYTES=4194304;
    private static final byte[] DOMAIN="DistribuTAK/android-state/v1".getBytes(StandardCharsets.US_ASCII);
    interface CipherBox {
        Sealed seal(byte[] plain,byte[] aad)throws Exception;
        byte[] open(byte[] iv,byte[] ciphertext,byte[] aad)throws Exception;
    }
    static final class Sealed {
        final byte[] iv,ciphertext;
        Sealed(byte[] iv,byte[] ciphertext){this.iv=iv;this.ciphertext=ciphertext;}
    }
    interface AtomicTarget {
        void begin()throws Exception;
        void write(byte[] bytes)throws Exception;
        void commit()throws Exception;
        void rollback();
    }
    private final CipherBox box;
    private final int maximum;
    StateEnvelope(CipherBox box){this(box,MAX_BYTES);}
    private StateEnvelope(CipherBox box,int maximum){this.box=box;this.maximum=maximum;}
    StateEnvelope withMaximum(int maximum){if(maximum<HEADER_BYTES+12+16)throw new IllegalArgumentException("包みの上限が違います");return new StateEnvelope(box,maximum);}
    private static byte[] header(int ciphertextLength) {
        return ByteBuffer.allocate(HEADER_BYTES).putInt(0x44544b53).put((byte)1).put((byte)12).putInt(ciphertextLength).array();
    }
    byte[] seal(byte[] plain)throws Exception {
        if(plain.length>maximum-HEADER_BYTES-12-16)throw new SecurityException("保存の上限を超えています");
        byte[] head=header(plain.length+16),aad=Crypto.concat(DOMAIN,head);
        Sealed sealed=box.seal(plain,aad);
        try {
            if(sealed.iv.length!=12 || sealed.ciphertext.length!=plain.length+16)throw new SecurityException("包みの長さが違います");
            return Crypto.concat(head,sealed.iv,sealed.ciphertext);
        } finally {Crypto.wipe(aad);Crypto.wipe(sealed.iv);Crypto.wipe(sealed.ciphertext);}
    }
    byte[] open(byte[] wire)throws Exception {
        if(wire.length<HEADER_BYTES+12+16 || wire.length>maximum)throw new SecurityException("包みの長さが違います");
        ByteBuffer input=ByteBuffer.wrap(wire);
        if(input.getInt()!=0x44544b53 || input.get()!=1 || input.get()!=12)throw new SecurityException("包みの版が違います");
        int length=input.getInt();
        if(length!=wire.length-HEADER_BYTES-12)throw new SecurityException("包みの長さが違います");
        byte[] iv=new byte[12],ciphertext=new byte[length];input.get(iv);input.get(ciphertext);
        byte[] aad=Crypto.concat(DOMAIN,Arrays.copyOf(wire,HEADER_BYTES));
        try {return box.open(iv,ciphertext,aad);}
        finally {Crypto.wipe(iv);Crypto.wipe(ciphertext);Crypto.wipe(aad);}
    }
    /** 保存の開始後に失敗した場合は前の記録を残す。wireの所有を受け取る。 */
    static void writeAtomic(byte[] wire,AtomicTarget target)throws Exception {
        boolean started=false;
        try{target.begin();started=true;target.write(wire);target.commit();started=false;}
        finally{try{if(started)target.rollback();}finally{Crypto.wipe(wire);}}
    }
    /** plainの所有を受け取り、成功・失敗のどちらでも消す。 */
    void save(byte[] plain,AtomicTarget target)throws Exception {
        try{writeAtomic(seal(plain),target);}finally{Crypto.wipe(plain);}
    }
}
