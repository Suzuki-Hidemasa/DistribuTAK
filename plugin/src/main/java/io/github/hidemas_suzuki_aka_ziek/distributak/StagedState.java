// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

/** 加入の結果を仮に包み、核の加入が成功したあとだけ本体へ原子的に移す。 */
final class StagedState implements LanRuntime.Pending {
    interface Read {byte[] get()throws Exception;}
    private final Read read;
    private final StateEnvelope envelope;
    private final byte[] digest;
    private boolean committed;
    private final LanController.Action delete;
    private final StateEnvelope.AtomicTarget target;
    StagedState(StateEnvelope envelope,byte[] plain,StateEnvelope.AtomicTarget temporary,Read read,
                LanController.Action delete,StateEnvelope.AtomicTarget target)throws Exception {
        this.read=read;this.delete=delete;this.target=target;this.envelope=envelope;digest=Crypto.blake2s(plain);
        try{envelope.save(plain,temporary);}catch(Exception e){delete.run();throw e;}
    }
    public void commit()throws Exception {
        byte[] wire=read.get(),plain=null;
        try {
            plain=envelope.open(wire);
            if(!Crypto.equal(digest,Crypto.blake2s(plain)))throw new SecurityException("仮の保存の中身が違います");
            StateEnvelope.writeAtomic(wire,target);wire=null;committed=true;delete.run();
        }finally{Crypto.wipe(wire);Crypto.wipe(plain);}
    }
    boolean committed(){return committed;}
    public void abort()throws Exception {delete.run();}
}
