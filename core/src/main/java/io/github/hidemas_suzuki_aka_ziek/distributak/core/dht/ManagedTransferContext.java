// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core.dht;

/**
 * 完成した管理用 Transfer の照合に使う文脈。番号や相手を文字列には出さない。
 * <p>
 * Context for matching a complete managed Transfer, without rendering identifiers or peers as strings.
 */
public final class ManagedTransferContext {
    private final DhtId peer,key;
    private final byte[] session,request;
    private final long generation;
    private final DhtWire.TransferKind kind;
    public ManagedTransferContext(DhtId peer,byte[] session,long generation,byte[] request,DhtId key,DhtWire.TransferKind kind) {
        this.kind=java.util.Objects.requireNonNull(kind);
        this.peer=java.util.Objects.requireNonNull(peer);this.key=java.util.Objects.requireNonNull(key);
        if(session==null||session.length!=16||request==null||request.length!=16)throw new IllegalArgumentException("Invalid transfer context");
        this.session=session.clone();this.request=request.clone();this.generation=generation;
    }
    public DhtWire.TransferKind kind(){return kind;}
    public DhtId peer(){return peer;}
    public DhtId key(){return key;}
    public long generation(){return generation;}
    public byte[] requestId(){return request.clone();}
    public byte[] sessionId(){return session.clone();}
    @Override public String toString(){return "Managed transfer context";}
}
