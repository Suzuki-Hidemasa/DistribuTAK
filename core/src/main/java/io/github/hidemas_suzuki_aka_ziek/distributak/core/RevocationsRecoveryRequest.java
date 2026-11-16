// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import com.google.protobuf.CodedInputStream;
import java.io.IOException;
import java.util.Arrays;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.ManagementWire.*;

/**
 * 限定回復の専用要求。版は uint64 のビット列として保持し、比較には符号なし比較を使う。
 * <p>
 * Dedicated limited-recovery request. Versions retain uint64 bits and use unsigned comparison.
 */
public final class RevocationsRecoveryRequest {
    public static final int ENVELOPE_FIELD=ManagementEnvelopeFields.REVOCATIONS_RECOVERY_REQUEST;
    private final byte[] group,operation,digest;
    private final long version;
    public RevocationsRecoveryRequest(byte[] group,byte[] operation,long version,byte[] digest){
        Crypto.length(group,32);Crypto.length(operation,16);Crypto.length(digest,32);
        this.group=group.clone();this.operation=operation.clone();this.version=version;this.digest=digest.clone();
    }
    public byte[] group(){return group.clone();}
    public byte[] operationId(){return operation.clone();}
    public long requiredVersion(){return version;}
    public byte[] targetDigest(){return digest.clone();}
    public byte[] encode(){return write(out->{out.writeUInt32(1,1);out.writeByteArray(2,group);out.writeByteArray(3,operation);
        out.writeUInt64(4,version);out.writeByteArray(5,digest);});}
    public byte[] envelope(){return wrap(ENVELOPE_FIELD,encode());}
    public static RevocationsRecoveryRequest decode(byte[] wire){
        if(wire==null||wire.length<1||wire.length>128)throw invalid();
        try{
            var in=CodedInputStream.newInstance(wire);if(number(in,1,1)!=1)throw invalid();
            byte[] group=bytes(in,2),operation=bytes(in,3);tag(in,4,0);long version=in.readUInt64();
            var result=new RevocationsRecoveryRequest(group,operation,version,bytes(in,5));
            if(!in.isAtEnd()||!Arrays.equals(wire,result.encode()))throw invalid();return result;
        }catch(IOException malformed){throw invalid();}
    }
    public static RevocationsRecoveryRequest decodeEnvelope(byte[] wire){
        try{
            var body=unwrap(wire);if(body.field()!=ENVELOPE_FIELD)throw invalid();var result=decode(body.data());
            if(!Arrays.equals(wire,result.envelope()))throw invalid();return result;
        }catch(IOException malformed){throw invalid();}
    }
    @Override public String toString(){return "Revocations recovery request";}
}
