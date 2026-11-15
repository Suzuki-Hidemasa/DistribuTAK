// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import java.nio.ByteBuffer;
import java.util.*;
public class RevokedStoredPeerTest {
    /** 読む側の試験用に、署名した新しい失効の一覧と版だけを保存の中へ入れる。 */
    static byte[] replaceRevocations(LanGroup group,byte[] revokedId)throws Exception{
        byte[] plain=group.encode();
        byte[] next=AdminRecords.list(AdminRecords.Kind.REVOCATIONS,group.groupId,1,LanControllerHarness.CLOCK.millis(),List.of(revokedId),group.administratorSecret).encode();
        var buffer=new java.io.ByteArrayOutputStream();
        try(var in=new java.io.DataInputStream(new java.io.ByteArrayInputStream(plain));var out=new java.io.DataOutputStream(buffer)){
            out.writeInt(in.readInt());out.writeInt(in.readInt());
            for(int i=0;i<4;i++)copyBytes(in,out);
            out.writeLong(in.readLong());for(int i=0;i<3;i++)copyBytes(in,out);
            int records=in.readInt();out.writeInt(records+1);for(int i=0;i<records;i++)copyBytes(in,out);
            out.writeInt(next.length);out.write(next);copyBytes(in,out);
            in.skipNBytes(in.readInt());out.writeInt(next.length);out.write(next);
            out.writeLong(in.readLong());in.readLong();out.writeLong(1);out.write(in.readAllBytes());
        }
        return buffer.toByteArray();
    }
    static void copyBytes(java.io.DataInputStream in,java.io.DataOutputStream out)throws Exception{int length=in.readInt();out.writeInt(length);out.write(in.readNBytes(length));}
    @Test public void revokedPeerCanLoadAndIsForgottenAndSavedAcrossRestart()throws Exception{
        LanControllerHarness.Disk disk;byte[] self;
        try(var f=new LanControllerHarness()){f.create();var g=LanBehaviourWiringTest.group(f);var peer=StoredUpdatesTest.peer(g,71,72,LanControllerHarness.CLOCK.millis());
            f.disk.savePeer(g,peer,new java.net.InetSocketAddress("192.0.2.200",54321));self=g.certificate.encode();
            f.disk.state.value=f.disk.envelope.seal(replaceRevocations(g,Crypto.blake2s(peer.field(0))));disk=f.disk;
        }
        try(var f=new LanControllerHarness(disk)){assertTrue(f.ui.last.text.contains("相手は失効しました"));assertTrue(f.ui.last.running);
            try(var loaded=disk.load(LanControllerHarness.CLOCK)){assertNull(loaded.peerCertificate);assertNull(loaded.peerAddress);assertArrayEquals(self,loaded.certificate.encode());}}
        try(var f=new LanControllerHarness(disk);var loaded=disk.load(LanControllerHarness.CLOCK)){assertTrue(f.ui.last.running);assertNull(loaded.peerCertificate);}
    }
    @Test public void revokedPeerSaveFailureKeepsOldBytesButForgetsInMemory()throws Exception{
        try(var f=new LanControllerHarness()){f.create();var g=LanBehaviourWiringTest.group(f);var peer=StoredUpdatesTest.peer(g,71,72,LanControllerHarness.CLOCK.millis());
            f.disk.savePeer(g,peer,new java.net.InetSocketAddress("192.0.2.200",54321));f.disk.state.value=f.disk.envelope.seal(replaceRevocations(g,Crypto.blake2s(peer.field(0))));
            byte[] old=f.disk.state.value.clone();f.disk.failSave=true;
            try(var loaded=f.disk.load(LanControllerHarness.CLOCK)){assertNull(loaded.peerCertificate);assertArrayEquals(old,f.disk.state.value);}
        }
    }
    @Test public void revokedAndExpiredLocalStateErasesOnStartup()throws Exception{
        LanControllerHarness.Disk disk;
        try(var f=new LanControllerHarness()){f.create();var g=LanBehaviourWiringTest.group(f);
            g.certificate=AdminRecords.certificate(g.groupId,g.certificate.field(0),g.certificate.field(1),g.certificate.field(2),LanControllerHarness.CLOCK.millis()-AdminRecords.CERTIFICATE_LIFETIME_MILLIS,g.administratorSecret);
            f.disk.save(g);f.disk.state.value=f.disk.envelope.seal(replaceRevocations(g,g.id()));disk=f.disk;
        }
        try(var f=new LanControllerHarness(disk)){assertTrue(disk.erased);assertNull(disk.state.value);assertTrue(f.ui.last.text.contains("自分の証明書が無効です。消去しました"));}
    }
}
