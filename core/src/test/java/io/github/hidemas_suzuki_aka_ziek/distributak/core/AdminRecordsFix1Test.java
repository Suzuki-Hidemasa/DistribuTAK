// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.time.*;
import java.util.*;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.ByteString;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.proto.AdminRecordSchema;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static io.github.hidemas_suzuki_aka_ziek.distributak.core.AdminRecords.Kind.*;

class AdminRecordsFix1Test {
    final AdminStateTest f=new AdminStateTest();
    static byte[] id(int value) { byte[] out=new byte[32];out[0]=(byte)(value>>>16);out[1]=(byte)(value>>>8);out[2]=(byte)value;return out; }
    static List<byte[]> ids(int first, int end) {
        List<byte[]> out=new ArrayList<>();for(int i=first;i<end;i++) out.add(id(i));return out;
    }
    @Test void removedSignerRequiresStrictlyGreaterRevocationVersionIncludingAfterRestore() {
        byte[] member=Crypto.blake2s(Crypto.ed25519Public(f.identity));
        var held=f.revocations(1,f.now,List.of(member),f.b);
        // signer の項目が先に比較されるので、公開鍵の大きい側を残す。
        byte[] removed=f.b, remaining=f.a;
        if(AdminRecords.compareBytes(f.ap,f.bp)<0) {
            removed=f.a;remaining=f.b;
            held=f.revocations(1,f.now,List.of(member),removed);
        }
        var byteWinner=f.revocations(1,f.now,List.of(),remaining);
        assertTrue(AdminRecords.compare(byteWinner,held)>0);
        var later=f.revocations(1,f.now+1,List.of(),remaining);
        for(boolean restart:new boolean[]{false,true}) {
            var store=new InMemoryAdminRecordStore();var state=f.fresh(store);
            state.acceptRevocations(held);
            state.acceptAdministrators(f.admins(1,f.now,List.of(Crypto.ed25519Public(remaining)),remaining),v->fail());
            if(restart) { state=new AdminState(f.group,f.ap,f.clock,store);state.restore(); }
            assertFalse(state.acceptRevocations(later));assertFalse(state.acceptRevocations(byteWinner));
            assertTrue(AdminRecords.contains(state.revocations().entries(),member));
            assertTrue(state.acceptRevocations(f.revocations(2,f.now,List.of(),remaining)));
            assertTrue(state.revocations().entries().isEmpty());
        }
    }
    @Test void ownListSignatureCannotBeUsedAsAttachedAnchorSignature() {
        var state=new AdminState(f.group,f.ap,f.clock,new InMemoryAdminRecordStore());
        var first=f.admins(0,f.now,List.of(f.ap),f.a);
        assertThrows(SecurityException.class,()->state.bootstrap(first,first.signature()));
        assertArrayEquals(anchor(first,f.a),AdminRecords.signAnchor(first,f.a));
        state.bootstrap(first,AdminRecords.signAnchor(first,f.a));
    }
    @Test void issuanceFiveMinutesAheadIsAcceptedButOneMillisecondFurtherIsNot() {
        var state=f.fresh();byte[] binding=SignaturePurpose.identityProof(f.identity,f.group,Crypto.x25519Public(f.handshake));
        state.verifyCertificate(f.certificate(f.a,f.now+300000,binding),Crypto.x25519Public(f.handshake));
        assertThrows(SecurityException.class,()->state.verifyCertificate(f.certificate(f.a,f.now+300001,binding),Crypto.x25519Public(f.handshake)));
    }
    @Test void expiryMinusOnePassesAndExpiryItselfFails() {
        var cert=f.certificate();byte[] peer=Crypto.x25519Public(f.handshake);
        for(long delta:new long[]{-1,0}) {
            var state=new AdminState(f.group,f.ap,Clock.fixed(Instant.ofEpochMilli(cert.expiresAt()+delta),ZoneOffset.UTC),new InMemoryAdminRecordStore());
            var first=f.admins(0,f.now,List.of(f.ap),f.a);
            // この試験は期限の端だけを比べる。添えた署名は実装の新しい口に追随する。
            state.bootstrap(first,anchor(first,f.a));state.acceptRevocations(AdminRecords.initialRevocations(f.group,f.now,f.a));
            if(delta<0) state.verifyCertificate(cert,peer);
            else assertThrows(SecurityException.class,()->state.verifyCertificate(cert,peer));
        }
    }
    static byte[] anchor(AdminRecords.Record first, byte[] secret) {
        return Crypto.sign(secret,Crypto.concat("DistribuTAK/anchor/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII),first.signedBytes()));
    }
    @Test void rejectsNoncanonicalScalarAndIdentityAndZeroPublicKeys() throws Exception {
        byte[] message={1,2,3},sig=highScalarSignature(Crypto.sign(f.a,message));
        assertFalse(Crypto.verify(f.ap,message,sig));
        byte[] identity=new byte[32],trivial=new byte[64];identity[0]=1;trivial[0]=1;
        assertFalse(Crypto.verify(identity,message,trivial));assertFalse(Crypto.verify(new byte[32],message,trivial));
        var valid=f.revocations(1,f.now,List.of(),f.a);
        var malformed=AdminRecords.decode(AdminRecordsTest.envelope(valid.signedBytes(),highScalarSignature(valid.signature())));
        assertThrows(SecurityException.class,()->malformed.verify(REVOCATIONS,f.group,List.of(f.ap)));
        for(byte[] point:List.of(identity,new byte[32])) {
            byte[] payload=AdminRecordSchema.RevocationList.parseFrom(valid.signedBytes()).toBuilder()
                    .setSigner(ByteString.copyFrom(point)).build().toByteArray();
            var forged=AdminRecords.decode(AdminRecordsTest.envelope(payload,trivial));
            assertThrows(SecurityException.class,()->forged.verify(REVOCATIONS,f.group,List.of(point)));
        }
    }
    static byte[] highScalarSignature(byte[] signature) {
        byte[] result=signature.clone(), scalar=new byte[32];
        for(int i=0;i<32;i++) scalar[31-i]=signature[32+i];
        var order=BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
        byte[] highS=new BigInteger(1,scalar).add(order).toByteArray();
        Arrays.fill(result,32,64,(byte)0);for(int i=0;i<highS.length;i++) result[32+i]=highS[highS.length-1-i];
        return result;
    }
    static byte[] listWire(AdminRecords.Kind kind, List<byte[]> entries, AdminStateTest f) throws Exception {
        var bytes=new ByteArrayOutputStream();var out=CodedOutputStream.newInstance(bytes);
        out.writeUInt32(1,kind.ordinal()+1);out.writeByteArray(2,f.group);out.writeByteArray(3,f.ap);
        out.writeUInt64(4,1);out.writeUInt64(5,f.now);
        for(byte[] entry:entries) out.writeByteArray(6,entry);
        out.flush();byte[] payload=bytes.toByteArray();return AdminRecordsTest.envelope(payload,Crypto.sign(f.a,payload));
    }
    @Test void maximumEntriesRoundTripAndGenerationAndDecodeRejectOneMore() throws Exception {
        var maximum=f.revocations(1,f.now,ids(0,65536),f.a);
        var decoded=AdminRecords.decode(maximum.encode());assertEquals(65536,decoded.entries().size());
        assertArrayEquals(maximum.encode(),decoded.encode());
        assertThrows(IllegalArgumentException.class,()->f.revocations(1,f.now,ids(0,65537),f.a));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(listWire(REVOCATIONS,ids(0,65537),f)));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(new byte[AdminRecords.MAX_RECORD_BYTES+1]));
        var state=f.fresh();assertTrue(state.acceptRevocations(decoded));
    }
    @Test void noAdministratorsRejectedOnGenerationDecodeAndReissue() {
        assertThrows(IllegalArgumentException.class,()->f.admins(1,f.now,List.of(),f.a));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(listWire(ADMINS,List.of(),f)));
        var state=f.fresh();var previous=state.administrators();var own=f.admins(1,f.now,List.of(f.bp),f.a);
        state.acceptAdministrators(f.admins(1,f.now,List.of(f.ap),f.b),v->fail());
        assertThrows(IllegalArgumentException.class,()->state.reissue(previous,own,f.a));
        assertEquals(1,state.administrators().version());assertArrayEquals(f.ap,state.administrators().entries().get(0));
    }
    @Test void neverOwnedGroupKeyAcceptsMinusOneCurrentVersion() {
        var wrapped=GroupKeyEnvelope.wrap(f.group,id(99),Crypto.x25519Public(f.handshake),0,f.now,id(100),f.a);
        try(var opened=f.fresh().openGroupKey(wrapped,id(99),f.handshake,-1)) { assertArrayEquals(id(100),opened.copy()); }
    }
    @Test void genuineDisconnectedChainHasDifferentTypeFromForgedOrWrongGroupRecords() throws Exception {
        var state=f.fresh();var disconnected=f.admins(1,f.now,List.of(f.ap,f.cp),f.c);
        assertThrowsExactly(AdminState.ChainDisconnectedException.class,()->state.acceptAdministrators(disconnected,v->fail()));
        byte[] forged=disconnected.encode();forged[forged.length-1]^=1;
        // 項目7の所持証明より先に、decodeで一覧の署名を断る。
        assertThrowsExactly(SecurityException.class,()->AdminRecords.decode(forged));
        var otherGroup=AdminRecords.list(ADMINS,id(91),1,f.now,List.of(f.ap),f.a);
        assertThrowsExactly(SecurityException.class,()->state.acceptAdministrators(otherGroup,v->fail()));
        var initial=f.admins(0,f.now,List.of(f.ap,f.bp),f.a);
        var joining=new AdminState(f.group,f.ap,f.clock,new InMemoryAdminRecordStore());
        assertThrowsExactly(AdminState.ChainDisconnectedException.class,()->joining.join(List.of(initial,disconnected),
                AdminRecords.signAnchor(initial,f.a),AdminRecords.initialRevocations(f.group,f.now,f.a)));
        assertThrows(IllegalStateException.class,joining::administrators);
    }
    @Test void largeReissueAddsAndRemovesEntriesWithinFiveSeconds() {
        var state=f.fresh();var previous=f.revocations(0,f.now,ids(0,65536),f.a);
        // 自分は0を外して65536を足す。勝った側は65535を外して70000を足す。
        var own=f.revocations(1,f.now,ids(1,65537),f.a);
        List<byte[]> winnerIds=ids(0,65535);winnerIds.add(id(70000));
        state.acceptRevocations(previous);state.acceptRevocations(f.revocations(1,f.now+1,winnerIds,f.b));
        long start=System.nanoTime();
        var result=assertTimeout(Duration.ofSeconds(5),()->state.reissue(previous,own,f.a));
        System.out.printf(Locale.ROOT,"65536項目の出し直し: %.1f ms%n",(System.nanoTime()-start)/1_000_000.0);
        assertEquals(65536,result.entries().size());assertFalse(result.hasEntry(id(0)));assertFalse(result.hasEntry(id(65535)));
        assertTrue(result.hasEntry(id(1)));assertTrue(result.hasEntry(id(65534)));assertTrue(result.hasEntry(id(65536)));assertTrue(result.hasEntry(id(70000)));
        assertEquals(2,result.version());state.acceptRevocations(result);
        // 失効の検索でも毎回の一覧の写しと並べ直しを避ける。
        var certificate=f.certificate();byte[] peer=Crypto.x25519Public(f.handshake);
        assertTimeout(Duration.ofSeconds(5),()->{ for(int i=0;i<100;i++) state.verifyCertificate(certificate,peer); });
    }
    @Test void revocationOverflowHasDedicatedTypeAndDoesNotDiscardAnyEntries() {
        var state=f.fresh();var previous=state.revocations();var own=f.revocations(1,f.now,List.of(id(65536)),f.a);
        var full=f.revocations(1,f.now+1,ids(0,65536),f.b);state.acceptRevocations(full);
        assertThrowsExactly(AdminRecords.RevocationLimitException.class,()->state.reissue(previous,own,f.a));
        assertArrayEquals(full.encode(),state.revocations().encode());
        assertTrue(state.revocations().hasEntry(id(0)));assertTrue(state.revocations().hasEntry(id(65535)));
        assertEquals(65536,state.revocations().entries().size());
    }
}
