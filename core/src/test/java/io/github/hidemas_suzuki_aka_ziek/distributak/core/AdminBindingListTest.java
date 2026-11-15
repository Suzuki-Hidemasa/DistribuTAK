// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class AdminBindingListTest {
    final byte[] group=new byte[32],a=AdminRecordsTest.key(1),b=AdminRecordsTest.key(2),identity=AdminRecordsTest.key(3);
    AdminBinding binding(byte[] secret,byte[] person,long version) {
        var proof=AdminControl.keyProof(group,new byte[16],version,person,secret);
        return AdminBinding.bound(proof.administratorKey(),proof.memberId(),proof.encode());
    }
    AdminState state(AdminRecords.Record first) {
        var state=new AdminState(group,Crypto.ed25519Public(a),java.time.Clock.systemUTC(),new InMemoryAdminRecordStore());
        state.bootstrap(first,AdminRecords.signAnchor(first,a));state.acceptRevocations(AdminRecords.initialRevocations(group,100,a));return state;
    }
    @Test void boundProofCanBeCheckedFromListWithoutDirectory() {
        var record=AdminRecords.administrators(group,0,100,List.of(binding(a,identity,0)),a);
        var copy=AdminRecords.decode(record.encode());assertTrue(copy.hasAdminBindings());assertTrue(copy.hasValidSignature());
        assertEquals(AdminBinding.State.BOUND,copy.binding(Crypto.ed25519Public(a)).state());
        assertTrue(Crypto.equal(copy.binding(Crypto.ed25519Public(a)).memberId(),Crypto.blake2s(Crypto.ed25519Public(identity))));
    }
    @Test void keysAndBindingsMustBeOneToOneAndMembersCannotRepeat() {
        assertThrows(IllegalArgumentException.class,()->AdminRecords.administrators(group,0,100,List.of(binding(a,identity,0),binding(a,identity,0)),a));
        assertThrows(IllegalArgumentException.class,()->AdminRecords.administrators(group,0,100,List.of(binding(a,identity,0),binding(b,identity,0)),a));
    }
    @Test void invalidPossessionProofAndWrongGroupAreRejected() {
        var proof=AdminControl.keyProof(group,new byte[16],0,identity,a);byte[] bad=proof.encode();bad[bad.length-1]^=1;
        assertThrows(IllegalArgumentException.class,()->AdminRecords.administrators(group,0,100,List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),bad)),a));
        byte[] other=group.clone();other[0]=1;
        assertThrows(IllegalArgumentException.class,()->AdminRecords.administrators(other,0,100,List.of(binding(a,identity,0)),a));
        var offer=AdminControl.offer(group,new byte[16],proof.memberId(),0,a);
        assertThrows(IllegalArgumentException.class,()->AdminRecords.administrators(group,0,100,List.of(AdminBinding.bound(proof.administratorKey(),proof.memberId(),offer.encode())),a));
    }
    @Test void unknownCannotBeUsedToGrantANewKey() {
        var first=AdminRecords.administrators(group,0,100,List.of(binding(a,identity,0)),a);var state=state(first);
        var next=AdminRecords.administrators(group,1,101,List.of(binding(a,identity,0),AdminBinding.unknown(Crypto.ed25519Public(b))),a);
        assertThrows(SecurityException.class,()->state.acceptAdministrators(next,v->fail()));
        var valid=AdminRecords.administrators(group,1,101,List.of(binding(a,identity,0),binding(b,AdminRecordsTest.key(4),0)),a);
        assertTrue(state.acceptAdministrators(valid,v->fail()));
    }
    @Test void boundCannotBecomeUnknownOrChangeItsMember() {
        var first=AdminRecords.administrators(group,0,100,List.of(binding(a,identity,0)),a);var state=state(first);
        var unknown=AdminRecords.administrators(group,1,101,List.of(AdminBinding.unknown(Crypto.ed25519Public(a))),a);
        assertThrows(SecurityException.class,()->state.acceptAdministrators(unknown,v->fail()));
        var changed=AdminRecords.administrators(group,1,101,List.of(binding(a,b,0)),a);
        assertThrows(SecurityException.class,()->state.acceptAdministrators(changed,v->fail()));
    }
    @Test void unknownExistingKeyCanBecomeBound() {
        var first=AdminRecords.administrators(group,0,100,List.of(AdminBinding.unknown(Crypto.ed25519Public(a))),a);var state=state(first);
        assertTrue(state.acceptAdministrators(AdminRecords.administrators(group,1,101,List.of(binding(a,identity,0)),a),v->fail()));
    }
    @Test void zeroAdministratorsAreRejectedAtCreationAndDecoding()throws Exception {
        assertThrows(IllegalArgumentException.class,()->AdminRecords.administrators(group,1,100,List.of(),a));
        var bytes=new java.io.ByteArrayOutputStream();var out=com.google.protobuf.CodedOutputStream.newInstance(bytes);
        out.writeUInt32(1,2);out.writeByteArray(2,group);out.writeByteArray(3,Crypto.ed25519Public(a));out.writeUInt64(4,1);out.writeUInt64(5,100);
        out.writeUInt32(15,2);out.writeByteArray(16,SignaturePurpose.ADMINISTRATORS.purpose());out.flush();byte[] payload=bytes.toByteArray();
        bytes.reset();out=com.google.protobuf.CodedOutputStream.newInstance(bytes);out.writeByteArray(1,payload);out.writeByteArray(2,SignaturePurpose.ADMINISTRATORS.sign(a,payload));out.flush();
        byte[] wire=bytes.toByteArray();assertThrows(IllegalArgumentException.class,()->AdminRecords.decode(wire));
        var store=new InMemoryAdminRecordStore();store.save(new AdminRecordStore.Snapshot(List.of(wire),new byte[64],null,1,-1));
        assertThrows(SecurityException.class,()->new AdminState(group,Crypto.ed25519Public(a),java.time.Clock.systemUTC(),store).restore());
    }
}
