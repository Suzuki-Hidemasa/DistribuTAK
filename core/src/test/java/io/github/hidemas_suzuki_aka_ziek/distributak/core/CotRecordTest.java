// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class CotRecordTest {
    static final long NOW=Instant.parse("2026-11-12T00:00:00Z").toEpochMilli();
    static byte[] id(int value) { byte[] id=new byte[32];id[0]=(byte)value;return id; }
    static byte[] xml(String uid,long stale) {
        return ("<event version=\"2.0\" uid=\""+uid+"\" type=\"a-f-G\" time=\"2026-11-12T00:00:00Z\" start=\"2026-11-12T00:00:00Z\" stale=\""+Instant.ofEpochMilli(stale)+"\" how=\"h-e\"><point lat=\"0\" lon=\"0\" hae=\"9999999\" ce=\"9999999\" le=\"9999999\"/><detail/></event>").getBytes(StandardCharsets.UTF_8);
    }
    static CotRecord record(long time,int author,int hop) {
        return CotRecord.record("test",time,id(author),NOW+60000,xml("test",NOW+60000),hop);
    }
    @Test void versionUsesTimeThenUnsignedAuthor() {
        assertTrue(record(NOW+1,0,1).compareForWinner(record(NOW,255,1))>0);
        assertTrue(record(NOW,255,1).compareForWinner(record(NOW,127,1))>0);
    }
    @Test void hashIncludesExactXmlAndKindInSpecifiedLengthDelimitedFormat() {
        var item=record(NOW,1,1);byte[] uid="test".getBytes(StandardCharsets.UTF_8),xml=item.xml();
        byte[] prefix="DTK-SYNC-RECORD-v1\0".getBytes(StandardCharsets.US_ASCII);
        var bytes=ByteBuffer.allocate(prefix.length+1+4+uid.length+8+32+8+4+xml.length);
        bytes.put(prefix).put((byte)1).putInt(uid.length).put(uid).putLong(NOW).put(id(1));
        bytes.putLong(NOW+60000).putInt(xml.length).put(xml);
        assertArrayEquals(Crypto.blake2s(bytes.array()),item.hash());
        var deleted=CotRecord.tombstone("test",NOW,id(1),1);
        assertFalse(Arrays.equals(item.hash(),deleted.hash()));
        int expected=-Arrays.compareUnsigned(item.hash(),deleted.hash());
        assertEquals(Integer.signum(expected),Integer.signum(item.compareForWinner(deleted)));
    }
    @Test void hopDoesNotChangeHashAndSixteenCannotBeRelayed() {
        var item=record(NOW,1,1);var relayed=item.relay();
        assertEquals(2,relayed.hop());assertArrayEquals(item.hash(),relayed.hash());
        assertTrue(item.sameRecord(relayed));
        assertThrows(IllegalArgumentException.class,()->record(NOW,1,16).relay());
        assertThrows(IllegalArgumentException.class,()->record(NOW,1,17));
    }
    @Test void returnedArraysCannotChangeTheRecord() {
        var item=record(NOW,1,1);byte[] expected=item.hash();
        Arrays.fill(item.hash(),(byte)0);Arrays.fill(item.author(),(byte)0);Arrays.fill(item.xml(),(byte)0);
        assertArrayEquals(expected,item.hash());assertEquals(1,item.author()[0]);
        assertArrayEquals(xml("test",NOW+60000),item.xml());
    }
    @Test void futureAndStaleBoundariesAreInclusiveAndExpiryIsNot() {
        long future=NOW+300000,stale=NOW+30L*24*60*60*1000;
        CotRecord.record("test",future,id(1),stale,xml("test",stale),1).validateAt(NOW);
        assertThrows(IllegalArgumentException.class,()->record(future+1,1,1).validateAt(NOW));
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("test",NOW,id(1),stale+1,xml("test",stale+1),1).validateAt(NOW));
        assertThrows(IllegalArgumentException.class,()->record(NOW,1,1).validateAt(NOW+60000));
        CotRecord.tombstone("test",NOW,id(1),1).validateAt(NOW);
    }
    @Test void xmlMustMatchTheEnvelopeUidAndStale() {
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("other",NOW,id(1),NOW+60000,xml("test",NOW+60000),1));
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("test",NOW,id(1),NOW+60001,xml("test",NOW+60000),1));
    }
    @Test void rejectsDtdEntitiesMalformedUtf8AndExcessiveDepth() {
        String dtd="<!DOCTYPE event [<!ENTITY x SYSTEM 'file:///not-a-real-sync-fixture'>]>";
        byte[] bad=(dtd+new String(xml("test",NOW+60000),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("test",NOW,id(1),NOW+60000,bad,1));
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("test",NOW,id(1),NOW+60000,new byte[]{(byte)0xc0,(byte)0x80},1));
        String deep=new String(xml("test",NOW+60000),StandardCharsets.UTF_8).replace("<detail/>","<detail>"+"<a>".repeat(33)+"</a>".repeat(33)+"</detail>");
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("test",NOW,id(1),NOW+60000,deep.getBytes(StandardCharsets.UTF_8),1));
    }
    @Test void acceptsLargeXmlButRejectsBytesOverSixtyFourKiB() {
        String base=new String(xml("test",NOW+60000),StandardCharsets.UTF_8);
        byte[] large=base.replace("<detail/>","<detail><remarks>"+"x".repeat(60000)+"</remarks></detail>").getBytes(StandardCharsets.UTF_8);
        assertTrue(CotRecord.record("test",NOW,id(1),NOW+60000,large,1).xml().length>1176);
        assertThrows(IllegalArgumentException.class,()->CotRecord.record("test",NOW,id(1),NOW+60000,new byte[65537],1));
        assertThrows(IllegalArgumentException.class,()->CotRecord.tombstone("x".repeat(257),NOW,id(1),1));
    }
    @Test void staleShorteningChangesOnlyTheRootAttributeAndLeavesReceivedXmlUntouched() {
        long year=NOW+365L*24*60*60*1000;
        byte[] original=xml("test",year);
        byte[] shortened=CotXml.shortenStale(original,NOW);
        long capped=NOW+30L*24*60*60*1000-300000;
        assertArrayEquals(xml("test",capped),shortened);
        assertArrayEquals(xml("test",year),original);
        assertArrayEquals(xml("test",NOW+60000),CotXml.shortenStale(xml("test",NOW+60000),NOW));
    }
    @Test void diagnosticStringsNeverContainUidOrXml() {
        var item=record(NOW,1,1);
        assertFalse(item.toString().contains("test"));assertFalse(item.toString().contains("event"));
    }
}
