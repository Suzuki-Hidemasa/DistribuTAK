// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import org.junit.Test;
import static org.junit.Assert.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.CotXml;

public class CotFixtureXmlTest {
    @Test public void deletionXmlEscapesTargetAndUsesDocumentedDeleteType() {
        byte[] xml=CotImportXml.deletion("target\"<&",10_000_000_000L);
        var fields=CotXml.inspect(xml);assertEquals("distributak-internal-deletion-v1",fields.uid());
        String text=new String(xml,java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(text.contains("type=\"t-x-d-d\""));assertTrue(text.contains("uid=\"target&quot;&lt;&amp;\""));assertTrue(text.contains("<__forcedelete/>"));
    }
    @Test public void fixtureIsFixedImaginaryPositionWithFiveMinuteLifetimeAndRealImportIsEnabled() {
        assertTrue(CotPort.REAL_IMPORT_ENABLED);long now=10_000_000_000L;
        byte[] xml=CotFixture.xml(now);var fields=CotXml.inspect(xml);
        assertEquals(CotPort.FIXTURE_UID,fields.uid());assertEquals(now+300000,fields.stale());
        String value=new String(xml,java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(value.contains("lat=\"0\" lon=\"0\""));assertTrue(value.contains("hae=\"9999999\""));assertTrue(value.contains("callsign=\"DistribuTAK Fence Test\""));
    }
}
