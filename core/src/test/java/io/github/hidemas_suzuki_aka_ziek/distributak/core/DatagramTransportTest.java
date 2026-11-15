// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DatagramTransportTest {
    final byte[] key=AdminRecordsTest.key(4), aad={1,2};
    NoiseTransport transport() { return new NoiseTransport(key,key,()->0L); }
    @Test void lossReorderingDuplicatesAndForgeryDoNotStopReception() {
        try(var send=transport();var receive=transport()) {
            byte[][] packets=new byte[4][];
            for(int n=0;n<4;n++) packets[n]=send.sendDatagram(new byte[]{(byte)n},aad);
            assertArrayEquals(new byte[]{2},receive.receiveDatagram(2,packets[2],aad));
            assertArrayEquals(new byte[]{0},receive.receiveDatagram(0,packets[0],aad));
            assertThrows(SecurityException.class,()->receive.receiveDatagram(2,packets[2],aad));
            assertThrows(SecurityException.class,()->receive.receiveDatagram(3,packets[3],new byte[]{9}));
            assertThrows(SecurityException.class,()->receive.receiveDatagram(999999,packets[3],aad));
            assertArrayEquals(new byte[]{3},receive.receiveDatagram(3,packets[3],aad));
            assertArrayEquals(new byte[]{1},receive.receiveDatagram(1,packets[1],aad));
        }
    }
    @Test void windowBoundaryAndUnsignedCounters() {
        try(var send=transport();var receive=transport()) {
            byte[] first=send.sendDatagram(new byte[]{0},aad), second=send.sendDatagram(new byte[]{1},aad);
            byte[] latest=null;
            for(int n=2;n<=ReplayWindow.SIZE;n++) latest=send.sendDatagram(new byte[]{2},aad);
            assertArrayEquals(new byte[]{2},receive.receiveDatagram(ReplayWindow.SIZE,latest,aad));
            assertThrows(SecurityException.class,()->receive.receiveDatagram(0,first,aad));
            assertArrayEquals(new byte[]{1},receive.receiveDatagram(1,second,aad));
        }
        try(var send=new NoiseTransport(key,key,()->0L,Long.MAX_VALUE,0);var receive=transport()) {
            byte[] a=send.sendDatagram(new byte[]{1},aad), b=send.sendDatagram(new byte[]{2},aad);
            assertArrayEquals(new byte[]{2},receive.receiveDatagram(Long.MIN_VALUE,b,aad));
            assertArrayEquals(new byte[]{1},receive.receiveDatagram(Long.MAX_VALUE,a,aad));
        }
    }
    @Test void invalidUpperNonceDoesNotCloseReceivingKey() {
        try(var send=new NoiseTransport(key,key,()->0L,NoiseTransport.REJECT_AFTER,0);var receive=transport()) {
            byte[] last=send.sendDatagram(new byte[]{1},aad);
            assertThrows(SecurityException.class,()->receive.receiveDatagram(NoiseTransport.REJECT_AFTER+1,last,aad));
            assertArrayEquals(new byte[]{1},receive.receiveDatagram(NoiseTransport.REJECT_AFTER,last,aad));
            assertThrows(SecurityException.class,()->send.sendDatagram(new byte[0],aad));
        }
    }
}
