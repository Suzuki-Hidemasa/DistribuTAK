// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.util.*;import java.nio.*;
import org.junit.Test;import static org.junit.Assert.*;
public class CameraGeometryTest {
    @Test public void eightBackCameraOrientationsRemainUniformAndCentered(){
        int[][] expected={{90,180,270,0},{270,0,90,180}};
        for(int s=0;s<2;s++)for(int d=0;d<4;d++) {
            int sensor=s==0?90:270;var t=CameraGeometry.preview(1280,720,540,720,sensor,d*90);
            assertEquals(expected[s][d],t.rotation());
            double[] center=t.mapBuffer(640,360);assertEquals(270,center[0],1e-6);assertEquals(360,center[1],1e-6);
            double[] x=t.mapBuffer(641,360),y=t.mapBuffer(640,361);
            double ax=x[0]-center[0],ay=x[1]-center[1],bx=y[0]-center[0],by=y[1]-center[1];
            assertEquals(Math.hypot(ax,ay),Math.hypot(bx,by),1e-6);assertEquals(0,ax*bx+ay*by,1e-6);
            double[][] directions={{1,0},{0,1},{-1,0},{0,-1}};var direction=directions[expected[s][d]/90];
            double coverageW=Math.abs(ax)*1280+Math.abs(bx)*720,coverageH=Math.abs(ay)*1280+Math.abs(by)*720;
            assertTrue(coverageW>=540-1e-6&&coverageH>=720-1e-6);assertTrue(Math.abs(coverageW-540)<1e-6||Math.abs(coverageH-720)<1e-6);
            double length=Math.hypot(ax,ay);assertEquals(direction[0],ax/length,1e-6);assertEquals(direction[1],ay/length,1e-6);
            // TextureViewが行うセンサーの回転と引き伸ばしを補正する行列も、同じ最終位置を作る。
            double sw=720,sh=1280;
            // 下の点はrawの中心から右へ1画素。
            double sx=0,sy=sensor==90?1:-1;
            double vx=270+sx*540/sw,vy=360+sy*720/sh;
            var values=t.texture();
            assertEquals(x[0],values[0]*vx+values[1]*vy+values[2],1e-4);
            assertEquals(x[1],values[3]*vx+values[4]*vy+values[5],1e-4);
        }
    }
    @Test public void common720pIsPreferredAnd1080pIsMaximum(){
        var p720=new CameraGeometry.Resolution(1280,720);var p1080=new CameraGeometry.Resolution(1920,1080);
        var huge=new CameraGeometry.Resolution(3840,2160);var small=new CameraGeometry.Resolution(640,480);
        assertEquals(p720,CameraGeometry.choose(List.of(small,huge,p1080,p720),List.of(p720,p1080,small,huge)));
        assertEquals(p1080,CameraGeometry.choose(List.of(p1080,huge),List.of(p1080,huge)));
        assertEquals(small,CameraGeometry.choose(List.of(p720,small),List.of(small)));
        assertThrows(Exception.class,()->CameraGeometry.choose(List.of(huge),List.of(huge)));
    }
    @Test public void paddedAndInterleavedYPlanesCopyOnlyVisiblePixelsAndPreservePosition(){
        var source=ByteBuffer.wrap(new byte[]{99,1,2,3,88,4,5,6,88});source.position(1);
        assertArrayEquals(new byte[]{1,2,3,4,5,6},CameraGeometry.luminance(source,3,2,4,1));assertEquals(1,source.position());
        var sparse=ByteBuffer.wrap(new byte[]{1,9,2,9,3,9,4,9});
        assertArrayEquals(new byte[]{1,2,3,4},CameraGeometry.luminance(sparse,2,2,4,2));
        assertThrows(Exception.class,()->CameraGeometry.luminance(ByteBuffer.allocate(2),3,2,4,1));
    }
    @Test public void mediaUsesEightyFivePercentOfShortSideInDp(){
        assertEquals(918,CameraGeometry.mediaEdge(1080,2400,3));assertEquals(918,CameraGeometry.mediaEdge(2400,1080,3));
        assertEquals(1836,CameraGeometry.mediaEdge(2160,3840,6));
    }
}
