// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;

import java.nio.ByteBuffer;
import java.util.*;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.Crypto;

/** 公開Camera2の座標とY平面を、AndroidのUIなしで計算する。背面カメラ専用。 */
final class CameraGeometry {
    private CameraGeometry(){}
    record Resolution(int width,int height){}
    static Resolution choose(Collection<Resolution> yuv,Collection<Resolution> textures){
        return yuv.stream().filter(textures::contains).filter(s->s.width()>0&&s.height()>0
                &&Math.max(s.width(),s.height())<=1920&&Math.min(s.width(),s.height())<=1080)
                .min(Comparator.comparingDouble(CameraGeometry::score).thenComparingInt(Resolution::width).thenComparingInt(Resolution::height))
                .orElseThrow(()->new IllegalStateException("共通の解析サイズがありません"));
    }
    private static double score(Resolution s){
        double aspect=(double)Math.max(s.width(),s.height())/Math.min(s.width(),s.height());
        return Math.abs(Math.log((double)s.width()*s.height()/(1280*720)))+2*Math.abs(Math.log(aspect/(16.0/9)));
    }
    static int mediaEdge(int width,int height,float density){
        if(width<=0||height<=0||!(density>0))throw new IllegalArgumentException("画面の大きさが違います");
        return Math.max(1,Math.round(Math.min(width/density,height/density)*.85f*density));
    }
    record Preview(int rotation,double scale,double cosine,double sine,int bufferWidth,int bufferHeight,int viewWidth,int viewHeight,float[] texture){
        double[] mapBuffer(double x,double y){
            double dx=x-bufferWidth/2.0,dy=y-bufferHeight/2.0;
            return new double[]{viewWidth/2.0+scale*(cosine*dx-sine*dy),viewHeight/2.0+scale*(sine*dx+cosine*dy)};
        }
    }
    private static int quarter(int degrees){if(degrees<0||degrees>=360||degrees%90!=0)throw new IllegalArgumentException("回転が違います");return degrees/90;}
    static Preview preview(int width,int height,int viewWidth,int viewHeight,int sensor,int display){
        if(width<=0||height<=0||viewWidth<=0||viewHeight<=0)throw new IllegalArgumentException("映像の大きさが違います");
        int sensorTurn=quarter(sensor),displayTurn=quarter(display),rotation=(sensor+display)%360;
        int[] cos={1,0,-1,0},sin={0,1,0,-1};int turn=rotation/90;
        double rw=turn%2==0?width:height,rh=turn%2==0?height:width;
        double scale=Math.max(viewWidth/rw,viewHeight/rh),cx=viewWidth/2.0,cy=viewHeight/2.0;
        // TextureViewのセンサー回転と非一様の拡大を取り消し、所要のcenter cropへ写す。
        double baseW=sensorTurn%2==0?width:height,baseH=sensorTurn%2==0?height:width;
        double a=scale*cos[displayTurn]*baseW/viewWidth,b=-scale*sin[displayTurn]*baseH/viewHeight;
        double c=scale*sin[displayTurn]*baseW/viewWidth,d=scale*cos[displayTurn]*baseH/viewHeight;
        float[] texture={(float)a,(float)b,(float)(cx-a*cx-b*cy),(float)c,(float)d,(float)(cy-c*cx-d*cy),0,0,1};
        return new Preview(rotation,scale,cos[turn],sin[turn],width,height,viewWidth,viewHeight,texture);
    }
    static byte[] luminance(ByteBuffer source,int width,int height,int rowStride,int pixelStride){
        if(width<=0||height<=0||(long)width*height>1920L*1080||rowStride<=0||pixelStride<=0
                ||(long)(width-1)*pixelStride+1>rowStride)throw new IllegalArgumentException("Y平面の形が違います");
        int origin=source.position();long last=(long)origin+(long)(height-1)*rowStride+(long)(width-1)*pixelStride;
        if(last>=source.limit())throw new IllegalArgumentException("Y平面の長さが違います");
        byte[] image=new byte[width*height];var copy=source.duplicate();
        try{
            for(int y=0;y<height;y++) {
                if(pixelStride==1){copy.position(origin+y*rowStride);copy.get(image,y*width,width);}
                else for(int x=0;x<width;x++)image[y*width+x]=copy.get(origin+y*rowStride+x*pixelStride);
            }return image;
        }catch(RuntimeException e){Crypto.wipe(image);throw e;}
    }
}
