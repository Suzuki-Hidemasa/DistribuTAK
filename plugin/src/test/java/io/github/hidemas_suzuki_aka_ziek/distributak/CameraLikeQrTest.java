// SPDX-License-Identifier: GPL-3.0-only
package io.github.hidemas_suzuki_aka_ziek.distributak;
import java.util.*;
import com.google.zxing.qrcode.encoder.Encoder;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import io.github.hidemas_suzuki_aka_ziek.distributak.core.*;
import org.junit.Test;import static org.junit.Assert.*;
public class CameraLikeQrTest {
    @Test public void longestIpv4InvitationAtThreePixelsPerModuleSurvivesRotationAndBlur()throws Exception {camera(new byte[]{(byte)192,0,2,(byte)254},235);}
    @Test public void longestIpv6InvitationAtThreePixelsPerModuleSurvivesRotationAndBlur()throws Exception {camera(new byte[16],251);}
    private void camera(byte[] address,int characters)throws Exception {
        var random=new Random(163);byte[] x=new byte[32],a=new byte[32],t=new byte[32];random.nextBytes(x);random.nextBytes(a);random.nextBytes(t);
        try(var invitation=new Invitation(address,65535,Crypto.x25519Public(x),Crypto.ed25519Public(a),t, new byte[32])) {
            String expected=InvitationUrl.encode(invitation);assertEquals(characters,expected.length());var version=Encoder.encode(expected,ErrorCorrectionLevel.M).getVersion();
            int modules=version.getDimensionForVersion(),side=(modules+8)*3;long maximum=0;
            byte[] qr=InvitationQr.encode(invitation,side);
            try {
                assertEquals(side*side,qr.length);
                for(boolean rotated:new boolean[]{false,true})for(boolean blurred:new boolean[]{false,true}) {
                    byte[] frame=new byte[1280*720];Arrays.fill(frame,(byte)255);
                    for(int y=0;y<side;y++)for(int z=0;z<side;z++) {
                        int source=rotated?(side-1-z)*side+y:y*side+z;
                        frame[(190+y)*1280+170+z]=qr[source];
                    }
                    if(blurred){byte[] old=frame;frame=blur(old,1280,720);Crypto.wipe(old);}
                    long began=System.nanoTime();
                    try(var decoded=address.length==4?InvitationQr.decode(frame,1280,720):decodeWire(frame)) {
                        assertTrue("camera-like QR rotated="+rotated+" blurred="+blurred,expected.equals(InvitationUrl.encode(decoded)));
                    }finally{maximum=Math.max(maximum,System.nanoTime()-began);Crypto.wipe(frame);}
                }
                System.out.println("camera-like URL characters="+expected.length()+" QR version="+version.getVersionNumber()+" modules="+modules+" maximumDecodeMs="+(maximum/1_000_000.0));
            }finally{Crypto.wipe(qr);}
        }finally{Crypto.wipe(x);Crypto.wipe(a);Crypto.wipe(t);}
    }
    private static Invitation decodeWire(byte[] frame)throws Exception {
        // IPv6 は核の最大長の試料。画面の加入口は既存どおり IPv4 だけを受け付ける。
        byte[] view=frame;int width=1280,height=720;
        var reader=new com.google.zxing.qrcode.QRCodeReader();
        com.google.zxing.ReaderException last=com.google.zxing.NotFoundException.getNotFoundInstance();
        try {
            for(int turn=0;turn<4;turn++) {
                var source=new com.google.zxing.PlanarYUVLuminanceSource(view,width,height,0,0,width,height,false);
                try {
                    String text=reader.decode(new com.google.zxing.BinaryBitmap(new com.google.zxing.common.HybridBinarizer(source)),
                            java.util.Map.of(com.google.zxing.DecodeHintType.TRY_HARDER,Boolean.TRUE)).getText();
                    assertThrows(SecurityException.class,()->InvitationQr.parse(text));return InvitationUrl.decode(text);
                }catch(com.google.zxing.ReaderException failure){last=failure;}
                finally{reader.reset();}
                byte[] rotated=new byte[view.length];
                for(int y=0;y<height;y++)for(int x=0;x<width;x++)rotated[x*height+height-1-y]=view[y*width+x];
                if(view!=frame)Crypto.wipe(view);view=rotated;int previous=width;width=height;height=previous;
            }
            throw last;
        }finally{reader.reset();if(view!=frame)Crypto.wipe(view);}
    }
    private static byte[] blur(byte[] source,int width,int height){
        byte[] result=source.clone();int[] weights={1,2,1};
        for(int y=1;y<height-1;y++)for(int x=1;x<width-1;x++) {
            int sum=0;for(int dy=-1;dy<=1;dy++)for(int dx=-1;dx<=1;dx++)sum+=(source[(y+dy)*width+x+dx]&255)*weights[dy+1]*weights[dx+1];
            result[y*width+x]=(byte)((sum+8)/16);
        }return result;
    }
}
